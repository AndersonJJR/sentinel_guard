//! Server-Sent Events (SSE) broadcaster for real-time inspection, alert, and config updates.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::{BroadcastStream, WatchStream};

use crate::domain::entities::{InspectionReport, NetworkAlert, RuntimeConfig};

/// Default broadcast ring-buffer capacity for live SSE subscribers.
pub const DEFAULT_SSE_CHANNEL_CAPACITY: usize = 256;

/// Upper bound on SSE broadcast channel capacity to prevent excessive pre-allocation.
pub const MAX_SSE_CHANNEL_CAPACITY: usize = 65_536;

/// Interval between SSE keep-alive comment frames sent to idle subscribers.
pub const DEFAULT_SSE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Real-time domain events streamed to authenticated dashboard subscribers via SSE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum SseEvent {
    /// Emitted when a quarantined file finishes the inspection pipeline.
    InspectionCompleted {
        /// Completed inspection report including verdict and disposition.
        report: InspectionReport,
    },
    /// Emitted when a suspicious Suricata network alert is detected.
    NetworkAlertDetected {
        /// Parsed network intrusion alert.
        alert: NetworkAlert,
    },
    /// Emitted when runtime operational paths are updated dynamically.
    ConfigUpdated {
        /// Newly persisted runtime configuration.
        config: RuntimeConfig,
    },
}

impl SseEvent {
    /// Returns the SSE `event:` field name associated with this variant.
    pub const fn event_name(&self) -> &'static str {
        match self {
            Self::InspectionCompleted { .. } => "inspection_completed",
            Self::NetworkAlertDetected { .. } => "network_alert_detected",
            Self::ConfigUpdated { .. } => "config_updated",
        }
    }
}

/// Multi-subscriber broadcast hub backing the `/api/v1/events/stream` SSE endpoint.
#[derive(Debug, Clone)]
pub struct SseBroadcaster {
    sender: broadcast::Sender<SseEvent>,
    shutdown_tx: watch::Sender<bool>,
}

impl Default for SseBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl SseBroadcaster {
    /// Creates a new [`SseBroadcaster`] with [`DEFAULT_SSE_CHANNEL_CAPACITY`].
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_SSE_CHANNEL_CAPACITY)
    }

    /// Creates a new [`SseBroadcaster`] clamping `capacity` into `1..=MAX_SSE_CHANNEL_CAPACITY`.
    pub fn with_capacity(capacity: usize) -> Self {
        let bounded_capacity = capacity.clamp(1, MAX_SSE_CHANNEL_CAPACITY);
        let (sender, _) = broadcast::channel(bounded_capacity);
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            sender,
            shutdown_tx,
        }
    }

    /// Broadcasts `event` to all active subscribers and returns the recipient count (`0` if none).
    pub fn publish(&self, event: SseEvent) -> usize {
        self.sender.send(event).unwrap_or_default()
    }

    /// Subscribes a new broadcast receiver for live [`SseEvent`] notifications.
    pub fn subscribe(&self) -> broadcast::Receiver<SseEvent> {
        self.sender.subscribe()
    }

    /// Returns the number of currently active broadcast subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Signals all active SSE response streams to close cleanly during daemon shutdown.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Converts a new subscription into an Axum [`Sse`] streaming response with 15-second keep-alive.
    pub fn into_sse_response(
        &self,
    ) -> Sse<impl Stream<Item = Result<Event, Infallible>> + Send + 'static + use<>> {
        let stream = ShutdownAwareSseStream {
            events: BroadcastStream::new(self.subscribe()),
            shutdown: WatchStream::new(self.shutdown_tx.subscribe()),
        };

        Sse::new(stream).keep_alive(
            KeepAlive::new()
                .interval(DEFAULT_SSE_KEEPALIVE_INTERVAL)
                .text("keep-alive"),
        )
    }
}

struct ShutdownAwareSseStream {
    events: BroadcastStream<SseEvent>,
    shutdown: WatchStream<bool>,
}

impl Stream for ShutdownAwareSseStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match Pin::new(&mut self.shutdown).poll_next(cx) {
                Poll::Ready(Some(true)) => return Poll::Ready(None),
                Poll::Ready(Some(false)) => continue,
                Poll::Ready(None) | Poll::Pending => break,
            }
        }

        loop {
            match Pin::new(&mut self.events).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if let Some(sse_event) = map_broadcast_item(item) {
                        return Poll::Ready(Some(Ok(sse_event)));
                    }
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn map_broadcast_item(item: Result<SseEvent, BroadcastStreamRecvError>) -> Option<Event> {
    match item {
        Ok(event) => {
            let event_name = event.event_name();
            match Event::default().event(event_name).json_data(&event) {
                Ok(sse_event) => Some(sse_event),
                Err(err) => {
                    tracing::error!(
                        event_name,
                        error = %err,
                        "Failed to serialize SSE event payload as JSON"
                    );
                    None
                }
            }
        }
        Err(BroadcastStreamRecvError::Lagged(skipped)) => {
            tracing::warn!(
                skipped,
                "SSE subscriber lagged behind broadcast channel; emitting lag notification"
            );
            Some(
                Event::default()
                    .event("lagged")
                    .data(format!("{{\"skipped\":{skipped}}}")),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axum::response::IntoResponse;
    use chrono::Utc;
    use tokio::sync::broadcast::error::RecvError;
    use tokio_stream::StreamExt;

    use crate::domain::entities::{FileArtifact, SecurityVerdict};

    use super::*;

    fn sample_report(id: i64, name: &str) -> InspectionReport {
        InspectionReport {
            id: Some(id),
            artifact: FileArtifact {
                path: PathBuf::from(format!("/var/sentinel/quarantine/{name}")),
                sanitized_name: name.to_string(),
                extension: Some("pdf".to_string()),
                size_bytes: 2_048,
                sha256_hash: "a".repeat(64),
                detected_mime: Some("application/pdf".to_string()),
            },
            verdict: SecurityVerdict::Clean,
            destination_path: Some(PathBuf::from(format!("/var/sentinel/approved/{name}"))),
            inspected_at: Utc::now(),
        }
    }

    fn sample_alert() -> NetworkAlert {
        NetworkAlert {
            timestamp: Utc::now(),
            src_ip: "198.51.100.42".to_string(),
            dest_ip: "10.0.0.10".to_string(),
            signature: "ET MALWARE Payload Download".to_string(),
            severity: 1,
        }
    }

    fn sample_config() -> RuntimeConfig {
        RuntimeConfig {
            quarantine_dir: PathBuf::from("/var/sentinel/quarantine"),
            approved_dir: PathBuf::from("/var/sentinel/approved"),
            clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
            suricata_eve_path: PathBuf::from("/var/log/suricata/eve.json"),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn publish_without_subscribers_returns_zero_and_capacity_zero_is_safe() {
        let broadcaster = SseBroadcaster::with_capacity(0);
        assert_eq!(broadcaster.subscriber_count(), 0);

        let delivered = broadcaster.publish(SseEvent::ConfigUpdated {
            config: sample_config(),
        });
        assert_eq!(delivered, 0);

        let default_broadcaster = SseBroadcaster::default();
        assert_eq!(default_broadcaster.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn fan_out_delivers_events_to_multiple_subscribers() {
        let broadcaster = SseBroadcaster::new();
        let mut rx1 = broadcaster.subscribe();
        let mut rx2 = broadcaster.subscribe();
        assert_eq!(broadcaster.subscriber_count(), 2);

        let event = SseEvent::InspectionCompleted {
            report: sample_report(1, "invoice.pdf"),
        };
        let delivered = broadcaster.publish(event.clone());
        assert_eq!(delivered, 2);

        assert_eq!(rx1.recv().await.expect("rx1 receive"), event);
        assert_eq!(rx2.recv().await.expect("rx2 receive"), event);

        drop(rx2);
        assert_eq!(broadcaster.subscriber_count(), 1);
    }

    #[tokio::test]
    async fn lagged_subscriber_recovers_and_sse_stream_emits_lagged_event() {
        let broadcaster = SseBroadcaster::with_capacity(2);
        let mut raw_rx = broadcaster.subscribe();

        let first = SseEvent::ConfigUpdated {
            config: sample_config(),
        };
        let second = SseEvent::NetworkAlertDetected {
            alert: sample_alert(),
        };
        let third = SseEvent::InspectionCompleted {
            report: sample_report(3, "archive.pdf"),
        };

        broadcaster.publish(first);
        broadcaster.publish(second.clone());
        broadcaster.publish(third.clone());

        assert!(matches!(raw_rx.recv().await, Err(RecvError::Lagged(1))));
        assert_eq!(raw_rx.recv().await.expect("second"), second);
        assert_eq!(raw_rx.recv().await.expect("third"), third);

        // Verify full SSE response stream emits `event: lagged` cleanly without panicking.
        let sse_broadcaster = SseBroadcaster::with_capacity(2);
        let response = sse_broadcaster.into_sse_response().into_response();
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );

        let mut data_stream = response.into_body().into_data_stream();

        sse_broadcaster.publish(SseEvent::ConfigUpdated {
            config: sample_config(),
        });
        sse_broadcaster.publish(SseEvent::NetworkAlertDetected {
            alert: sample_alert(),
        });
        sse_broadcaster.publish(SseEvent::InspectionCompleted {
            report: sample_report(4, "latest.pdf"),
        });

        let first_chunk = data_stream
            .next()
            .await
            .expect("lagged chunk present")
            .expect("valid bytes");
        let first_text = std::str::from_utf8(&first_chunk).expect("utf-8");
        assert!(
            first_text.contains("event: lagged") && first_text.contains("data: {\"skipped\":1}"),
            "expected lagged SSE frame, got: {first_text:?}"
        );

        let second_chunk = data_stream
            .next()
            .await
            .expect("alert chunk present")
            .expect("valid bytes");
        let second_text = std::str::from_utf8(&second_chunk).expect("utf-8");
        assert!(
            second_text.contains("event: network_alert_detected")
                && second_text.contains("\"event_type\":\"network_alert_detected\""),
            "expected network_alert_detected SSE frame, got: {second_text:?}"
        );

        sse_broadcaster.shutdown();
        while let Some(chunk) = data_stream.next().await {
            let _ = chunk.expect("remaining buffered frame valid");
        }
    }

    #[test]
    fn sse_event_variants_serialize_with_snake_case_event_type_tag() {
        let inspection = SseEvent::InspectionCompleted {
            report: sample_report(7, "doc.pdf"),
        };
        let inspection_json: serde_json::Value =
            serde_json::to_value(&inspection).expect("serialize inspection");
        assert_eq!(inspection.event_name(), "inspection_completed");
        assert_eq!(inspection_json["event_type"], "inspection_completed");
        assert_eq!(inspection_json["report"]["id"], 7);
        assert_eq!(
            serde_json::from_value::<SseEvent>(inspection_json).expect("round-trip"),
            inspection
        );

        let alert = SseEvent::NetworkAlertDetected {
            alert: sample_alert(),
        };
        let alert_json: serde_json::Value = serde_json::to_value(&alert).expect("serialize alert");
        assert_eq!(alert.event_name(), "network_alert_detected");
        assert_eq!(alert_json["event_type"], "network_alert_detected");
        assert_eq!(alert_json["alert"]["src_ip"], "198.51.100.42");
        assert_eq!(
            serde_json::from_value::<SseEvent>(alert_json).expect("round-trip"),
            alert
        );

        let config = SseEvent::ConfigUpdated {
            config: sample_config(),
        };
        let config_json: serde_json::Value =
            serde_json::to_value(&config).expect("serialize config");
        assert_eq!(config.event_name(), "config_updated");
        assert_eq!(config_json["event_type"], "config_updated");
        assert_eq!(
            config_json["config"]["quarantine_dir"],
            "/var/sentinel/quarantine"
        );
        assert_eq!(
            serde_json::from_value::<SseEvent>(config_json).expect("round-trip"),
            config
        );
    }
}
