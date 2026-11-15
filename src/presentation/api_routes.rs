//! Authenticated Axum REST API endpoints, security middleware, and domain error mapping.

use std::fmt;
use std::sync::Arc;

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::application::update_config::{UpdateConfigRequest, UpdateConfigUseCase};
use crate::domain::entities::{InspectionReport, NetworkAlert, RuntimeConfig};
use crate::domain::errors::DomainError;
use crate::domain::ports::{ConfigStore, QuarantineRepo};
use crate::infrastructure::suricata_tail::SuricataCorrelator;
use crate::presentation::sse_broadcaster::{SseBroadcaster, SseEvent};

/// Maximum accepted JSON request payload size (64 KB).
pub const MAX_API_BODY_BYTES: usize = 64 * 1024;

/// Default number of recent inspection reports returned by `GET /api/v1/reports`.
pub const DEFAULT_REPORTS_LIMIT: u32 = 50;

/// Minimum clamped `limit` for `GET /api/v1/reports`.
pub const MIN_REPORTS_LIMIT: u32 = 1;

/// Maximum clamped `limit` for `GET /api/v1/reports`.
pub const MAX_REPORTS_LIMIT: u32 = 500;

const CONTENT_SECURITY_POLICY_VALUE: &str = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";

/// Shared application state injected into Axum REST and SSE handlers.
#[derive(Clone)]
pub struct ApiState {
    /// Persistent configuration store port.
    pub config_store: Arc<dyn ConfigStore>,
    /// Persistent quarantine inspection repository port.
    pub quarantine_repo: Arc<dyn QuarantineRepo>,
    /// Shared in-memory runtime configuration synchronized across components.
    pub runtime_config: Arc<RwLock<RuntimeConfig>>,
    /// Use case validating, persisting, and reloading runtime configuration.
    pub update_config_use_case: Arc<UpdateConfigUseCase>,
    /// Suricata `eve.json` streaming tailer and network alert correlator.
    pub suricata_correlator: Arc<SuricataCorrelator>,
    /// Broadcast hub for real-time SSE notifications.
    pub sse_broadcaster: Arc<SseBroadcaster>,
    /// Administrative bearer token protecting `/api/` endpoints (redacted in `Debug`).
    pub admin_api_token: SecretString,
}

impl fmt::Debug for ApiState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiState")
            .field("sse_subscribers", &self.sse_broadcaster.subscriber_count())
            .field("admin_api_token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Standard JSON error body returned across API error responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Machine-readable error category code.
    pub error: String,
    /// Human-readable diagnostic message (sanitized for 500 errors).
    pub message: String,
}

/// Response payload for `GET /api/v1/health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Health indicator (`"ok"`).
    pub status: String,
    /// Active runtime configuration snapshot.
    pub config: RuntimeConfig,
    /// Count of currently connected SSE subscribers.
    pub sse_subscribers: usize,
}

/// Query parameters for `GET /api/v1/reports`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReportsQuery {
    /// Optional maximum number of reports to return (clamped to `1..=500`, default `50`).
    pub limit: Option<u32>,
}

/// Response payload for `GET /api/v1/reports`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportsResponse {
    /// Recent inspection reports ordered newest-first.
    pub reports: Vec<InspectionReport>,
    /// Number of reports included in `reports`.
    pub count: usize,
}

/// Response payload for `GET /api/v1/alerts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertsResponse {
    /// Active non-expired Suricata alerts matching policy.
    pub alerts: Vec<NetworkAlert>,
    /// Number of alerts included in `alerts`.
    pub count: usize,
}

/// Builds the authenticated Axum router for all `/api/v1` REST and SSE endpoints.
pub fn build_api_router(state: Arc<ApiState>) -> Router {
    let auth_layer = middleware::from_fn_with_state(state.clone(), bearer_auth_middleware);

    let v1_router = Router::new()
        .route("/health", get(health_handler))
        .route("/reports", get(reports_handler))
        .route("/alerts", get(alerts_handler))
        .route(
            "/config",
            get(get_config_handler).patch(patch_config_handler),
        )
        .route("/events/stream", get(events_stream_handler));

    let api_router = Router::new()
        .nest("/v1", v1_router)
        .method_not_allowed_fallback(api_method_not_allowed_handler)
        .fallback(api_not_found_handler)
        .layer(auth_layer.clone());

    Router::new()
        .nest("/api", api_router)
        .route("/api/", any(api_not_found_handler).layer(auth_layer))
        .layer(DefaultBodyLimit::max(MAX_API_BODY_BYTES))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

async fn bearer_auth_middleware(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let expected_token = state.admin_api_token.expose_secret();
    if expected_token.trim().is_empty() {
        tracing::error!("ADMIN_API_TOKEN is empty; rejecting API request fail-closed");
        return unauthorized_response();
    }

    let Some(provided_token) = extract_bearer_token(request.headers()) else {
        tracing::warn!(
            method = %request.method(),
            path = %request.uri().path(),
            "Rejected API request with missing or malformed Bearer token"
        );
        return unauthorized_response();
    };

    if !tokens_match_constant_time(provided_token, expected_token) {
        tracing::warn!(
            method = %request.method(),
            path = %request.uri().path(),
            "Rejected API request with invalid Bearer token"
        );
        return unauthorized_response();
    }

    next.run(request).await
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }

    let raw = first.to_str().ok()?.trim();
    let (scheme, credentials) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let token = credentials.trim();
    if token.is_empty() {
        return None;
    }

    Some(token)
}

fn tokens_match_constant_time(provided: &str, expected: &str) -> bool {
    let provided_digest = Sha256::digest(provided.as_bytes());
    let expected_digest = Sha256::digest(expected.as_bytes());
    bool::from(provided_digest.ct_eq(&expected_digest))
}

async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let is_api_path = path == "/api" || path.starts_with("/api/");

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY_VALUE),
    );
    if is_api_path {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }

    response
}

async fn health_handler(State(state): State<Arc<ApiState>>) -> Json<HealthResponse> {
    let config = state.runtime_config.read().await.clone();
    let sse_subscribers = state.sse_broadcaster.subscriber_count();

    Json(HealthResponse {
        status: "ok".to_string(),
        config,
        sse_subscribers,
    })
}

async fn reports_handler(
    State(state): State<Arc<ApiState>>,
    query: Result<Query<ReportsQuery>, QueryRejection>,
) -> Result<Json<ReportsResponse>, ApiError> {
    let Query(params) = query.map_err(ApiError::from_query_rejection)?;
    let clamped_limit = params
        .limit
        .unwrap_or(DEFAULT_REPORTS_LIMIT)
        .clamp(MIN_REPORTS_LIMIT, MAX_REPORTS_LIMIT);

    let reports = state
        .quarantine_repo
        .list_recent_reports(clamped_limit)
        .await?;
    let count = reports.len();

    Ok(Json(ReportsResponse { reports, count }))
}

async fn alerts_handler(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<AlertsResponse>, ApiError> {
    let alerts = state.suricata_correlator.active_alerts().await?;
    let count = alerts.len();

    Ok(Json(AlertsResponse { alerts, count }))
}

async fn get_config_handler(State(state): State<Arc<ApiState>>) -> Json<RuntimeConfig> {
    let config = state.runtime_config.read().await.clone();
    Json(config)
}

async fn patch_config_handler(
    State(state): State<Arc<ApiState>>,
    payload: Result<Json<UpdateConfigRequest>, JsonRejection>,
) -> Result<Json<RuntimeConfig>, ApiError> {
    let Json(req) = payload.map_err(ApiError::from_json_rejection)?;
    let updated = state.update_config_use_case.execute(req).await?;
    let _ = state.sse_broadcaster.publish(SseEvent::ConfigUpdated {
        config: updated.clone(),
    });

    Ok(Json(updated))
}

async fn events_stream_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    state.sse_broadcaster.into_sse_response()
}

async fn api_not_found_handler() -> Response {
    api_error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Endpoint not found".to_string(),
    )
}

async fn api_method_not_allowed_handler() -> Response {
    api_error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "HTTP method not allowed".to_string(),
    )
}

fn unauthorized_response() -> Response {
    let mut response = api_error_response(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "Missing or invalid bearer token".to_string(),
    );
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn api_error_response(status: StatusCode, error: &str, message: String) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
            message,
        }),
    )
        .into_response()
}

enum ApiError {
    Domain(DomainError),
    Http {
        status: StatusCode,
        error: &'static str,
        message: String,
    },
}

impl ApiError {
    fn from_query_rejection(rejection: QueryRejection) -> Self {
        Self::Http {
            status: rejection.status(),
            error: "bad_request",
            message: rejection.body_text(),
        }
    }

    fn from_json_rejection(rejection: JsonRejection) -> Self {
        let status = rejection.status();
        let error = match status {
            StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
            StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
            StatusCode::UNPROCESSABLE_ENTITY => "unprocessable_entity",
            _ => "bad_request",
        };
        Self::Http {
            status,
            error,
            message: rejection.body_text(),
        }
    }
}

impl From<DomainError> for ApiError {
    fn from(err: DomainError) -> Self {
        Self::Domain(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Http {
                status,
                error,
                message,
            } => api_error_response(status, error, message),
            Self::Domain(err) => match err {
                DomainError::PathTraversalAttempt(_) | DomainError::ForbiddenSystemDirectory(_) => {
                    api_error_response(StatusCode::FORBIDDEN, "forbidden", err.to_string())
                }
                DomainError::InvalidPath(_) | DomainError::ConfigError(_) => {
                    api_error_response(StatusCode::BAD_REQUEST, "bad_request", err.to_string())
                }
                DomainError::StorageError(_)
                | DomainError::IoError(_)
                | DomainError::InspectionError(_)
                | DomainError::QuarantineError(_) => {
                    tracing::error!(error = %err, "Internal domain error while handling API request");
                    api_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "Internal security service error".to_string(),
                    )
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request as HttpRequest};
    use chrono::Utc;
    use serde_json::Value;
    use tempfile::{TempDir, tempdir};
    use tokio::sync::watch;
    use tower::ServiceExt;

    use crate::domain::entities::{FileArtifact, SecurityVerdict};

    use super::*;

    const TEST_TOKEN: &str = "sentinel_guard_test_token_64chars_0123456789abcdef0123456789";

    struct MockConfigStore {
        fail_save: Mutex<bool>,
        saved: Mutex<Option<RuntimeConfig>>,
    }

    impl MockConfigStore {
        fn new() -> Self {
            Self {
                fail_save: Mutex::new(false),
                saved: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl ConfigStore for MockConfigStore {
        async fn load_or_seed(
            &self,
            defaults: &RuntimeConfig,
        ) -> Result<RuntimeConfig, DomainError> {
            let guard = self.saved.lock().expect("mock lock");
            Ok(guard.clone().unwrap_or_else(|| defaults.clone()))
        }

        async fn save_config(&self, config: &RuntimeConfig) -> Result<(), DomainError> {
            if *self.fail_save.lock().expect("mock lock") {
                return Err(DomainError::StorageError(
                    "sensitive sqlite disk path /var/lib/secret.db failure".to_string(),
                ));
            }
            let mut guard = self.saved.lock().expect("mock lock");
            *guard = Some(config.clone());
            Ok(())
        }
    }

    struct MockQuarantineRepo {
        reports: Mutex<Vec<InspectionReport>>,
        fail_list: Mutex<bool>,
        last_limit: Mutex<Option<u32>>,
    }

    impl MockQuarantineRepo {
        fn new(reports: Vec<InspectionReport>) -> Self {
            Self {
                reports: Mutex::new(reports),
                fail_list: Mutex::new(false),
                last_limit: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl QuarantineRepo for MockQuarantineRepo {
        async fn save_report(&self, report: &InspectionReport) -> Result<i64, DomainError> {
            let mut guard = self.reports.lock().expect("mock lock");
            let next_id = (guard.len() + 1) as i64;
            let mut saved = report.clone();
            saved.id = Some(next_id);
            guard.push(saved);
            Ok(next_id)
        }

        async fn list_recent_reports(
            &self,
            limit: u32,
        ) -> Result<Vec<InspectionReport>, DomainError> {
            *self.last_limit.lock().expect("mock lock") = Some(limit);
            if *self.fail_list.lock().expect("mock lock") {
                return Err(DomainError::StorageError(
                    "sqlite internal table leak".to_string(),
                ));
            }
            let guard = self.reports.lock().expect("mock lock");
            Ok(guard.iter().take(limit as usize).cloned().collect())
        }
    }

    struct TestHarness {
        _temp_dir: TempDir,
        quarantine_dir: PathBuf,
        approved_dir: PathBuf,
        eve_path: PathBuf,
        config_store: Arc<MockConfigStore>,
        quarantine_repo: Arc<MockQuarantineRepo>,
        state: Arc<ApiState>,
        watcher_rx: watch::Receiver<PathBuf>,
    }

    fn sample_report(id: i64, name: &str) -> InspectionReport {
        InspectionReport {
            id: Some(id),
            artifact: FileArtifact {
                path: PathBuf::from(format!("/var/sentinel/quarantine/{name}")),
                sanitized_name: name.to_string(),
                extension: Some("pdf".to_string()),
                size_bytes: 512,
                sha256_hash: "b".repeat(64),
                detected_mime: Some("application/pdf".to_string()),
            },
            verdict: SecurityVerdict::Clean,
            destination_path: Some(PathBuf::from(format!("/var/sentinel/approved/{name}"))),
            inspected_at: Utc::now(),
        }
    }

    fn build_harness(token: &str, reports: Vec<InspectionReport>) -> TestHarness {
        let dir = tempdir().expect("tempdir");
        let quarantine_dir = std::fs::canonicalize(dir.path())
            .expect("canonical tempdir")
            .join("quarantine");
        let approved_dir = std::fs::canonicalize(dir.path())
            .expect("canonical tempdir")
            .join("approved");
        std::fs::create_dir_all(&quarantine_dir).expect("create quarantine");
        std::fs::create_dir_all(&approved_dir).expect("create approved");

        let eve_path = std::fs::canonicalize(dir.path())
            .expect("canonical tempdir")
            .join("eve.json");
        let clamd_socket_path = std::fs::canonicalize(dir.path())
            .expect("canonical tempdir")
            .join("clamd.ctl");

        let initial_config = RuntimeConfig {
            quarantine_dir: quarantine_dir.clone(),
            approved_dir: approved_dir.clone(),
            clamd_socket_path,
            suricata_eve_path: eve_path.clone(),
            updated_at: Utc::now(),
        };

        let config_store = Arc::new(MockConfigStore::new());
        let quarantine_repo = Arc::new(MockQuarantineRepo::new(reports));
        let runtime_config = Arc::new(RwLock::new(initial_config));
        let (watcher_tx, watcher_rx) = watch::channel(quarantine_dir.clone());
        let update_config_use_case = Arc::new(UpdateConfigUseCase::new(
            config_store.clone(),
            runtime_config.clone(),
            watcher_tx,
        ));
        let suricata_correlator = Arc::new(SuricataCorrelator::new(runtime_config.clone()));
        let sse_broadcaster = Arc::new(SseBroadcaster::new());

        let state = Arc::new(ApiState {
            config_store: config_store.clone(),
            quarantine_repo: quarantine_repo.clone(),
            runtime_config,
            update_config_use_case,
            suricata_correlator,
            sse_broadcaster,
            admin_api_token: SecretString::from(token.to_string()),
        });

        TestHarness {
            _temp_dir: dir,
            quarantine_dir,
            approved_dir,
            eve_path,
            config_store,
            quarantine_repo,
            state,
            watcher_rx,
        }
    }

    async fn json_body(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read body bytes");
        serde_json::from_slice(&bytes).expect("parse response JSON")
    }

    fn assert_security_headers(headers: &HeaderMap, expect_no_store: bool) {
        assert_eq!(
            headers
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers
                .get(header::X_FRAME_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            headers
                .get(header::REFERRER_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some("no-referrer")
        );
        assert_eq!(
            headers
                .get(header::CONTENT_SECURITY_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some(CONTENT_SECURITY_POLICY_VALUE)
        );
        if expect_no_store {
            assert_eq!(
                headers
                    .get(header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-store")
            );
        }
    }

    #[test]
    fn api_state_debug_redacts_admin_api_token() {
        let harness = build_harness(TEST_TOKEN, Vec::new());
        let debug_str = format!("{:?}", harness.state);
        assert!(
            !debug_str.contains(TEST_TOKEN),
            "ApiState Debug must never expose admin_api_token: {debug_str}"
        );
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn bearer_auth_rejects_missing_malformed_query_and_invalid_tokens() {
        let harness = build_harness(TEST_TOKEN, Vec::new());
        let app = build_api_router(harness.state.clone());

        // Missing header
        let res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            res.headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer")
        );
        assert_security_headers(res.headers(), true);
        let body = json_body(res).await;
        assert_eq!(body["error"], "unauthorized");

        // Token in query string must NEVER be accepted
        let query_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/api/v1/health?token={TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(query_res.status(), StatusCode::UNAUTHORIZED);

        // Unknown API route must return 401 when unauthenticated
        let unauth_unknown = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/nonexistent")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauth_unknown.status(), StatusCode::UNAUTHORIZED);

        // Trailing-slash /api/ must also return 401 when unauthenticated
        let unauth_api_slash = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauth_api_slash.status(), StatusCode::UNAUTHORIZED);

        // Malformed / wrong Authorization headers
        let wrong_same_len = format!("Bearer {}x", &TEST_TOKEN[..TEST_TOKEN.len() - 1]);
        for bad_header in [
            "Basic dXNlcjpwYXNz",
            "Bearer",
            "Bearer ",
            "Bearer    ",
            "Bearer wrong",
            wrong_same_len.as_str(),
        ] {
            let res = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri("/api/v1/config")
                        .header(header::AUTHORIZATION, bad_header)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "expected 401 for Authorization header {bad_header:?}"
            );
        }

        // Duplicate Authorization headers must be rejected
        let dup_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/health")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .header(header::AUTHORIZATION, "Bearer other")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(dup_res.status(), StatusCode::UNAUTHORIZED);

        // Case-insensitive "bearer" scheme succeeds
        let bearer_lower = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/health")
                    .header(header::AUTHORIZATION, format!("bearer {TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(bearer_lower.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn empty_configured_admin_api_token_fails_closed() {
        let harness = build_harness("   ", Vec::new());
        let app = build_api_router(harness.state.clone());

        for auth in ["Bearer ", "Bearer anything"] {
            let res = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri("/api/v1/health")
                        .header(header::AUTHORIZATION, auth)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn authenticated_unknown_api_route_returns_json_404_with_security_headers() {
        let harness = build_harness(TEST_TOKEN, Vec::new());
        let app = build_api_router(harness.state.clone());

        for uri in ["/api/v1/nonexistent", "/api/v2/health", "/api/", "/api"] {
            let res = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri(uri)
                        .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                res.status(),
                StatusCode::NOT_FOUND,
                "expected 404 for {uri}"
            );
            assert_security_headers(res.headers(), true);
            let body = json_body(res).await;
            assert_eq!(body["error"], "not_found");
            assert_eq!(body["message"], "Endpoint not found");
        }
    }

    #[tokio::test]
    async fn health_and_get_config_return_snapshot_and_sse_subscriber_count() {
        let harness = build_harness(TEST_TOKEN, Vec::new());
        let _rx = harness.state.sse_broadcaster.subscribe();
        let app = build_api_router(harness.state.clone());

        let health_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/health")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(health_res.status(), StatusCode::OK);
        assert_security_headers(health_res.headers(), true);
        let health_json = json_body(health_res).await;
        assert_eq!(health_json["status"], "ok");
        assert_eq!(health_json["sse_subscribers"], 1);
        assert_eq!(
            health_json["config"]["quarantine_dir"],
            harness.quarantine_dir.to_string_lossy().as_ref()
        );

        let config_res = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/config")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(config_res.status(), StatusCode::OK);
        assert_security_headers(config_res.headers(), true);
        let config_json = json_body(config_res).await;
        assert_eq!(
            config_json["approved_dir"],
            harness.approved_dir.to_string_lossy().as_ref()
        );
    }

    #[tokio::test]
    async fn reports_endpoint_clamps_limit_rejects_invalid_query_and_sanitizes_internal_errors() {
        let reports = vec![sample_report(1, "a.pdf"), sample_report(2, "b.pdf")];
        let harness = build_harness(TEST_TOKEN, reports);
        let app = build_api_router(harness.state.clone());

        // Default limit = 50
        let default_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/reports")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(default_res.status(), StatusCode::OK);
        assert_eq!(
            *harness.quarantine_repo.last_limit.lock().expect("lock"),
            Some(50)
        );
        let default_json = json_body(default_res).await;
        assert_eq!(default_json["count"], 2);

        // Clamp 0 -> 1
        let min_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/reports?limit=0")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(min_res.status(), StatusCode::OK);
        assert_eq!(
            *harness.quarantine_repo.last_limit.lock().expect("lock"),
            Some(1)
        );
        let min_json = json_body(min_res).await;
        assert_eq!(min_json["count"], 1);

        // Clamp 9999 -> 500
        let max_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/reports?limit=9999")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(max_res.status(), StatusCode::OK);
        assert_eq!(
            *harness.quarantine_repo.last_limit.lock().expect("lock"),
            Some(500)
        );

        // Reject invalid non-numeric limit with 400 Bad Request JSON
        for bad_uri in ["/api/v1/reports?limit=abc", "/api/v1/reports?limit=-5"] {
            let bad_res = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri(bad_uri)
                        .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(bad_res.status(), StatusCode::BAD_REQUEST);
            let bad_json = json_body(bad_res).await;
            assert_eq!(bad_json["error"], "bad_request");
        }

        // StorageError returns sanitized 500 Internal Server Error
        *harness.quarantine_repo.fail_list.lock().expect("lock") = true;
        let err_res = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/reports")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(err_res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let err_json = json_body(err_res).await;
        assert_eq!(err_json["error"], "internal_error");
        assert_eq!(err_json["message"], "Internal security service error");
        assert!(!err_json.to_string().contains("sqlite"));
    }

    #[tokio::test]
    async fn alerts_endpoint_returns_active_suricata_alerts() {
        let harness = build_harness(TEST_TOKEN, Vec::new());
        let ts = Utc::now().to_rfc3339();
        let line = format!(
            "{{\"timestamp\":\"{ts}\",\"event_type\":\"alert\",\"src_ip\":\"198.51.100.20\",\"dest_ip\":\"10.0.0.5\",\"alert\":{{\"signature\":\"ET EXPLOIT Test\",\"severity\":1}}}}\n"
        );
        std::fs::write(&harness.eve_path, line).expect("write eve.json");

        let app = build_api_router(harness.state.clone());
        let res = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/alerts")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(res.status(), StatusCode::OK);
        assert_security_headers(res.headers(), true);
        let json = json_body(res).await;
        assert_eq!(json["count"], 1);
        assert_eq!(json["alerts"][0]["src_ip"], "198.51.100.20");
        assert_eq!(json["alerts"][0]["signature"], "ET EXPLOIT Test");
    }

    #[tokio::test]
    async fn patch_config_updates_persists_broadcasts_and_maps_domain_errors() {
        let mut harness = build_harness(TEST_TOKEN, Vec::new());
        let mut sse_rx = harness.state.sse_broadcaster.subscribe();
        let new_q = std::fs::canonicalize(harness._temp_dir.path())
            .expect("canonical")
            .join("new_q");
        let new_a = std::fs::canonicalize(harness._temp_dir.path())
            .expect("canonical")
            .join("new_a");
        std::fs::create_dir_all(&new_q).expect("create new_q");
        std::fs::create_dir_all(&new_a).expect("create new_a");

        let app = build_api_router(harness.state.clone());

        // 1. Valid PATCH updates config and broadcasts ConfigUpdated SSE event
        let valid_payload = serde_json::json!({
            "quarantine_dir": new_q,
            "approved_dir": new_a,
            "clamd_socket_path": null,
            "suricata_eve_path": null
        });
        let ok_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method(Method::PATCH)
                    .uri("/api/v1/config")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(valid_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(ok_res.status(), StatusCode::OK);
        assert_security_headers(ok_res.headers(), true);
        let ok_json = json_body(ok_res).await;
        assert_eq!(ok_json["quarantine_dir"], new_q.to_string_lossy().as_ref());
        assert!(harness.watcher_rx.has_changed().expect("watch open"));
        assert_eq!(*harness.watcher_rx.borrow_and_update(), new_q);

        let sse_event = sse_rx.recv().await.expect("receive ConfigUpdated SSE");
        assert!(matches!(
            sse_event,
            SseEvent::ConfigUpdated { config } if config.quarantine_dir == new_q && config.approved_dir == new_a
        ));

        // 2. Path traversal and forbidden system directory map to 403 Forbidden
        for bad_q in ["/tmp/../etc", "/etc"] {
            let forbidden_payload = serde_json::json!({
                "quarantine_dir": bad_q,
                "approved_dir": new_a,
                "clamd_socket_path": null,
                "suricata_eve_path": null
            });
            let forbidden_res = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .method(Method::PATCH)
                        .uri("/api/v1/config")
                        .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(forbidden_payload.to_string()))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                forbidden_res.status(),
                StatusCode::FORBIDDEN,
                "expected 403 for {bad_q}"
            );
            let forbidden_json = json_body(forbidden_res).await;
            assert_eq!(forbidden_json["error"], "forbidden");
        }

        // 3. InvalidPath (non-existent / equal dirs) maps to 400 Bad Request
        let invalid_payload = serde_json::json!({
            "quarantine_dir": new_q,
            "approved_dir": new_q,
            "clamd_socket_path": null,
            "suricata_eve_path": null
        });
        let invalid_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method(Method::PATCH)
                    .uri("/api/v1/config")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(invalid_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(invalid_res.status(), StatusCode::BAD_REQUEST);
        let invalid_json = json_body(invalid_res).await;
        assert_eq!(invalid_json["error"], "bad_request");

        // 4. Storage failure maps to sanitized 500 Internal Server Error
        *harness.config_store.fail_save.lock().expect("lock") = true;
        let storage_err_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method(Method::PATCH)
                    .uri("/api/v1/config")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(valid_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(storage_err_res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let storage_err_json = json_body(storage_err_res).await;
        assert_eq!(storage_err_json["error"], "internal_error");
        assert_eq!(
            storage_err_json["message"],
            "Internal security service error"
        );
        assert!(!storage_err_json.to_string().contains("/var/lib/secret.db"));

        // 5. Request body > 64 KB is rejected with 413 Payload Too Large
        let oversized = "x".repeat(MAX_API_BODY_BYTES + 1024);
        let oversized_payload = serde_json::json!({
            "quarantine_dir": oversized,
            "approved_dir": new_a,
            "clamd_socket_path": null,
            "suricata_eve_path": null
        });
        let limit_res = app
            .oneshot(
                HttpRequest::builder()
                    .method(Method::PATCH)
                    .uri("/api/v1/config")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(oversized_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(limit_res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let limit_json = json_body(limit_res).await;
        assert_eq!(limit_json["error"], "payload_too_large");
    }

    #[tokio::test]
    async fn sse_stream_endpoint_requires_auth_and_streams_events_with_security_headers() {
        let harness = build_harness(TEST_TOKEN, Vec::new());
        let app = build_api_router(harness.state.clone());

        let unauth_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/events/stream")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);

        let sse_res = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/events/stream")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(sse_res.status(), StatusCode::OK);
        assert_security_headers(sse_res.headers(), true);
        assert_eq!(
            sse_res
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );

        let mut stream = sse_res.into_body().into_data_stream();
        harness
            .state
            .sse_broadcaster
            .publish(SseEvent::InspectionCompleted {
                report: sample_report(10, "report.pdf"),
            });

        use tokio_stream::StreamExt;
        let frame = stream
            .next()
            .await
            .expect("SSE frame present")
            .expect("valid SSE bytes");
        let text = std::str::from_utf8(&frame).expect("utf-8");
        assert!(text.contains("event: inspection_completed"));
        assert!(text.contains("report.pdf"));

        harness.state.sse_broadcaster.shutdown();
        while let Some(next_chunk) = stream.next().await {
            let _ = next_chunk.expect("clean stream end");
        }
    }
}
