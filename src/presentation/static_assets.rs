//! Embedded Vue 3 SPA asset server and traversal-hardened fallback handler.

use axum::Json;
use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

use crate::presentation::api_routes::ErrorResponse;

/// Compiled production frontend assets embedded directly into the Sentinel Guard binary.
#[derive(RustEmbed)]
#[folder = "../vue_sentinel_guard/dist"]
pub struct EmbeddedFrontendAssets;

/// Serves embedded SPA static assets with strict path-traversal rejection and history fallback.
pub async fn serve_embedded_asset(uri: Uri) -> Response {
    let raw_path = uri.path();
    let Ok(normalized) = validate_and_normalize_asset_path(raw_path) else {
        return invalid_asset_path_response();
    };

    // Defense-in-depth: never serve index.html or assets for API namespaces.
    if normalized == "api" || normalized.starts_with("api/") {
        return asset_not_found_response();
    }

    let asset_path = if normalized.is_empty() {
        "index.html"
    } else {
        normalized
    };

    if let Some(file) = EmbeddedFrontendAssets::get(asset_path) {
        return build_asset_response(asset_path, file.data);
    }

    let last_segment = asset_path.rsplit('/').next().unwrap_or("");
    if asset_path.starts_with("assets/") || last_segment.contains('.') {
        return asset_not_found_response();
    }

    let Some(index_file) = EmbeddedFrontendAssets::get("index.html") else {
        return asset_not_found_response();
    };

    build_asset_response("index.html", index_file.data)
}

fn validate_and_normalize_asset_path(raw_path: &str) -> Result<&str, &'static str> {
    let lower = raw_path.to_ascii_lowercase();

    if raw_path.contains('\0') || lower.contains("%00") {
        return Err("Null byte in asset path");
    }

    if raw_path.contains('\\') || lower.contains("%5c") {
        return Err("Backslash in asset path");
    }

    let slash_normalized = lower.replace("%2f", "/");
    for segment in slash_normalized.split('/') {
        let dot_decoded = segment.replace("%2e", ".");
        if dot_decoded == ".." {
            return Err("Parent traversal segment in asset path");
        }
    }

    Ok(raw_path.trim_start_matches('/'))
}

fn build_asset_response(asset_path: &str, data: std::borrow::Cow<'static, [u8]>) -> Response {
    let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
    let content_type = if asset_path == "index.html"
        || (mime.type_() == mime_guess::mime::TEXT && mime.subtype() == mime_guess::mime::HTML)
    {
        HeaderValue::from_static("text/html; charset=utf-8")
    } else {
        HeaderValue::from_str(mime.as_ref())
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
    };

    let cache_control = if asset_path == "index.html" {
        HeaderValue::from_static("no-cache")
    } else if asset_path.starts_with("assets/") {
        HeaderValue::from_static("public, max-age=31536000, immutable")
    } else {
        HeaderValue::from_static("public, max-age=3600")
    };

    let mut response = Response::new(Body::from(data));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, cache_control);
    response
}

fn invalid_asset_path_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: "bad_request".to_string(),
            message: "Invalid asset path".to_string(),
        }),
    )
        .into_response()
}

fn asset_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "not_found".to_string(),
            message: "Asset not found".to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .expect("read body bytes");
        String::from_utf8(bytes.to_vec()).expect("valid utf-8 body")
    }

    #[tokio::test]
    async fn root_and_spa_routes_serve_index_html_with_no_cache() {
        for route in ["/", "/dashboard", "/quarantine", "/config", "/quarantine/"] {
            let uri: Uri = route.parse().expect("valid test uri");
            let res = serve_embedded_asset(uri).await;

            assert_eq!(res.status(), StatusCode::OK, "expected 200 for {route}");
            assert_eq!(
                res.headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some("text/html; charset=utf-8")
            );
            assert_eq!(
                res.headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-cache")
            );

            let html = body_text(res).await;
            assert!(
                html.contains("Sentinel Guard"),
                "expected Sentinel Guard title in HTML for {route}"
            );
            assert!(html.contains("<div id=\"app\"></div>"));
        }
    }

    #[tokio::test]
    async fn embedded_hashed_js_and_css_assets_are_served_with_immutable_cache() {
        let asset_paths: Vec<String> = EmbeddedFrontendAssets::iter()
            .map(|p| p.into_owned())
            .filter(|p| p.starts_with("assets/") && (p.ends_with(".js") || p.ends_with(".css")))
            .collect();

        assert!(
            asset_paths.iter().any(|p| p.ends_with(".js")),
            "expected at least one embedded JS bundle in assets/"
        );
        assert!(
            asset_paths.iter().any(|p| p.ends_with(".css")),
            "expected at least one embedded CSS bundle in assets/"
        );

        for asset_path in asset_paths {
            let uri: Uri = format!("/{asset_path}").parse().expect("valid asset uri");
            let res = serve_embedded_asset(uri).await;

            assert_eq!(
                res.status(),
                StatusCode::OK,
                "expected 200 for /{asset_path}"
            );
            assert_eq!(
                res.headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("public, max-age=31536000, immutable")
            );

            let content_type = res
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if asset_path.ends_with(".js") {
                assert!(
                    content_type.contains("javascript"),
                    "expected JS content-type for {asset_path}, got {content_type}"
                );
            } else if asset_path.ends_with(".css") {
                assert!(
                    content_type.contains("css"),
                    "expected CSS content-type for {asset_path}, got {content_type}"
                );
            }
        }
    }

    #[tokio::test]
    async fn missing_assets_and_api_paths_return_404_without_spa_fallback() {
        for missing in [
            "/assets/nonexistent.js",
            "/assets/missing.css",
            "/assets/no-extension",
            "/unknown-file.txt",
            "/api",
            "/api/",
            "/api/v1/health",
            "//api/v1/secret",
        ] {
            let uri: Uri = missing.parse().expect("valid uri");
            let res = serve_embedded_asset(uri).await;
            assert_eq!(
                res.status(),
                StatusCode::NOT_FOUND,
                "expected 404 Not Found for {missing}"
            );
            let text = body_text(res).await;
            assert!(
                text.contains("Asset not found"),
                "expected 'Asset not found' body for {missing}, got {text}"
            );
        }
    }

    #[tokio::test]
    async fn traversal_null_bytes_and_backslashes_are_rejected_with_400() {
        for bad_uri in [
            "/%2e%2e/etc/passwd",
            "/%2E%2E/etc/passwd",
            "/assets/../index.html",
            "/assets/%2e%2e/index.html",
            "/assets/.%2e/index.html",
            "/assets/%2e%2e%2findex.html",
            "/%00",
            "/assets/app%00.js",
            "/%5c",
            "/assets%5Cindex.html",
        ] {
            let uri: Uri = bad_uri.parse().expect("valid test uri");
            let res = serve_embedded_asset(uri).await;
            assert_eq!(
                res.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 Bad Request for {bad_uri}"
            );
            let body = body_text(res).await;
            assert!(body.contains("Invalid asset path"));
        }

        // Literal backslash and NUL bytes cannot appear inside a parsed http::Uri,
        // so verify the underlying validator rejects them directly as well.
        assert!(validate_and_normalize_asset_path("/assets\\index.html").is_err());
        assert!(validate_and_normalize_asset_path("/index\0.html").is_err());
    }
}
