//! Default-deny security headers applied to every response.
//!
//! The middleware uses `entry().or_insert()` so per-route handlers can
//! override individual headers (e.g. the admin page that must be iframed by
//! the RoleLogic dashboard sets its own `Content-Security-Policy` *before*
//! this layer runs — that value is preserved).

use axum::extract::Request;
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// CSP for HTML that must never be embedded in a frame (member-facing verify
/// page, public birthdays list, error pages).
pub const PUBLIC_PAGE_CSP: &str = "frame-ancestors 'none'";

/// Build the `Content-Security-Policy` value for the admin page embedded
/// inside the RoleLogic dashboard iframe. Falls back to `*` only when the
/// operator hasn't configured `RL_DASHBOARD_ORIGIN` (dev / self-hosted).
pub fn admin_iframe_csp(dashboard_origin: Option<&str>) -> String {
    let ancestor = dashboard_origin.unwrap_or("*");
    format!("frame-ancestors {ancestor}")
}

/// Middleware: applies a baseline of security headers to every response.
/// Per-route handlers may set any of these explicitly before reaching this
/// layer; their values win.
pub async fn baseline(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();

    h.entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(PUBLIC_PAGE_CSP));
    h.entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    h.entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("strict-origin-when-cross-origin"));
    h.entry(header::STRICT_TRANSPORT_SECURITY)
        .or_insert(HeaderValue::from_static(
            "max-age=31536000; includeSubDomains",
        ));

    resp
}
