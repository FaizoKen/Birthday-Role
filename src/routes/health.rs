use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::AppState;

pub async fn favicon() -> impl IntoResponse {
    // 30-day immutable cache. Bytes are baked into the binary via
    // `include_bytes!`, so they only change on a redeploy.
    (
        [
            (header::CONTENT_TYPE, "image/x-icon"),
            (header::CACHE_CONTROL, "public, max-age=2592000, immutable"),
        ],
        include_bytes!("../../favicon.ico").as_slice(),
    )
}

/// Liveness — the process is up. Returns 503 if the DB is unreachable so an
/// orchestrator restarts a stuck pod instead of letting it serve failing
/// requests. This plugin has no external API to probe (the only data source
/// is the member's own input), so health is purely DB-bound.
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let start = std::time::Instant::now();
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();
    let db_latency = start.elapsed().as_millis() as u64;

    let http_status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = Json(json!({
        "status": if db_ok { "healthy" } else { "unhealthy" },
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {
            "database": {
                "status": if db_ok { "up" } else { "down" },
                "latency_ms": db_latency
            }
        }
    }));
    (http_status, body)
}

/// Readiness — should this replica receive traffic right now? Flips to 503
/// the moment shutdown begins so a load balancer can drain us before the
/// HTTP server actually stops accepting connections.
pub async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.draining.load(Ordering::SeqCst) {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "draining" })),
        )
    } else {
        (StatusCode::OK, Json(json!({ "status": "ready" })))
    }
}
