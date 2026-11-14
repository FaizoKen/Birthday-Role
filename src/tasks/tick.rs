//! The clock worker.
//!
//! Unlike a typical plugin there is no external API to poll — the only data
//! is the member's saved birthday, which doesn't change on its own. What DOES
//! change is *time*: "birthday today", "within 7 days", "this month",
//! "current age" all flip as the calendar advances, and they flip at a
//! different wall-clock instant for every timezone.
//!
//! So every `TICK_MINUTES` this worker fans a (de-duplicated) `config_sync`
//! out to every role link. `sync_for_role_link` recomputes the qualifying
//! set with the `bday_*` SQL functions evaluated against each member's local
//! "today", and — crucially — skips the RoleLogic PUT entirely when the set
//! is unchanged (the `current == qualifying` guard). On a quiet day this is
//! a handful of cheap SELECTs; the day a birthday rolls over in some
//! timezone, that role's set changes and gets pushed within one tick.
//!
//! It also GCs old terminal `jobs` rows so the table stays small.

use std::sync::Arc;
use std::time::Duration;

use crate::services::{jobs, sync};
use crate::tasks::shutdown::ShutdownGuard;
use crate::AppState;

/// Run a first pass shortly after boot (catch up on anything that flipped
/// while we were down), then every TICK.
const INITIAL_DELAY: Duration = Duration::from_secs(45);

pub async fn run(state: Arc<AppState>, mut shutdown: ShutdownGuard) {
    let tick = Duration::from_secs(state.config.tick_minutes * 60);
    tracing::info!(
        tick_minutes = state.config.tick_minutes,
        "Tick worker started"
    );

    tokio::select! {
        _ = tokio::time::sleep(INITIAL_DELAY) => {}
        _ = shutdown.wait() => return,
    }

    let mut interval = schedule(tick);
    loop {
        match jobs::gc_old(&state.pool).await {
            Ok(n) if n > 0 => tracing::info!(deleted = n, "GC'd old job rows"),
            Ok(_) => {}
            Err(e) => tracing::warn!("jobs GC failed: {e}"),
        }

        match sync::enqueue_resync_all_role_links(&state).await {
            Ok(n) => tracing::info!(role_links = n, "Tick: enqueued resync for all role links"),
            Err(e) => tracing::warn!("Tick resync enqueue failed: {e}"),
        }

        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.wait() => break,
        }
    }

    tracing::info!("Tick worker stopped");
}

/// The timer between passes: its first tick is one `tick` away. A plain
/// `tokio::time::interval` completes its first tick at once, which made the
/// loop run a second full pass (job GC and a resync queued for every role
/// link, again) straight after the first one at boot. A pass that overruns
/// the tick delays the next one instead of firing a catch-up burst.
fn schedule(tick: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + tick, tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pass that runs after INITIAL_DELAY is the only one at boot: the
    /// next waits a full tick.
    #[tokio::test(start_paused = true)]
    async fn next_pass_waits_a_full_tick() {
        let tick = Duration::from_secs(30 * 60);
        let mut interval = schedule(tick);
        let early = tokio::time::timeout(tick - Duration::from_secs(1), interval.tick()).await;
        assert!(
            early.is_err(),
            "the first tick must not complete before the tick"
        );
        let on_time = tokio::time::timeout(Duration::from_secs(2), interval.tick()).await;
        assert!(on_time.is_ok(), "the first tick completes at the tick");
    }
}
