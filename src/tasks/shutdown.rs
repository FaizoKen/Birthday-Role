//! Shutdown plumbing shared by the HTTP server and background workers.
//!
//! Owning a single `Shutdown` lets every component subscribe to the same
//! cancellation signal. On SIGTERM/SIGINT the listener fires
//! `broadcast::send`, which wakes the axum server (stop accepting, drain),
//! every job worker, the tick worker, and the rate-limiter GC.
//!
//! After `wait()` resolves, callers must NOT start new work but MUST finish
//! what's already in flight; `main.rs` joins all handles before exiting so
//! no in-flight job is silently dropped.

use tokio::sync::broadcast;

#[derive(Clone)]
pub struct Shutdown {
    tx: broadcast::Sender<()>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel::<()>(1);
        Self { tx }
    }

    pub fn subscribe(&self) -> ShutdownGuard {
        ShutdownGuard {
            rx: self.tx.subscribe(),
        }
    }

    /// Fire the shutdown signal. Idempotent.
    pub fn trigger(&self) {
        let _ = self.tx.send(());
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ShutdownGuard {
    rx: broadcast::Receiver<()>,
}

impl ShutdownGuard {
    /// Resolves when shutdown is triggered. Cancellation-safe under `select!`.
    pub async fn wait(&mut self) {
        let _ = self.rx.recv().await;
    }

    pub fn is_triggered(&mut self) -> bool {
        matches!(
            self.rx.try_recv(),
            Ok(()) | Err(broadcast::error::TryRecvError::Closed)
        )
    }
}

/// Block until the OS sends SIGTERM (orchestrator stop) or SIGINT (Ctrl-C).
/// On Windows only Ctrl-C is supported by tokio.
pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
            _ = sigint.recv() => tracing::info!("Received SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Received Ctrl-C");
    }
}
