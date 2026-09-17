//! Core engine of the replay projector.
//!
//! Stage 1 is deliberately deterministic: it observes a real emulated run,
//! records every change as an immutable event, and can rebuild any frame from
//! snapshots plus the event stream. There is no UI and no model in this layer.
//!
//! Module map:
//!
//! - [`event`] — the event model and its binary encoding.
//! - [`state`] — what an event does when applied (the single source of truth).
//! - [`snapshot`] — recovery anchors and the adaptive capture policy.
//! - [`replay`] — arbitrary-frame seek and reverse stepping.
//! - [`session`] — the Unicorn-backed capture loop.
//! - [`trace`] — the self-contained `.ctrace` container.
//!
//! [`python`] (feature `python`) exposes the engine to Python via PyO3.

pub mod event;
pub mod replay;
pub mod session;
pub mod snapshot;
pub mod state;
pub mod trace;

#[cfg(feature = "python")]
pub mod python;

/// The projector's version, mirroring the Python package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
