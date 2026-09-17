//! Snapshots: the anchors that make arbitrary-frame seek affordable.
//!
//! Replaying from frame 0 costs O(N). Snapshots bound that cost by keeping a
//! recoverable state every so often. Only pages touched before the snapshot
//! are stored, so a compute-only program carries almost no snapshot weight.

use std::collections::HashMap;
use std::sync::Arc;

use crate::event::Frame;
use crate::state::{MachineState, Memory, Page, RegFile};

/// A recoverable state at a specific frame.
///
/// `frame` counts events already applied: restoring this snapshot yields the
/// state after `frame` events, and replay continues from `frame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub frame: Frame,
    pub regs: RegFile,
    /// The complete captured output up to `frame`.
    pub output: Vec<u8>,
    /// Pages modified relative to the base image, sorted by address.
    pub dirty_pages: Vec<(u64, Page)>,
}

impl Snapshot {
    /// Capture the current state as a snapshot at `frame`.
    pub fn capture(frame: Frame, state: &MachineState) -> Snapshot {
        Snapshot {
            frame,
            regs: state.regs.clone(),
            output: state.output.clone(),
            dirty_pages: state.mem.dirty_pages(),
        }
    }

    /// Rebuild a machine state from this snapshot and a base image.
    ///
    /// The base image is shared, not copied; only the snapshot's dirty pages
    /// are materialized.
    pub fn restore(&self, base: Arc<HashMap<u64, Page>>) -> MachineState {
        MachineState {
            regs: self.regs.clone(),
            mem: Memory::restore(Arc::clone(&base), self.dirty_pages.clone()),
            output: self.output.clone(),
        }
    }
}

/// Decides when to capture a snapshot during a recording.
///
/// The interval grows geometrically once the trace gets long, which keeps the
/// snapshot count logarithmic in the number of events while bounding the
/// worst-case replay distance.
#[derive(Debug, Clone)]
pub struct SnapshotPolicy {
    interval: u64,
    next_at: u64,
}

/// First snapshot interval: every 1024 events.
pub const DEFAULT_INTERVAL: u64 = 1024;
/// Interval doubles once the trace length reaches `interval * GROWTH`.
pub const GROWTH: u64 = 64;
/// Upper bound on the interval.
pub const MAX_INTERVAL: u64 = 1 << 20;

impl SnapshotPolicy {
    /// A policy with the default interval.
    pub fn new() -> Self {
        Self::with_interval(DEFAULT_INTERVAL)
    }

    /// A policy with an explicit fixed starting interval (used by tests).
    pub fn with_interval(interval: u64) -> Self {
        let interval = interval.max(1);
        SnapshotPolicy {
            interval,
            next_at: interval,
        }
    }

    /// The current interval.
    pub fn interval(&self) -> u64 {
        self.interval
    }

    /// Record that `applied` events have been folded in.
    ///
    /// Returns true when a snapshot should be taken now.
    pub fn observe(&mut self, applied: u64) -> bool {
        if applied < self.next_at {
            return false;
        }
        if applied >= self.interval.saturating_mul(GROWTH) && self.interval < MAX_INTERVAL {
            self.interval = self.interval.saturating_mul(2).min(MAX_INTERVAL);
        }
        self.next_at = applied + self.interval;
        true
    }
}

impl Default for SnapshotPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, RegId};

    fn state_with(rip: u64) -> MachineState {
        let mut state = MachineState::new(Arc::new(HashMap::new()));
        state.regs.set(RegId::Rip, rip);
        state
    }

    #[test]
    fn capture_and_inspect() {
        let mut state = state_with(0x401000);
        state.apply(&Event::MemWrite {
            addr: 0x1000,
            data: b"abc".to_vec(),
        });
        let snap = Snapshot::capture(Frame(42), &state);
        assert_eq!(snap.frame, Frame(42));
        assert_eq!(snap.regs.ip(), 0x401000);
        assert_eq!(snap.dirty_pages.len(), 1);
        assert!(snap.output.is_empty());
    }

    #[test]
    fn capture_records_output() {
        let mut state = state_with(0x401000);
        state.apply(&Event::Output {
            data: b"hello".to_vec(),
        });
        let snap = Snapshot::capture(Frame(1), &state);
        assert_eq!(snap.output, b"hello");
    }

    #[test]
    fn restore_reproduces_state_without_copying_base() {
        let mut base_map = HashMap::new();
        base_map.insert(0x400000u64, Page::from_bytes(b"ELF!"));
        let base = Arc::new(base_map);

        let mut state = MachineState::new(Arc::clone(&base));
        state.regs.set(RegId::Rip, 0x401000);
        state.apply(&Event::MemWrite {
            addr: 0x1000,
            data: b"zz".to_vec(),
        });
        state.apply(&Event::Output {
            data: b"out".to_vec(),
        });

        let restored = Snapshot::capture(Frame(2), &state).restore(Arc::clone(&base));
        assert_eq!(restored.regs.ip(), 0x401000);
        assert_eq!(restored.mem.read(0x400000, 4), b"ELF!");
        assert_eq!(restored.mem.read(0x1000, 2), b"zz");
        assert_eq!(restored.output, b"out");
    }

    #[test]
    fn policy_defaults_to_first_interval() {
        let mut policy = SnapshotPolicy::new();
        assert!(!policy.observe(1023));
        assert!(policy.observe(1024));
    }

    #[test]
    fn policy_grows_interval_geometrically() {
        let mut policy = SnapshotPolicy::with_interval(4);
        let horizon = 1_000_000u64;
        let mut captured = 0u64;
        for applied in 1..=horizon {
            if policy.observe(applied) {
                captured += 1;
            }
        }
        // Intervals double as the trace grows, so the snapshot count stays
        // logarithmic instead of one per interval for the whole recording.
        assert!(captured < horizon / 1000, "captured={captured}");
        assert!(policy.interval() > 4);
    }

    #[test]
    fn policy_never_fires_below_next_at() {
        let mut policy = SnapshotPolicy::with_interval(100);
        for applied in 0..100 {
            assert!(!policy.observe(applied));
        }
        assert!(policy.observe(100));
    }

    #[test]
    fn zero_interval_is_clamped_to_one() {
        let mut policy = SnapshotPolicy::with_interval(0);
        assert_eq!(policy.interval(), 1);
        assert!(policy.observe(1));
    }
}
