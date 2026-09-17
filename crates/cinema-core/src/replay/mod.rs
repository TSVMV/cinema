//! Replay: rebuild any frame of a recording without re-executing anything.
//!
//! `state_at(target)` finds the nearest snapshot at or before `target` and
//! folds events forward from there. `step_back` is just `state_at(target - 1)`,
//! which is what makes reverse stepping cheap: it costs one bounded replay
//! segment, not a full restart.

use std::collections::HashMap;
use std::sync::Arc;

use crate::event::{Event, Frame};
use crate::snapshot::Snapshot;
use crate::state::{MachineState, Page};
use crate::trace::Trace;

/// A replay handle over a trace.
pub struct Replay<'a> {
    trace: &'a Trace,
    base: Arc<HashMap<u64, Page>>,
}

impl<'a> Replay<'a> {
    /// Build a replay over `trace`.
    pub fn new(trace: &'a Trace) -> Self {
        let base = trace.base_map();
        Replay { trace, base }
    }

    /// Build a replay reusing an already materialized base image.
    pub fn with_base(trace: &'a Trace, base: Arc<HashMap<u64, Page>>) -> Self {
        Replay { trace, base }
    }

    /// The final frame (total number of events).
    pub fn frame_count(&self) -> Frame {
        self.trace.last_frame()
    }

    /// The snapshot that anchors `target`: the newest one at or before it.
    pub fn anchor(&self, target: Frame) -> Option<&Snapshot> {
        self.trace
            .snapshots
            .iter()
            .filter(|snap| snap.frame <= target)
            .max_by_key(|snap| snap.frame.as_u64())
    }

    /// Rebuild the full machine state at `target`.
    ///
    /// `target` is clamped to `[0, frame_count]`, so callers can pass any value
    /// without bounds checks of their own.
    pub fn state_at(&self, target: Frame) -> MachineState {
        let target_n = target.as_u64().min(self.trace.len() as u64);
        let anchor = self.anchor(Frame(target_n));

        let (mut state, start) = match anchor {
            Some(snap) => (snap.restore(Arc::clone(&self.base)), snap.frame.as_u64()),
            None => {
                let mut state = MachineState::new(Arc::clone(&self.base));
                state.regs = self.trace.initial_regs.clone();
                (state, 0)
            }
        };

        for i in start..target_n {
            state.apply(&self.trace.events[i as usize]);
        }
        state
    }

    /// The state one frame earlier, if `frame` is not already frame 0.
    pub fn step_back(&self, frame: Frame) -> Option<MachineState> {
        frame.prev().map(|prev| self.state_at(prev))
    }

    /// The events in the half-open range `[from, to)`.
    pub fn events_between(&self, from: Frame, to: Frame) -> &[Event] {
        let len = self.trace.len();
        let a = (from.as_u64() as usize).min(len);
        let b = (to.as_u64() as usize).min(len).max(a);
        &self.trace.events[a..b]
    }

    /// The event at `frame - 1`, i.e. the event that produced the state at
    /// `frame`. Frame 0 has no producing event.
    pub fn event_at(&self, frame: Frame) -> Option<&Event> {
        frame
            .prev()
            .map(|prev| &self.trace.events[prev.as_u64() as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, ExitKind, RegId};
    use crate::session::{record_elf, RecordOptions};
    use crate::snapshot::Snapshot;
    use crate::state::MachineState;

    fn hello() -> Vec<u8> {
        include_bytes!("../../tests/fixtures/hello_static").to_vec()
    }

    fn recorded() -> Trace {
        record_elf(&hello(), &RecordOptions::default()).expect("record hello")
    }

    #[test]
    fn final_frame_matches_recorded_output() {
        let trace = recorded();
        let replay = Replay::new(&trace);
        let state = replay.state_at(trace.last_frame());
        assert_eq!(state.output, b"hello, winVpwn\n");
        assert!(state.regs.ip() > 0);
    }

    #[test]
    fn state_at_matches_straight_line_application() {
        let trace = recorded();
        let replay = Replay::new(&trace);

        // Reference: apply every event from the start.
        let mut reference = MachineState::new(trace.base_map());
        reference.regs = trace.initial_regs.clone();
        reference.apply_all(&trace.events);

        let last = replay.state_at(trace.last_frame());
        assert_eq!(last.regs, reference.regs);
        assert_eq!(last.output, reference.output);
    }

    #[test]
    fn intermediate_frames_are_prefix_states() {
        let trace = recorded();
        let replay = Replay::new(&trace);
        let mid = Frame(trace.len() as u64 / 2);

        let mut reference = MachineState::new(trace.base_map());
        reference.regs = trace.initial_regs.clone();
        for event in &trace.events[..mid.as_u64() as usize] {
            reference.apply(event);
        }

        let state = replay.state_at(mid);
        assert_eq!(state.regs, reference.regs);
        assert_eq!(state.output, reference.output);
        assert_eq!(state.mem.dirty_pages(), reference.mem.dirty_pages());
    }

    #[test]
    fn frame_zero_is_the_initial_state() {
        let trace = recorded();
        let replay = Replay::new(&trace);
        let state = replay.state_at(Frame::ZERO);
        assert_eq!(state.regs, trace.initial_regs);
        assert!(state.output.is_empty());
    }

    #[test]
    fn target_is_clamped_to_frame_count() {
        let trace = recorded();
        let replay = Replay::new(&trace);
        let beyond = replay.state_at(Frame(trace.len() as u64 + 10_000));
        let last = replay.state_at(trace.last_frame());
        assert_eq!(beyond.regs, last.regs);
        assert_eq!(beyond.output, last.output);
    }

    #[test]
    fn reverse_stepping_is_consistent_with_forward_replay() {
        let trace = recorded();
        let replay = Replay::new(&trace);
        let last = trace.last_frame();

        let mut cursor = last;
        for _ in 0..50 {
            let Some(prev) = cursor.prev() else { break };
            let back = replay.step_back(cursor).expect("step_back");
            let forward = replay.state_at(prev);
            assert_eq!(back.regs, forward.regs, "frame {prev} regs diverge");
            assert_eq!(back.output, forward.output, "frame {prev} output diverges");
            cursor = prev;
        }
    }

    #[test]
    fn snapshots_do_not_change_replayed_state() {
        let mut trace = recorded();
        // Build a trace that has snapshots by recording with a small policy.
        // Snapshot policy is internal to the session; instead, capture a few
        // snapshots here from the replayed states and confirm results hold.
        for frame in [Frame(1), Frame(trace.len() as u64 / 3), trace.last_frame()].iter() {
            let state = Replay::new(&trace).state_at(*frame);
            trace.snapshots.push(Snapshot::capture(*frame, &state));
        }
        trace.snapshots.sort_by_key(|s| s.frame.as_u64());

        let with_snaps = Replay::new(&trace);
        for frame in [
            Frame(0),
            Frame(1),
            Frame(trace.len() as u64 / 2),
            trace.last_frame(),
        ] {
            let state = with_snaps.state_at(frame);
            let mut reference = MachineState::new(trace.base_map());
            reference.regs = trace.initial_regs.clone();
            for event in &trace.events[..frame.as_u64() as usize] {
                reference.apply(event);
            }
            assert_eq!(state.regs, reference.regs, "frame {frame} regs");
            assert_eq!(state.output, reference.output, "frame {frame} output");
        }
    }

    #[test]
    fn events_between_clamps_and_orders() {
        let trace = recorded();
        let replay = Replay::new(&trace);
        let all = replay.events_between(Frame::ZERO, trace.last_frame());
        assert_eq!(all.len(), trace.len());
        assert!(replay.events_between(Frame(5), Frame(2)).is_empty());
        assert!(replay.events_between(Frame::ZERO, Frame(u64::MAX)).len() == trace.len());
    }

    #[test]
    fn event_at_reports_the_producing_event() {
        let trace = recorded();
        let replay = Replay::new(&trace);
        assert!(replay.event_at(Frame::ZERO).is_none());
        assert_eq!(replay.event_at(Frame(1)), Some(&trace.events[0]));
    }

    #[test]
    fn replay_finds_syscall_events() {
        let trace = recorded();
        let replay = Replay::new(&trace);
        let has_exit = replay
            .events_between(Frame::ZERO, trace.last_frame())
            .iter()
            .any(|e| {
                matches!(
                    e,
                    Event::Exit {
                        kind: ExitKind::Exit,
                        ..
                    }
                )
            });
        assert!(has_exit);
        let has_reg = replay
            .events_between(Frame::ZERO, trace.last_frame())
            .iter()
            .any(|e| {
                matches!(
                    e,
                    Event::RegWrite {
                        reg: RegId::Rip,
                        ..
                    }
                )
            });
        assert!(has_reg, "RIP changes must be recorded");
    }
}
