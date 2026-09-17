//! The event model: the immutable record of everything that happened.
//!
//! A [`Frame`] is a position in history; `Frame(n)` means "after the first `n`
//! events have been applied". A frame is therefore an event count, not an
//! index — this removes an entire class of off-by-one bugs from the replay
//! layer, because `snapshot.frame` and `seek(target)` speak the same language.

pub mod codec;

use std::fmt;

/// A position in the execution history.
///
/// `Frame(n)` denotes the state after `n` events have been applied starting
/// from frame 0 (the initial machine state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Frame(pub u64);

impl Frame {
    /// The initial state, before any event.
    pub const ZERO: Frame = Frame(0);

    /// The frame after applying one more event.
    pub fn next(self) -> Frame {
        Frame(self.0 + 1)
    }

    /// The previous frame, if any.
    pub fn prev(self) -> Option<Frame> {
        self.0.checked_sub(1).map(Frame)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The x86-64 register subset the projector tracks.
///
/// The numeric values are part of the on-disk format; never renumber them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RegId {
    Rax = 0,
    Rbx = 1,
    Rcx = 2,
    Rdx = 3,
    Rsi = 4,
    Rdi = 5,
    Rbp = 6,
    Rsp = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    Rip = 16,
    Rflags = 17,
}

/// Number of tracked registers. Keep in sync with [`RegId`].
pub const REG_COUNT: usize = 18;

impl RegId {
    /// Every register, in encoding order.
    pub const ALL: [RegId; REG_COUNT] = [
        RegId::Rax,
        RegId::Rbx,
        RegId::Rcx,
        RegId::Rdx,
        RegId::Rsi,
        RegId::Rdi,
        RegId::Rbp,
        RegId::Rsp,
        RegId::R8,
        RegId::R9,
        RegId::R10,
        RegId::R11,
        RegId::R12,
        RegId::R13,
        RegId::R14,
        RegId::R15,
        RegId::Rip,
        RegId::Rflags,
    ];

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(byte: u8) -> Option<RegId> {
        RegId::ALL.get(byte as usize).copied()
    }

    /// Lower-case conventional name.
    pub fn name(self) -> &'static str {
        match self {
            RegId::Rax => "rax",
            RegId::Rbx => "rbx",
            RegId::Rcx => "rcx",
            RegId::Rdx => "rdx",
            RegId::Rsi => "rsi",
            RegId::Rdi => "rdi",
            RegId::Rbp => "rbp",
            RegId::Rsp => "rsp",
            RegId::R8 => "r8",
            RegId::R9 => "r9",
            RegId::R10 => "r10",
            RegId::R11 => "r11",
            RegId::R12 => "r12",
            RegId::R13 => "r13",
            RegId::R14 => "r14",
            RegId::R15 => "r15",
            RegId::Rip => "rip",
            RegId::Rflags => "rflags",
        }
    }
}

impl fmt::Display for RegId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How the execution ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitKind {
    /// Terminated through `exit`/`exit_group`; the value is the exit code.
    Exit = 0,
    /// Execution fell off the mapped image; the value is the RIP it reached.
    Falloff = 1,
    /// Execution stopped without an exit (timeout or explicit stop).
    Stopped = 2,
}

impl ExitKind {
    pub fn from_u8(byte: u8) -> Option<ExitKind> {
        match byte {
            0 => Some(ExitKind::Exit),
            1 => Some(ExitKind::Falloff),
            2 => Some(ExitKind::Stopped),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ExitKind::Exit => "exit",
            ExitKind::Falloff => "falloff",
            ExitKind::Stopped => "stopped",
        }
    }
}

/// One observable change during execution.
///
/// Every variant carries enough data to be applied to a [`MachineState`]
/// without re-executing the instruction that produced it. Read-only operations
/// are deliberately not recorded.
///
/// [`MachineState`]: crate::state::MachineState
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// One instruction completed. `bytes` holds the raw encoding so consumers
    /// can disassemble without a Rust-side capstone dependency.
    Insn { addr: u64, size: u8, bytes: Vec<u8> },
    /// A register changed value, as observed at the next instruction boundary.
    RegWrite { reg: RegId, value: u64 },
    /// A memory range was written.
    MemWrite { addr: u64, data: Vec<u8> },
    /// A system call was entered.
    SyscallEnter {
        nr: i64,
        name: String,
        args: [u64; 6],
    },
    /// A system call returned; `ret` is the guest-visible value in `rax`.
    SyscallExit { ret: i64 },
    /// The guest produced output.
    Output { data: Vec<u8> },
    /// The guest terminated.
    Exit { kind: ExitKind, value: u64 },
}

impl Event {
    /// A short human-readable label for tables and logs.
    pub fn label(&self) -> String {
        match self {
            Event::Insn { addr, .. } => format!("insn 0x{addr:x}"),
            Event::RegWrite { reg, value } => format!("{reg} = 0x{value:x}"),
            Event::MemWrite { addr, data } => format!("mem[0x{addr:x}] <- {} bytes", data.len()),
            Event::SyscallEnter { name, nr, .. } => format!("{name} ({nr})"),
            Event::SyscallExit { ret } => format!("ret = {ret}"),
            Event::Output { data } => format!("output {} bytes", data.len()),
            Event::Exit { kind, value } => format!("{} {value}", kind.name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_arithmetic() {
        assert_eq!(Frame::ZERO.next(), Frame(1));
        assert_eq!(Frame(3).prev(), Some(Frame(2)));
        assert_eq!(Frame::ZERO.prev(), None);
    }

    #[test]
    fn reg_id_roundtrip() {
        for reg in RegId::ALL {
            assert_eq!(RegId::from_u8(reg.as_u8()), Some(reg));
        }
        assert_eq!(RegId::from_u8(REG_COUNT as u8), None);
        assert_eq!(RegId::Rax.name(), "rax");
        assert_eq!(RegId::R15.name(), "r15");
    }

    #[test]
    fn reg_ids_are_compact_and_ordered() {
        for (i, reg) in RegId::ALL.iter().enumerate() {
            assert_eq!(reg.as_u8() as usize, i);
        }
    }

    #[test]
    fn exit_kind_roundtrip() {
        for k in [ExitKind::Exit, ExitKind::Falloff, ExitKind::Stopped] {
            assert_eq!(ExitKind::from_u8(k as u8), Some(k));
        }
        assert_eq!(ExitKind::from_u8(9), None);
    }
}
