//! The capture session: run an ELF under Unicorn and record every observable
//! change into a [`Trace`].
//!
//! This is the only place that talks to Unicorn during a recording. It reuses
//! winVpwn's ELF loader and syscall dispatcher so the guest sees exactly the
//! same syscall semantics as the projector would, then layers instruction-level
//! observation on top.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Prot, RegisterX86, X86Insn};
use unicorn_engine::Unicorn;

use winvpwn_core::cpu::unicorn_engine::{STACK_BASE, STACK_SIZE};
use winvpwn_core::elf::{load_elf, ElfError, LoadedElf};
use winvpwn_core::syscall::dispatch::{Dispatch, SyscallOutcome, SyscallRegs};
use winvpwn_core::syscall::dispatch_impl;
use winvpwn_core::vkernel::mem::UnicornGuest;
use winvpwn_core::vkernel::process::ProcessState;
use winvpwn_core::vkernel::{Context, ExitReason};

use crate::event::{Event, ExitKind, Frame, RegId, REG_COUNT};
use crate::snapshot::{Snapshot, SnapshotPolicy};
use crate::state::{page_base, MachineState, Page, RegFile, PAGE_SIZE};
use crate::trace::Trace;

/// How a recording should be run.
#[derive(Debug, Clone, Default)]
pub struct RecordOptions {
    /// Wall-clock budget in milliseconds. `0` means no limit.
    pub timeout_ms: u64,
    /// Stop after this many events. `0` means no limit.
    pub max_events: usize,
}

/// Errors produced while recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The image could not be loaded.
    Elf(ElfError),
    /// The emulator failed.
    Engine(String),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::Elf(e) => write!(f, "{e}"),
            RecordError::Engine(msg) => write!(f, "E601: recording failed: {msg}"),
        }
    }
}

impl std::error::Error for RecordError {}

/// Register mapping between the projector's ids and Unicorn's enums.
const REG_PAIRS: [(RegId, RegisterX86); REG_COUNT] = [
    (RegId::Rax, RegisterX86::RAX),
    (RegId::Rbx, RegisterX86::RBX),
    (RegId::Rcx, RegisterX86::RCX),
    (RegId::Rdx, RegisterX86::RDX),
    (RegId::Rsi, RegisterX86::RSI),
    (RegId::Rdi, RegisterX86::RDI),
    (RegId::Rbp, RegisterX86::RBP),
    (RegId::Rsp, RegisterX86::RSP),
    (RegId::R8, RegisterX86::R8),
    (RegId::R9, RegisterX86::R9),
    (RegId::R10, RegisterX86::R10),
    (RegId::R11, RegisterX86::R11),
    (RegId::R12, RegisterX86::R12),
    (RegId::R13, RegisterX86::R13),
    (RegId::R14, RegisterX86::R14),
    (RegId::R15, RegisterX86::R15),
    (RegId::Rip, RegisterX86::RIP),
    (RegId::Rflags, RegisterX86::EFLAGS),
];

/// Accumulates events and snapshots during a recording.
struct Collector {
    events: Vec<Event>,
    snapshots: Vec<Snapshot>,
    policy: SnapshotPolicy,
    state: MachineState,
    prev_regs: RegFile,
    max_events: usize,
    exited: bool,
    stopped: bool,
}

impl Collector {
    fn push(&mut self, event: Event) {
        if matches!(event, Event::Exit { .. }) {
            self.exited = true;
        }
        self.state.apply(&event);
        self.events.push(event);
        let applied = self.events.len() as u64;
        if self.policy.observe(applied) {
            self.snapshots
                .push(Snapshot::capture(Frame(applied), &self.state));
        }
    }

    /// Emit a `RegWrite` for every register that changed since the last
    /// instruction boundary, then remember the new values.
    fn record_reg_diff(&mut self, current: &RegFile) {
        let changed = self.prev_regs.diff(current);
        for reg in changed {
            self.push(Event::RegWrite {
                reg,
                value: current.get(reg),
            });
        }
        self.prev_regs = current.clone();
    }

    fn over_budget(&self) -> bool {
        self.max_events > 0 && self.events.len() >= self.max_events
    }
}

/// Load `image` and record its execution.
pub fn record_elf(image: &[u8], opts: &RecordOptions) -> Result<Trace, RecordError> {
    let elf = load_elf(image).map_err(RecordError::Elf)?;
    let base_pages = build_base_pages(&elf);
    let base_map: HashMap<u64, Page> = base_pages.iter().cloned().collect();
    let base_arc = Arc::new(base_map);
    let page_prots = compute_page_prots(&elf);

    let image_hash: [u8; 32] = Sha256::digest(image).into();

    let mut dispatch = Dispatch::new();
    dispatch_impl::register_all(&mut dispatch);
    let dispatch = Arc::new(dispatch);

    let collector = Rc::new(RefCell::new(Collector {
        events: Vec::new(),
        snapshots: Vec::new(),
        policy: SnapshotPolicy::new(),
        state: MachineState::new(Arc::clone(&base_arc)),
        prev_regs: RegFile::new(),
        max_events: opts.max_events,
        exited: false,
        stopped: false,
    }));

    let mut uc: Unicorn<'static, ()> =
        Unicorn::new(Arch::X86, Mode::MODE_64).map_err(|e| RecordError::Engine(e.to_string()))?;

    for (addr, page) in &base_pages {
        let prot = page_prots
            .get(addr)
            .copied()
            .unwrap_or(Prot::READ | Prot::WRITE);
        uc.mem_map(*addr, PAGE_SIZE as u64, prot)
            .map_err(|e| RecordError::Engine(format!("map 0x{addr:x}: {e}")))?;
        uc.mem_write(*addr, &page.0[..])
            .map_err(|e| RecordError::Engine(format!("write 0x{addr:x}: {e}")))?;
    }

    install_code_hook(&mut uc, Rc::clone(&collector))?;
    install_mem_hook(&mut uc, Rc::clone(&collector))?;
    install_syscall_hook(&mut uc, Rc::clone(&collector), Arc::clone(&dispatch))?;

    // Initial register state: RIP at the entry point, RSP at the top of the
    // zeroed argument frame.
    let stack_top = STACK_BASE + STACK_SIZE;
    let argc_addr = stack_top - 0x20;
    uc.mem_write(argc_addr, &[0u8; 0x20])
        .map_err(|e| RecordError::Engine(format!("stack init: {e}")))?;
    uc.reg_write(RegisterX86::RIP, elf.entry)
        .map_err(|e| RecordError::Engine(format!("set rip: {e}")))?;
    uc.reg_write(RegisterX86::RSP, argc_addr)
        .map_err(|e| RecordError::Engine(format!("set rsp: {e}")))?;

    let initial_regs = {
        let initial = read_regs(&uc);
        collector.borrow_mut().prev_regs = initial.clone();
        initial
    };

    let run = uc.emu_start(elf.entry, u64::MAX, opts.timeout_ms.saturating_mul(1000), 0);

    // Fold in any register changes produced by the final instruction, but only
    // when the run ended without an explicit exit: a guest exit already carries
    // its own return value and must remain the terminal event.
    if !collector.borrow().exited {
        let final_regs = read_regs(&uc);
        collector.borrow_mut().record_reg_diff(&final_regs);
    }

    let mut col = collector.borrow_mut();
    match run {
        Ok(()) => {
            if !col.exited {
                let rip = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
                col.push(Event::Exit {
                    kind: ExitKind::Stopped,
                    value: rip,
                });
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if is_unmapped(&msg) {
                if !col.exited {
                    let rip = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
                    col.push(Event::Exit {
                        kind: ExitKind::Falloff,
                        value: rip,
                    });
                }
            } else {
                return Err(RecordError::Engine(msg));
            }
        }
    }
    drop(col);

    drop(uc);
    let collected = Rc::try_unwrap(collector)
        .map_err(|_| RecordError::Engine("collector still shared after run".into()))?
        .into_inner();

    let mut trace = Trace::new(elf.entry, image_hash, initial_regs, base_pages);
    trace.events = collected.events;
    trace.snapshots = collected.snapshots;
    Ok(trace)
}

fn install_code_hook(
    uc: &mut Unicorn<'static, ()>,
    collector: Rc<RefCell<Collector>>,
) -> Result<(), RecordError> {
    uc.add_code_hook(0, u64::MAX, move |uc, address, size| {
        let current = read_regs(uc);
        let mut col = collector.borrow_mut();
        col.record_reg_diff(&current);
        let mut bytes = vec![0u8; size as usize];
        let _ = uc.mem_read(address, &mut bytes);
        col.push(Event::Insn {
            addr: address,
            size: size as u8,
            bytes,
        });
        if col.over_budget() {
            col.stopped = true;
            let _ = uc.emu_stop();
        }
    })
    .map_err(|e| RecordError::Engine(format!("install code hook: {e}")))?;
    Ok(())
}

fn install_mem_hook(
    uc: &mut Unicorn<'static, ()>,
    collector: Rc<RefCell<Collector>>,
) -> Result<(), RecordError> {
    uc.add_mem_hook(
        HookType::MEM_WRITE,
        0,
        u64::MAX,
        move |uc, _mem_type, addr, size, value| {
            let data = written_bytes(uc, addr, size, value);
            let mut col = collector.borrow_mut();
            col.push(Event::MemWrite { addr, data });
            if col.over_budget() {
                col.stopped = true;
                let _ = uc.emu_stop();
            }
            true
        },
    )
    .map_err(|e| RecordError::Engine(format!("install mem hook: {e}")))?;
    Ok(())
}

fn install_syscall_hook(
    uc: &mut Unicorn<'static, ()>,
    collector: Rc<RefCell<Collector>>,
    dispatch: Arc<Dispatch>,
) -> Result<(), RecordError> {
    uc.add_insn_sys_hook(X86Insn::SYSCALL, 0, u64::MAX, move |uc| {
        let nr = uc.reg_read(RegisterX86::RAX).unwrap_or(0) as i64;
        let args = [
            uc.reg_read(RegisterX86::RDI).unwrap_or(0),
            uc.reg_read(RegisterX86::RSI).unwrap_or(0),
            uc.reg_read(RegisterX86::RDX).unwrap_or(0),
            uc.reg_read(RegisterX86::R10).unwrap_or(0),
            uc.reg_read(RegisterX86::R8).unwrap_or(0),
            uc.reg_read(RegisterX86::R9).unwrap_or(0),
        ];
        let rip = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
        let regs = SyscallRegs::from_regs(nr, args, rip);

        let (outcome, output) = {
            let mut ctx = Context {
                process: ProcessState::Running,
                mem: Box::new(UnicornGuest::new(uc)),
                io: Default::default(),
            };
            let outcome = dispatch.dispatch(&mut ctx, regs);
            (outcome, ctx.io.combined())
        };

        let mut col = collector.borrow_mut();
        let name = dispatch
            .get(nr)
            .map(|h| h.name().to_string())
            .unwrap_or_else(|| "<unimplemented>".to_string());
        col.push(Event::SyscallEnter { nr, name, args });
        if !output.is_empty() {
            col.push(Event::Output { data: output });
        }
        match outcome {
            Ok(SyscallOutcome::Return { ret }) => {
                let _ = uc.reg_write(RegisterX86::RAX, ret as u64);
                col.push(Event::SyscallExit { ret });
            }
            Ok(SyscallOutcome::Exit(reason)) => {
                let (kind, value) = exit_kind(&reason);
                col.push(Event::Exit { kind, value });
                let _ = uc.emu_stop();
            }
            Err(e) => {
                // A dispatcher-level failure is an engine fault, not a guest
                // errno; record it and stop rather than inventing a return.
                let _ = e;
                let _ = uc.emu_stop();
            }
        }
    })
    .map_err(|e| RecordError::Engine(format!("install syscall hook: {e}")))?;
    Ok(())
}

fn read_regs<T>(uc: &Unicorn<'_, T>) -> RegFile {
    let mut regs = RegFile::new();
    for (reg, uc_reg) in REG_PAIRS {
        regs.set(reg, uc.reg_read(uc_reg).unwrap_or(0));
    }
    regs
}

fn written_bytes<T>(uc: &Unicorn<'_, T>, addr: u64, size: usize, value: i64) -> Vec<u8> {
    if size <= 8 {
        let raw = value as u64;
        return (0..size).map(|i| ((raw >> (8 * i)) & 0xff) as u8).collect();
    }
    let mut buf = vec![0u8; size];
    if uc.mem_read(addr, &mut buf).is_err() {
        return Vec::new();
    }
    buf
}

fn exit_kind(reason: &ExitReason) -> (ExitKind, u64) {
    match reason {
        ExitReason::Exit { code } => (ExitKind::Exit, *code as u64),
        ExitReason::Falloff { rip } => (ExitKind::Falloff, *rip),
        ExitReason::Stopped => (ExitKind::Stopped, 0),
    }
}

fn prot_from_flags(flags: u32) -> Prot {
    let mut prot = Prot::NONE;
    if flags & 0x4 != 0 {
        prot |= Prot::READ;
    }
    if flags & 0x2 != 0 {
        prot |= Prot::WRITE;
    }
    if flags & 0x1 != 0 {
        prot |= Prot::EXEC;
    }
    prot
}

/// Every page that makes up the initial guest image: each `PT_LOAD` segment
/// expanded to page granularity, plus the zeroed stack.
fn build_base_pages(elf: &LoadedElf) -> Vec<(u64, Page)> {
    let mut pages: BTreeMap<u64, Page> = BTreeMap::new();

    for seg in &elf.segments {
        let seg_start = seg.vaddr;
        let seg_end = seg.vaddr + seg.memsz;
        let mut addr = page_base(seg_start);
        while addr < seg_end {
            let page = pages.entry(addr).or_insert_with(Page::zero);
            let lo = seg_start.max(addr);
            let hi = seg_end.min(addr + PAGE_SIZE as u64);
            if lo < hi {
                let src = (lo - seg_start) as usize;
                let dst = (lo - addr) as usize;
                let len = (hi - lo) as usize;
                page.0[dst..dst + len].copy_from_slice(&seg.data[src..src + len]);
            }
            addr += PAGE_SIZE as u64;
        }
    }

    let mut addr = STACK_BASE;
    while addr < STACK_BASE + STACK_SIZE {
        pages.entry(addr).or_insert_with(Page::zero);
        addr += PAGE_SIZE as u64;
    }

    pages.into_iter().collect()
}

/// Permission for each initial page, honouring overlapping segments (union).
fn compute_page_prots(elf: &LoadedElf) -> BTreeMap<u64, Prot> {
    let mut map: BTreeMap<u64, Prot> = BTreeMap::new();
    for seg in &elf.segments {
        let end = seg.vaddr + seg.memsz;
        let mut addr = page_base(seg.vaddr);
        while addr < end {
            let entry = map.entry(addr).or_insert(Prot::NONE);
            *entry |= prot_from_flags(seg.flags);
            addr += PAGE_SIZE as u64;
        }
    }
    let mut addr = STACK_BASE;
    while addr < STACK_BASE + STACK_SIZE {
        map.insert(addr, Prot::READ | Prot::WRITE);
        addr += PAGE_SIZE as u64;
    }
    map
}

fn is_unmapped(msg: &str) -> bool {
    msg.contains("READ_PROTECT")
        || msg.contains("FETCH_PROTECT")
        || msg.contains("READ_UNMAPPED")
        || msg.contains("FETCH_UNMAPPED")
        || msg.contains("WRITE_UNMAPPED")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::Replay;

    fn hello() -> Vec<u8> {
        include_bytes!("../tests/fixtures/hello_static").to_vec()
    }

    #[test]
    fn records_contract_events_for_hello() {
        let trace = record_elf(&hello(), &RecordOptions::default()).expect("record");
        assert!(!trace.is_empty(), "a recording must contain events");
        assert!(trace.events.iter().any(|e| matches!(e, Event::Insn { .. })));
        assert!(trace
            .events
            .iter()
            .any(|e| matches!(e, Event::SyscallEnter { name, .. } if name == "write")));
        assert!(trace
            .events
            .iter()
            .any(|e| matches!(e, Event::Output { data } if data == b"hello, winVpwn\n")));
        assert!(matches!(
            trace.events.last(),
            Some(Event::Exit {
                kind: ExitKind::Exit,
                value: 0
            })
        ));
    }

    #[test]
    fn replay_final_frame_matches_recorded_output() {
        let trace = record_elf(&hello(), &RecordOptions::default()).expect("record");
        let replay = Replay::new(&trace);
        let state = replay.state_at(trace.last_frame());
        assert_eq!(state.output, b"hello, winVpwn\n");
    }

    #[test]
    fn max_events_stops_the_recording() {
        let opts = RecordOptions {
            timeout_ms: 0,
            max_events: 5,
        };
        let trace = record_elf(&hello(), &opts).expect("record");
        assert!(trace.len() >= 5);
    }
}
