//! The machine state that events are applied to.
//!
//! The projector never re-executes instructions during replay. Reconstructing
//! a frame means starting from a base memory image plus the nearest snapshot,
//! then folding events in. This module is the single place that defines what
//! "apply an event" means, so the capture path and the replay path can never
//! drift apart.

use std::collections::HashMap;
use std::sync::Arc;

use crate::event::{Event, RegId, REG_COUNT};

/// Guest page size (x86-64).
pub const PAGE_SIZE: usize = 4096;
/// log2 of [`PAGE_SIZE`].
pub const PAGE_SHIFT: u32 = 12;

/// Page-align an address downwards.
pub fn page_base(addr: u64) -> u64 {
    addr & !((PAGE_SIZE as u64) - 1)
}

/// One page of guest memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page(pub Box<[u8; PAGE_SIZE]>);

impl Page {
    /// An all-zero page.
    pub fn zero() -> Self {
        Page(Box::new([0u8; PAGE_SIZE]))
    }

    /// Build a page from exactly `PAGE_SIZE` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut page = Self::zero();
        let n = bytes.len().min(PAGE_SIZE);
        page.0[..n].copy_from_slice(&bytes[..n]);
        page
    }
}

/// The value of every tracked register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegFile {
    pub v: [u64; REG_COUNT],
}

impl RegFile {
    pub fn new() -> Self {
        RegFile {
            v: [0u64; REG_COUNT],
        }
    }

    pub fn get(&self, reg: RegId) -> u64 {
        self.v[reg.as_u8() as usize]
    }

    pub fn set(&mut self, reg: RegId, value: u64) {
        self.v[reg.as_u8() as usize] = value;
    }

    /// The program counter.
    pub fn ip(&self) -> u64 {
        self.get(RegId::Rip)
    }

    /// Set the program counter.
    pub fn set_ip(&mut self, value: u64) {
        self.set(RegId::Rip, value);
    }

    /// Registers that differ between `self` and `other`, oldest id first.
    pub fn diff(&self, other: &RegFile) -> Vec<RegId> {
        RegId::ALL
            .iter()
            .copied()
            .filter(|reg| self.get(*reg) != other.get(*reg))
            .collect()
    }
}

impl Default for RegFile {
    fn default() -> Self {
        Self::new()
    }
}

/// A guest address space: an immutable base image plus written pages.
///
/// `base` is shared by every reconstructed state, so seeking never copies the
/// whole image; only pages touched by events are cloned into `dirty`.
#[derive(Debug, Clone)]
pub struct Memory {
    base: Arc<HashMap<u64, Page>>,
    dirty: HashMap<u64, Page>,
}

impl Memory {
    pub fn new(base: Arc<HashMap<u64, Page>>) -> Self {
        Memory {
            base,
            dirty: HashMap::new(),
        }
    }

    /// Read `len` bytes starting at `addr`, walking page boundaries.
    ///
    /// Addresses outside any known page read as zero, matching a freshly
    /// mapped anonymous region.
    pub fn read(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut cursor = addr;
        while out.len() < len {
            let base = page_base(cursor);
            let offset = (cursor - base) as usize;
            let take = (PAGE_SIZE - offset).min(len - out.len());
            let page = self.page(base);
            out.extend_from_slice(&page.0[offset..offset + take]);
            match base.checked_add(PAGE_SIZE as u64) {
                Some(next) => cursor = next,
                None => {
                    // Past the end of the 64-bit address space: the remaining
                    // bytes are unmapped and read as zero.
                    out.resize(len, 0);
                    break;
                }
            }
        }
        out
    }

    /// The contents of the page containing `addr`.
    pub fn page(&self, addr: u64) -> Page {
        let base = page_base(addr);
        if let Some(page) = self.dirty.get(&base) {
            return page.clone();
        }
        if let Some(page) = self.base.get(&base) {
            return page.clone();
        }
        Page::zero()
    }

    /// Write `data` at `addr`, updating only the pages it overlaps.
    pub fn write(&mut self, addr: u64, data: &[u8]) {
        let mut cursor = addr;
        let mut written = 0usize;
        while written < data.len() {
            let base = page_base(cursor);
            let offset = (cursor - base) as usize;
            let take = (PAGE_SIZE - offset).min(data.len() - written);
            let entry = self
                .dirty
                .entry(base)
                .or_insert_with(|| self.base.get(&base).cloned().unwrap_or_else(Page::zero));
            entry.0[offset..offset + take].copy_from_slice(&data[written..written + take]);
            written += take;
            match base.checked_add(PAGE_SIZE as u64) {
                Some(next) => cursor = next,
                None => break,
            }
        }
    }

    /// Pages modified relative to the base image, sorted by address.
    ///
    /// Sorted output keeps serialized traces byte-for-byte reproducible.
    pub fn dirty_pages(&self) -> Vec<(u64, Page)> {
        let mut pages: Vec<(u64, Page)> = self.dirty.iter().map(|(k, v)| (*k, v.clone())).collect();
        pages.sort_by_key(|(addr, _)| *addr);
        pages
    }

    /// Number of pages modified relative to the base image.
    pub fn dirty_count(&self) -> usize {
        self.dirty.len()
    }

    /// Restore from a base image plus a set of modified pages.
    pub fn restore(base: Arc<HashMap<u64, Page>>, dirty: Vec<(u64, Page)>) -> Self {
        Memory {
            base,
            dirty: dirty.into_iter().collect(),
        }
    }
}

/// A fully reconstructable machine state.
#[derive(Debug, Clone)]
pub struct MachineState {
    pub regs: RegFile,
    pub mem: Memory,
    pub output: Vec<u8>,
}

impl MachineState {
    pub fn new(base: Arc<HashMap<u64, Page>>) -> Self {
        MachineState {
            regs: RegFile::new(),
            mem: Memory::new(base),
            output: Vec::new(),
        }
    }

    /// Fold one event into this state.
    ///
    /// This is the only implementation of "what an event does". It must stay
    /// total (no panics) because it runs on decoded, potentially hostile input.
    pub fn apply(&mut self, event: &Event) {
        match event {
            Event::Insn { addr, size, .. } => {
                self.regs.set_ip(addr.wrapping_add(*size as u64));
            }
            Event::RegWrite { reg, value } => {
                self.regs.set(*reg, *value);
            }
            Event::MemWrite { addr, data } => {
                self.mem.write(*addr, data);
            }
            Event::SyscallEnter { .. } => {
                // Informational: the effects are carried by RegWrite and
                // SyscallExit events.
            }
            Event::SyscallExit { ret } => {
                self.regs.set(RegId::Rax, *ret as u64);
            }
            Event::Output { data } => {
                self.output.extend_from_slice(data);
            }
            Event::Exit { .. } => {
                // Informational: the final register and memory state is already
                // recorded by the preceding events.
            }
        }
    }

    /// Fold a slice of events in order.
    pub fn apply_all(&mut self, events: &[Event]) {
        for event in events {
            self.apply(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ExitKind;

    fn base_with(addr: u64, bytes: &[u8]) -> Arc<HashMap<u64, Page>> {
        let mut map = HashMap::new();
        map.insert(page_base(addr), Page::from_bytes(bytes));
        Arc::new(map)
    }

    #[test]
    fn reads_from_base_then_dirty() {
        let base = base_with(0x1000, b"AAAA");
        let mut mem = Memory::new(base);
        assert_eq!(&mem.read(0x1000, 4), b"AAAA");
        mem.write(0x1000, b"BB");
        assert_eq!(&mem.read(0x1000, 4), b"BBAA");
        assert_eq!(mem.dirty_count(), 1);
    }

    #[test]
    fn reads_across_page_boundary() {
        let base = base_with(0x2000, &[0xaa; 16]);
        let mem = Memory::new(base);
        // Last four bytes of page 0x1000 and first four of page 0x2000.
        let out = mem.read(0x1ffc, 8);
        assert_eq!(out, vec![0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa]);
    }

    #[test]
    fn writes_across_page_boundary() {
        let mem_base = Arc::new(HashMap::new());
        let mut mem = Memory::new(mem_base);
        mem.write(0x1ffc, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(mem.read(0x1ffc, 8), vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(mem.dirty_count(), 2);
    }

    #[test]
    fn unmapped_pages_read_as_zero() {
        let mem = Memory::new(Arc::new(HashMap::new()));
        assert_eq!(mem.read(0xdead_0000, 4), vec![0, 0, 0, 0]);
    }

    #[test]
    fn dirty_pages_are_sorted() {
        let mut mem = Memory::new(Arc::new(HashMap::new()));
        mem.write(0x5000, b"x");
        mem.write(0x1000, b"y");
        mem.write(0x3000, b"z");
        let addrs: Vec<u64> = mem.dirty_pages().into_iter().map(|(a, _)| a).collect();
        assert_eq!(addrs, vec![0x1000, 0x3000, 0x5000]);
    }

    #[test]
    fn apply_insn_advances_ip() {
        let mut state = MachineState::new(Arc::new(HashMap::new()));
        state.apply(&Event::Insn {
            addr: 0x401000,
            size: 5,
            bytes: vec![0x90; 5],
        });
        assert_eq!(state.regs.ip(), 0x401005);
    }

    #[test]
    fn apply_reg_write_and_syscall_return() {
        let mut state = MachineState::new(Arc::new(HashMap::new()));
        state.apply(&Event::RegWrite {
            reg: RegId::Rax,
            value: 7,
        });
        assert_eq!(state.regs.get(RegId::Rax), 7);
        state.apply(&Event::SyscallExit { ret: -38 });
        assert_eq!(state.regs.get(RegId::Rax) as i64, -38);
    }

    #[test]
    fn apply_mem_write_and_output() {
        let mut state = MachineState::new(Arc::new(HashMap::new()));
        state.apply(&Event::MemWrite {
            addr: 0x1000,
            data: b"hi".to_vec(),
        });
        assert_eq!(state.mem.read(0x1000, 2), b"hi");
        state.apply(&Event::Output {
            data: b"out".to_vec(),
        });
        state.apply(&Event::Output {
            data: b"put".to_vec(),
        });
        assert_eq!(state.output, b"output");
    }

    #[test]
    fn informational_events_are_noops() {
        let mut state = MachineState::new(Arc::new(HashMap::new()));
        state.regs.set_ip(0x1234);
        state.apply(&Event::SyscallEnter {
            nr: 1,
            name: "write".into(),
            args: [1, 2, 3, 4, 5, 6],
        });
        state.apply(&Event::Exit {
            kind: ExitKind::Exit,
            value: 0,
        });
        assert_eq!(state.regs.ip(), 0x1234);
        assert!(state.mem.dirty_pages().is_empty());
    }

    #[test]
    fn regfile_diff_reports_changed_ids() {
        let mut a = RegFile::new();
        let mut b = RegFile::new();
        b.set(RegId::Rax, 1);
        b.set(RegId::Rip, 0x401000);
        assert_eq!(a.diff(&b), vec![RegId::Rax, RegId::Rip]);
        a.set(RegId::Rax, 1);
        assert_eq!(a.diff(&b), vec![RegId::Rip]);
    }
}
