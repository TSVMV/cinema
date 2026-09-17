//! The trace container and the `.ctrace` on-disk format.
//!
//! A trace is self-contained: it carries the base memory image, the event
//! stream and the snapshot index. Replaying a `.ctrace` therefore needs no ELF
//! file and no re-execution, which is what makes traces shareable artifacts.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::event::codec::{write_bytes, write_uvarint, DecodeError, Reader};
use crate::event::{Event, Frame, RegId, REG_COUNT};
use crate::snapshot::Snapshot;
use crate::state::{MachineState, Page, RegFile, PAGE_SIZE};

/// Magic bytes at the head of every `.ctrace` file.
pub const MAGIC: [u8; 4] = *b"CTRC";
/// Current format version.
pub const FORMAT_VERSION: u16 = 1;
/// Architecture id for x86-64.
pub const ARCH_X86_64: u8 = 0;
/// FNV-1a 64 offset basis, used for the trailing integrity checksum.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64 prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Errors while reading or writing a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceError {
    /// The file does not start with [`MAGIC`].
    BadMagic,
    /// The format version is newer than this build understands.
    UnsupportedVersion(u16),
    /// The architecture id is unknown.
    UnsupportedArch(u8),
    /// The event stream failed to decode.
    Decode(DecodeError),
    /// The trailing checksum does not match the payload.
    ChecksumMismatch { expected: u64, actual: u64 },
    /// The file is too short to contain the header or footer.
    TooShort,
    /// A declared page count cannot fit in the remaining input.
    BadPageCount(u64),
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceError::BadMagic => write!(f, "not a cinema trace (bad magic)"),
            TraceError::UnsupportedVersion(v) => write!(f, "unsupported trace version {v}"),
            TraceError::UnsupportedArch(a) => write!(f, "unsupported architecture id {a}"),
            TraceError::Decode(e) => write!(f, "malformed trace: {e}"),
            TraceError::ChecksumMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#x}, got {actual:#x}"
                )
            }
            TraceError::TooShort => write!(f, "trace file is truncated"),
            TraceError::BadPageCount(n) => write!(f, "implausible page count {n}"),
        }
    }
}

impl std::error::Error for TraceError {}

impl From<DecodeError> for TraceError {
    fn from(e: DecodeError) -> Self {
        TraceError::Decode(e)
    }
}

/// A complete recording: base image, event stream and snapshot index.
#[derive(Debug, Clone)]
pub struct Trace {
    /// Program entry point at the time of recording.
    pub entry: u64,
    /// SHA-256 of the source image, for provenance.
    pub image_hash: [u8; 32],
    /// Registers at frame 0, before any event is applied.
    pub initial_regs: RegFile,
    /// The initial guest memory image, sorted by address.
    pub base_pages: Vec<(u64, Page)>,
    /// The event stream. `Frame(n)` means events `[0, n)` are applied.
    pub events: Vec<Event>,
    /// Snapshots, sorted by frame.
    pub snapshots: Vec<Snapshot>,
}

impl Trace {
    /// An empty trace with the given initial state.
    pub fn new(
        entry: u64,
        image_hash: [u8; 32],
        initial_regs: RegFile,
        base_pages: Vec<(u64, Page)>,
    ) -> Self {
        Trace {
            entry,
            image_hash,
            initial_regs,
            base_pages,
            events: Vec::new(),
            snapshots: Vec::new(),
        }
    }

    /// Number of events, i.e. the frame count of the final state.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True when no events were recorded.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The final frame.
    pub fn last_frame(&self) -> Frame {
        Frame(self.events.len() as u64)
    }

    /// The base image as a shared map for state reconstruction.
    pub fn base_map(&self) -> Arc<HashMap<u64, Page>> {
        Arc::new(self.base_pages.iter().cloned().collect())
    }

    /// Append an event.
    pub fn push(&mut self, event: Event) -> Frame {
        self.events.push(event);
        Frame(self.events.len() as u64)
    }

    /// Serialize to the `.ctrace` format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.push(ARCH_X86_64);
        out.push(0); // flags, reserved
        out.extend_from_slice(&self.entry.to_le_bytes());
        out.extend_from_slice(&self.image_hash);
        for reg in RegId::ALL {
            out.extend_from_slice(&self.initial_regs.get(reg).to_le_bytes());
        }

        write_uvarint(&mut out, self.base_pages.len() as u64);
        for (addr, page) in &self.base_pages {
            write_uvarint(&mut out, *addr);
            out.extend_from_slice(&page.0[..]);
        }

        write_uvarint(&mut out, self.events.len() as u64);
        for event in &self.events {
            event.encode(&mut out);
        }

        write_uvarint(&mut out, self.snapshots.len() as u64);
        for snap in &self.snapshots {
            encode_snapshot(&mut out, snap);
        }

        let checksum = fnv1a(&out);
        out.extend_from_slice(&checksum.to_le_bytes());
        out
    }

    /// Parse a `.ctrace` byte string.
    pub fn decode(bytes: &[u8]) -> Result<Trace, TraceError> {
        if bytes.len() < MAGIC.len() + 2 + 1 + 1 + 8 + 32 + REG_COUNT * 8 + 8 {
            return Err(TraceError::TooShort);
        }
        if bytes[..4] != MAGIC {
            return Err(TraceError::BadMagic);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != FORMAT_VERSION {
            return Err(TraceError::UnsupportedVersion(version));
        }
        let arch = bytes[6];
        if arch != ARCH_X86_64 {
            return Err(TraceError::UnsupportedArch(arch));
        }
        // bytes[7] is reserved flags.
        let entry = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed slice"));
        let mut image_hash = [0u8; 32];
        image_hash.copy_from_slice(&bytes[16..48]);

        let reg_base = 48;
        let body_base = reg_base + REG_COUNT * 8;
        let mut initial_regs = RegFile::new();
        for (i, reg) in RegId::ALL.iter().enumerate() {
            let off = reg_base + i * 8;
            let value = u64::from_le_bytes(
                bytes[off..off + 8]
                    .try_into()
                    .map_err(|_| TraceError::TooShort)?,
            );
            initial_regs.set(*reg, value);
        }

        let payload_end = bytes.len() - 8;
        let expected = u64::from_le_bytes(
            bytes[payload_end..]
                .try_into()
                .map_err(|_| TraceError::TooShort)?,
        );
        let actual = fnv1a(&bytes[..payload_end]);
        if expected != actual {
            return Err(TraceError::ChecksumMismatch { expected, actual });
        }

        let mut reader = Reader::new(&bytes[body_base..payload_end]);

        let page_count = reader.read_uvarint()?;
        if page_count.saturating_mul(PAGE_SIZE as u64) > reader.remaining() as u64 {
            return Err(TraceError::BadPageCount(page_count));
        }
        let mut base_pages = Vec::with_capacity(page_count as usize);
        for _ in 0..page_count {
            let addr = reader.read_uvarint()?;
            let raw = read_page(&mut reader)?;
            base_pages.push((addr, raw));
        }
        base_pages.sort_by_key(|(addr, _)| *addr);

        let event_count = reader.read_uvarint()?;
        let mut events = Vec::with_capacity(event_count.min(1 << 20) as usize);
        for _ in 0..event_count {
            events.push(Event::decode(&mut reader)?);
        }

        let snapshot_count = reader.read_uvarint()?;
        let mut snapshots = Vec::with_capacity(snapshot_count.min(1 << 20) as usize);
        for _ in 0..snapshot_count {
            snapshots.push(decode_snapshot(&mut reader)?);
        }

        Ok(Trace {
            entry,
            image_hash,
            initial_regs,
            base_pages,
            events,
            snapshots,
        })
    }
}

fn read_page(reader: &mut Reader<'_>) -> Result<Page, DecodeError> {
    let mut page = Page::zero();
    for byte in page.0.iter_mut() {
        *byte = reader.read_u8()?;
    }
    Ok(page)
}

fn encode_snapshot(out: &mut Vec<u8>, snap: &Snapshot) {
    write_uvarint(out, snap.frame.as_u64());
    for reg in RegId::ALL {
        out.extend_from_slice(&snap.regs.get(reg).to_le_bytes());
    }
    write_bytes(out, &snap.output);
    write_uvarint(out, snap.dirty_pages.len() as u64);
    for (addr, page) in &snap.dirty_pages {
        write_uvarint(out, *addr);
        out.extend_from_slice(&page.0[..]);
    }
}

fn decode_snapshot(reader: &mut Reader<'_>) -> Result<Snapshot, DecodeError> {
    let frame = Frame(reader.read_uvarint()?);
    let mut regs = crate::state::RegFile::new();
    for reg in RegId::ALL {
        let mut raw = [0u8; 8];
        for byte in raw.iter_mut() {
            *byte = reader.read_u8()?;
        }
        regs.set(reg, u64::from_le_bytes(raw));
    }
    let output = reader.read_bytes()?;
    let dirty_count = reader.read_uvarint()?;
    if dirty_count.saturating_mul(PAGE_SIZE as u64) > reader.remaining() as u64 {
        return Err(DecodeError::BadLength(dirty_count));
    }
    let mut dirty_pages = Vec::with_capacity(dirty_count as usize);
    for _ in 0..dirty_count {
        let addr = reader.read_uvarint()?;
        let page = read_page(reader)?;
        dirty_pages.push((addr, page));
    }
    Ok(Snapshot {
        frame,
        regs,
        output,
        dirty_pages,
    })
}

/// FNV-1a 64 over `bytes`.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Convenience: the frame count of a [`MachineState`] is not stored in the
/// state itself, so callers pass it explicitly when capturing.
pub fn capture_snapshot(frame: Frame, state: &MachineState) -> Snapshot {
    Snapshot::capture(frame, state)
}

/// Number of registers archived per snapshot (documented for tooling).
pub const SNAPSHOT_REG_COUNT: usize = REG_COUNT;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ExitKind, RegId};

    fn sample() -> Trace {
        let mut base = vec![(0x400000u64, Page::from_bytes(b"ELF segment"))];
        base.push((0x600000u64, Page::zero()));
        base.sort_by_key(|(a, _)| *a);

        let mut regs = RegFile::new();
        regs.set(RegId::Rip, 0x401000);
        regs.set(RegId::Rsp, 0x7fff_fffd_e000);
        let mut trace = Trace::new(0x401000, [7u8; 32], regs, base);
        trace.push(Event::Insn {
            addr: 0x401000,
            size: 5,
            bytes: vec![0xb8, 1, 0, 0, 0],
        });
        trace.push(Event::RegWrite {
            reg: RegId::Rax,
            value: 1,
        });
        trace.push(Event::SyscallEnter {
            nr: 1,
            name: "write".into(),
            args: [1, 0x400000, 3, 0, 0, 0],
        });
        trace.push(Event::Output {
            data: b"hi\n".to_vec(),
        });
        trace.push(Event::Exit {
            kind: ExitKind::Exit,
            value: 0,
        });
        trace
    }

    #[test]
    fn roundtrip_preserves_everything() {
        let trace = sample();
        let bytes = trace.encode();
        let decoded = Trace::decode(&bytes).expect("decode must succeed");
        assert_eq!(decoded.entry, trace.entry);
        assert_eq!(decoded.image_hash, trace.image_hash);
        assert_eq!(decoded.initial_regs, trace.initial_regs);
        assert_eq!(decoded.events, trace.events);
        assert_eq!(decoded.base_pages.len(), trace.base_pages.len());
        assert_eq!(decoded.len(), 5);
        assert_eq!(decoded.last_frame(), Frame(5));
    }

    #[test]
    fn roundtrip_with_snapshots() {
        let mut trace = sample();
        let mut state = MachineState::new(trace.base_map());
        state.apply_all(&trace.events);
        trace.snapshots.push(Snapshot::capture(Frame(5), &state));

        let decoded = Trace::decode(&trace.encode()).unwrap();
        assert_eq!(decoded.snapshots.len(), 1);
        assert_eq!(decoded.snapshots[0].frame, Frame(5));
        assert_eq!(decoded.snapshots[0].output, b"hi\n");
    }

    #[test]
    fn encoding_is_deterministic() {
        let trace = sample();
        assert_eq!(trace.encode(), trace.encode());
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = sample().encode();
        bytes[0] = b'X';
        assert!(matches!(Trace::decode(&bytes), Err(TraceError::BadMagic)));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bytes = sample().encode();
        bytes[4] = 0xff;
        bytes[5] = 0x00;
        assert!(matches!(
            Trace::decode(&bytes),
            Err(TraceError::UnsupportedVersion(0xff))
        ));
    }

    #[test]
    fn unsupported_arch_is_rejected() {
        let mut bytes = sample().encode();
        bytes[6] = 9;
        assert!(matches!(
            Trace::decode(&bytes),
            Err(TraceError::UnsupportedArch(9))
        ));
    }

    #[test]
    fn corruption_is_caught_by_checksum() {
        let mut bytes = sample().encode();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        assert!(matches!(
            Trace::decode(&bytes),
            Err(TraceError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn truncation_is_rejected() {
        let bytes = sample().encode();
        assert!(matches!(
            Trace::decode(&bytes[..20]),
            Err(TraceError::TooShort)
        ));
    }

    #[test]
    fn absurd_page_count_is_rejected() {
        // Hand-build a header claiming a huge page count, with a valid checksum.
        let mut body = Vec::new();
        body.extend_from_slice(&MAGIC);
        body.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        body.push(ARCH_X86_64);
        body.push(0);
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0u8; REG_COUNT * 8]);
        write_uvarint(&mut body, u64::MAX); // page count
        let checksum = fnv1a(&body);
        body.extend_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            Trace::decode(&body),
            Err(TraceError::BadPageCount(_))
        ));
    }
}
