//! Binary encoding for [`Event`]s.
//!
//! The format is deliberately simple and strictly validated: an unknown tag, a
//! truncated payload or an out-of-range enum value is a hard error, never a
//! silent default. Traces come from untrusted files; decoding must not panic.

use std::fmt;

use super::{Event, ExitKind, RegId};

/// Stable event tags. Never renumber.
mod tag {
    pub const INSN: u8 = 1;
    pub const REG_WRITE: u8 = 2;
    pub const MEM_WRITE: u8 = 3;
    pub const SYSCALL_ENTER: u8 = 4;
    pub const SYSCALL_EXIT: u8 = 5;
    pub const OUTPUT: u8 = 6;
    pub const EXIT: u8 = 7;
}

/// An error while decoding a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended in the middle of a value.
    Truncated,
    /// A tag byte does not belong to any event.
    UnknownTag(u8),
    /// A register id is out of range.
    BadRegId(u8),
    /// An exit kind is out of range.
    BadExitKind(u8),
    /// A length field exceeds what the remaining input can hold.
    BadLength(u64),
    /// A string payload is valid UTF-8-wise but the bytes are not.
    BadString,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "truncated trace payload"),
            DecodeError::UnknownTag(t) => write!(f, "unknown event tag {t}"),
            DecodeError::BadRegId(r) => write!(f, "invalid register id {r}"),
            DecodeError::BadExitKind(k) => write!(f, "invalid exit kind {k}"),
            DecodeError::BadLength(n) => write!(f, "implausible length field {n}"),
            DecodeError::BadString => write!(f, "invalid UTF-8 in string payload"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Append `value` as an unsigned LEB128 varint.
pub fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Append `value` as a zig-zag encoded signed varint (small magnitudes stay
/// small on disk).
pub fn write_ivarint(out: &mut Vec<u8>, value: i64) {
    let zz = ((value << 1) ^ (value >> 63)) as u64;
    write_uvarint(out, zz);
}

/// Append `bytes` prefixed with their length.
pub fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_uvarint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Append a string as length-prefixed UTF-8.
pub fn write_str(out: &mut Vec<u8>, s: &str) {
    write_bytes(out, s.as_bytes());
}

/// A bounds-checked cursor over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Remaining byte count.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Current absolute offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let byte = *self.buf.get(self.pos).ok_or(DecodeError::Truncated)?;
        self.pos += 1;
        Ok(byte)
    }

    pub fn read_uvarint(&mut self) -> Result<u64, DecodeError> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8()?;
            if shift >= 64 {
                return Err(DecodeError::BadLength(u64::MAX));
            }
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    pub fn read_ivarint(&mut self) -> Result<i64, DecodeError> {
        let zz = self.read_uvarint()?;
        Ok(((zz >> 1) as i64) ^ -((zz & 1) as i64))
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.read_uvarint()?;
        let len = usize::try_from(len).map_err(|_| DecodeError::BadLength(len))?;
        if len > self.remaining() {
            return Err(DecodeError::BadLength(len as u64));
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    pub fn read_str(&mut self) -> Result<String, DecodeError> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|_| DecodeError::BadString)
    }
}

impl Event {
    /// Append this event to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Event::Insn { addr, size, bytes } => {
                out.push(tag::INSN);
                write_uvarint(out, *addr);
                out.push(*size);
                write_bytes(out, bytes);
            }
            Event::RegWrite { reg, value } => {
                out.push(tag::REG_WRITE);
                out.push(reg.as_u8());
                write_uvarint(out, *value);
            }
            Event::MemWrite { addr, data } => {
                out.push(tag::MEM_WRITE);
                write_uvarint(out, *addr);
                write_bytes(out, data);
            }
            Event::SyscallEnter { nr, name, args } => {
                out.push(tag::SYSCALL_ENTER);
                write_ivarint(out, *nr);
                write_str(out, name);
                for arg in args {
                    write_uvarint(out, *arg);
                }
            }
            Event::SyscallExit { ret } => {
                out.push(tag::SYSCALL_EXIT);
                write_ivarint(out, *ret);
            }
            Event::Output { data } => {
                out.push(tag::OUTPUT);
                write_bytes(out, data);
            }
            Event::Exit { kind, value } => {
                out.push(tag::EXIT);
                out.push(*kind as u8);
                write_uvarint(out, *value);
            }
        }
    }

    /// Decode one event from `reader`.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Event, DecodeError> {
        let tag = reader.read_u8()?;
        match tag {
            tag::INSN => {
                let addr = reader.read_uvarint()?;
                let size = reader.read_u8()?;
                let bytes = reader.read_bytes()?;
                Ok(Event::Insn { addr, size, bytes })
            }
            tag::REG_WRITE => {
                let raw = reader.read_u8()?;
                let reg = RegId::from_u8(raw).ok_or(DecodeError::BadRegId(raw))?;
                let value = reader.read_uvarint()?;
                Ok(Event::RegWrite { reg, value })
            }
            tag::MEM_WRITE => {
                let addr = reader.read_uvarint()?;
                let data = reader.read_bytes()?;
                Ok(Event::MemWrite { addr, data })
            }
            tag::SYSCALL_ENTER => {
                let nr = reader.read_ivarint()?;
                let name = reader.read_str()?;
                let mut args = [0u64; 6];
                for slot in &mut args {
                    *slot = reader.read_uvarint()?;
                }
                Ok(Event::SyscallEnter { nr, name, args })
            }
            tag::SYSCALL_EXIT => {
                let ret = reader.read_ivarint()?;
                Ok(Event::SyscallExit { ret })
            }
            tag::OUTPUT => {
                let data = reader.read_bytes()?;
                Ok(Event::Output { data })
            }
            tag::EXIT => {
                let raw = reader.read_u8()?;
                let kind = ExitKind::from_u8(raw).ok_or(DecodeError::BadExitKind(raw))?;
                let value = reader.read_uvarint()?;
                Ok(Event::Exit { kind, value })
            }
            other => Err(DecodeError::UnknownTag(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(event: Event) {
        let mut buf = Vec::new();
        event.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = Event::decode(&mut reader).expect("decode must succeed");
        assert_eq!(decoded, event);
        assert_eq!(
            reader.remaining(),
            0,
            "encoder must not leave trailing bytes"
        );
    }

    #[test]
    fn all_event_kinds_roundtrip() {
        roundtrip(Event::Insn {
            addr: 0x401000,
            size: 5,
            bytes: vec![0x48, 0xc7, 0xc0, 0x01, 0x00],
        });
        roundtrip(Event::RegWrite {
            reg: RegId::Rax,
            value: 0xdead_beef_cafe_0000,
        });
        roundtrip(Event::MemWrite {
            addr: 0x7fff_fffd_e000,
            data: b"hello, winVpwn\n".to_vec(),
        });
        roundtrip(Event::SyscallEnter {
            nr: 1,
            name: "write".into(),
            args: [1, 0x400000, 15, 0, 0, 0],
        });
        roundtrip(Event::SyscallExit { ret: -38 });
        roundtrip(Event::Output {
            data: vec![0x41, 0x42],
        });
        roundtrip(Event::Exit {
            kind: ExitKind::Falloff,
            value: 0x0,
        });
    }

    #[test]
    fn negative_syscall_numbers_stay_compact() {
        let mut buf = Vec::new();
        write_ivarint(&mut buf, -38);
        assert_eq!(buf.len(), 1, "zig-zag keeps -38 in one byte");
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_ivarint().unwrap(), -38);
    }

    #[test]
    fn truncated_payload_errors() {
        let mut buf = Vec::new();
        Event::MemWrite {
            addr: 0x1000,
            data: vec![1, 2, 3, 4],
        }
        .encode(&mut buf);
        buf.truncate(buf.len() - 2);
        let mut reader = Reader::new(&buf);
        assert!(matches!(
            Event::decode(&mut reader),
            Err(DecodeError::Truncated | DecodeError::BadLength(_))
        ));
    }

    #[test]
    fn unknown_tag_errors() {
        let buf = [0x7f];
        let mut reader = Reader::new(&buf);
        assert_eq!(
            Event::decode(&mut reader),
            Err(DecodeError::UnknownTag(0x7f))
        );
    }

    #[test]
    fn bad_register_id_errors() {
        let buf = [tag::REG_WRITE, 200, 0];
        let mut reader = Reader::new(&buf);
        assert_eq!(Event::decode(&mut reader), Err(DecodeError::BadRegId(200)));
    }

    #[test]
    fn absurd_length_errors_without_allocation() {
        // A length of u64::MAX must be rejected before any allocation attempt.
        let buf = [
            tag::OUTPUT,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0x01,
        ];
        let mut reader = Reader::new(&buf);
        assert!(matches!(
            Event::decode(&mut reader),
            Err(DecodeError::BadLength(_))
        ));
    }
}
