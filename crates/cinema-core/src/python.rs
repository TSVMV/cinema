//! PyO3 bindings exposing the projector to Python.
//!
//! The Python surface is intentionally small: record or load a trace, then ask
//! it for frames. Everything a consumer needs to render (registers, memory,
//! output, event labels) is reachable from a `PyTrace`, so the TUI never has
//! to reach into Rust internals.

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::event::{Event, Frame, RegId};
use crate::replay::Replay;
use crate::session::{record_elf, RecordOptions};
use crate::state::{MachineState, Page};
use crate::trace::Trace;

/// Record the execution of an ELF image and return its trace.
#[pyfunction]
#[pyo3(signature = (image, timeout_ms=0, max_events=0))]
fn record(image: &[u8], timeout_ms: u64, max_events: usize) -> PyResult<PyTrace> {
    let opts = RecordOptions {
        timeout_ms,
        max_events,
    };
    let trace = record_elf(image, &opts).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyTrace::from_trace(trace))
}

/// Load a trace from `.ctrace` bytes.
#[pyfunction]
fn load_ctrace(data: &[u8]) -> PyResult<PyTrace> {
    let trace = Trace::decode(data).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyTrace::from_trace(trace))
}

fn to_err(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// A recorded trace.
#[pyclass(name = "Trace")]
pub struct PyTrace {
    trace: Trace,
    base: Arc<HashMap<u64, Page>>,
}

impl PyTrace {
    fn from_trace(trace: Trace) -> Self {
        let base = trace.base_map();
        PyTrace { trace, base }
    }

    fn replay(&self) -> Replay<'_> {
        Replay::with_base(&self.trace, Arc::clone(&self.base))
    }
}

#[pymethods]
impl PyTrace {
    /// Number of events (the final frame).
    fn len(&self) -> usize {
        self.trace.len()
    }

    /// True when no events were recorded.
    fn is_empty(&self) -> bool {
        self.trace.is_empty()
    }

    /// The final frame number.
    fn frame_count(&self) -> u64 {
        self.trace.last_frame().as_u64()
    }

    /// Program entry point.
    fn entry(&self) -> u64 {
        self.trace.entry
    }

    /// SHA-256 of the source image, as a hex string.
    fn image_hash(&self) -> String {
        self.trace
            .image_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Number of base pages in the initial image.
    fn base_page_count(&self) -> usize {
        self.trace.base_pages.len()
    }

    /// Frame numbers at which snapshots exist.
    fn snapshot_frames(&self) -> Vec<u64> {
        self.trace
            .snapshots
            .iter()
            .map(|s| s.frame.as_u64())
            .collect()
    }

    /// Registers at frame 0.
    fn initial_regs(&self) -> HashMap<String, u64> {
        reg_map(&self.trace.initial_regs)
    }

    /// Serialize back to `.ctrace` bytes.
    fn encode<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.trace.encode())
    }

    /// Rebuild the full state at `frame`.
    fn state_at(&self, frame: u64) -> PyState {
        let state = self.replay().state_at(Frame(frame));
        PyState { frame, state }
    }

    /// Read guest memory as seen at `frame`.
    fn read_memory(&self, frame: u64, addr: u64, len: usize) -> Vec<u8> {
        const MAX_READ: usize = 64 * 1024 * 1024;
        let len = len.min(MAX_READ);
        self.replay().state_at(Frame(frame)).mem.read(addr, len)
    }

    /// The event that produced the state at `frame`, as a dict.
    fn event_at<'py>(&self, py: Python<'py>, frame: u64) -> Option<Bound<'py, PyDict>> {
        self.replay()
            .event_at(Frame(frame))
            .map(|event| event_dict(py, frame, event))
    }

    /// Events in the half-open frame range `[from, to)`.
    ///
    /// `events(from, to)` returns the events at indices `[from, to)`; each one
    /// is the event that produced the state at `from + 1 ..= to`.
    fn events<'py>(&self, py: Python<'py>, from: u64, to: u64) -> PyResult<Bound<'py, PyList>> {
        let replay = self.replay();
        let slice = replay.events_between(Frame(from), Frame(to));
        let list = PyList::empty(py);
        for (offset, event) in slice.iter().enumerate() {
            let frame = from + offset as u64 + 1;
            list.append(event_dict(py, frame, event))?;
        }
        Ok(list)
    }

    /// A short summary for CLI display.
    fn summary<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("entry", self.trace.entry)?;
        dict.set_item("image_hash", self.image_hash())?;
        dict.set_item("events", self.trace.len())?;
        dict.set_item("snapshots", self.trace.snapshots.len())?;
        dict.set_item("base_pages", self.trace.base_pages.len())?;
        dict.set_item("final_frame", self.frame_count())?;

        let last = self.replay().state_at(self.trace.last_frame());
        dict.set_item("output", PyBytes::new(py, &last.output))?;
        dict.set_item("final_rip", last.regs.ip())?;

        let exit = self.trace.events.iter().rev().find_map(|e| match e {
            Event::Exit { kind, value } => Some((kind.name().to_string(), *value)),
            _ => None,
        });
        match exit {
            Some((kind, value)) => {
                dict.set_item("exit_kind", kind)?;
                dict.set_item("exit_value", value)?;
            }
            None => {
                dict.set_item("exit_kind", "none")?;
                dict.set_item("exit_value", 0u64)?;
            }
        }
        Ok(dict)
    }

    fn __len__(&self) -> usize {
        self.trace.len()
    }

    fn __repr__(&self) -> String {
        format!(
            "<Trace {} events, {} snapshots, entry=0x{:x}>",
            self.trace.len(),
            self.trace.snapshots.len(),
            self.trace.entry
        )
    }
}

/// A materialized machine state at one frame.
#[pyclass(name = "State")]
pub struct PyState {
    frame: u64,
    state: MachineState,
}

#[pymethods]
impl PyState {
    /// The frame this state belongs to.
    fn frame(&self) -> u64 {
        self.frame
    }

    /// The program counter.
    fn rip(&self) -> u64 {
        self.state.regs.ip()
    }

    /// One register by name, or `None` for an unknown name.
    fn reg(&self, name: &str) -> Option<u64> {
        RegId::ALL
            .iter()
            .find(|r| r.name() == name)
            .map(|r| self.state.regs.get(*r))
    }

    /// All tracked registers.
    fn regs(&self) -> HashMap<String, u64> {
        reg_map(&self.state.regs)
    }

    /// Captured output up to this frame.
    fn output<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.state.output)
    }

    /// Read guest memory at this frame.
    fn read_memory(&self, addr: u64, len: usize) -> Vec<u8> {
        self.state.mem.read(addr, len)
    }

    /// Number of pages modified relative to the base image.
    fn dirty_page_count(&self) -> usize {
        self.state.mem.dirty_count()
    }

    fn __repr__(&self) -> String {
        format!(
            "<State frame={} rip=0x{:x} output={} bytes>",
            self.frame,
            self.state.regs.ip(),
            self.state.output.len()
        )
    }
}

fn reg_map(regs: &crate::state::RegFile) -> HashMap<String, u64> {
    RegId::ALL
        .iter()
        .map(|reg| (reg.name().to_string(), regs.get(*reg)))
        .collect()
}

fn event_dict<'py>(py: Python<'py>, frame: u64, event: &Event) -> Bound<'py, PyDict> {
    let dict = PyDict::new(py);
    let _ = dict.set_item("frame", frame);
    let _ = dict.set_item("label", event.label());
    match event {
        Event::Insn { addr, size, bytes } => {
            let _ = dict.set_item("kind", "insn");
            let _ = dict.set_item("addr", addr);
            let _ = dict.set_item("size", size);
            let _ = dict.set_item("bytes", PyBytes::new(py, bytes));
        }
        Event::RegWrite { reg, value } => {
            let _ = dict.set_item("kind", "reg_write");
            let _ = dict.set_item("reg", reg.name());
            let _ = dict.set_item("value", value);
        }
        Event::MemWrite { addr, data } => {
            let _ = dict.set_item("kind", "mem_write");
            let _ = dict.set_item("addr", addr);
            let _ = dict.set_item("data", PyBytes::new(py, data));
        }
        Event::SyscallEnter { nr, name, args } => {
            let _ = dict.set_item("kind", "syscall_enter");
            let _ = dict.set_item("nr", nr);
            let _ = dict.set_item("name", name);
            let _ = dict.set_item("args", args.to_vec());
        }
        Event::SyscallExit { ret } => {
            let _ = dict.set_item("kind", "syscall_exit");
            let _ = dict.set_item("ret", ret);
        }
        Event::Output { data } => {
            let _ = dict.set_item("kind", "output");
            let _ = dict.set_item("data", PyBytes::new(py, data));
        }
        Event::Exit { kind, value } => {
            let _ = dict.set_item("kind", "exit");
            let _ = dict.set_item("exit_kind", kind.name());
            let _ = dict.set_item("value", value);
        }
    }
    dict
}

/// The `cinema._core` Python module.
#[pymodule(name = "_core")]
fn python_mod(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", crate::VERSION)?;
    m.add_function(wrap_pyfunction!(record, m)?)?;
    m.add_function(wrap_pyfunction!(load_ctrace, m)?)?;
    m.add_class::<PyTrace>()?;
    m.add_class::<PyState>()?;
    Ok(())
}

#[allow(dead_code)]
fn unused_to_err(e: impl std::fmt::Display) -> PyErr {
    to_err(e)
}
