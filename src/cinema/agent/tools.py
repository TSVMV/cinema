"""Controlled tools for querying a recording.

Each tool is a plain function ``(session, kwargs) -> dict``. Tools never
invent data: they read the recording through the engine and return exactly
what is in it. They are also the only way the agent can touch a trace.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cinema import _core as core
from cinema.agent.session import Session

ToolFn = Callable[[Session, dict[str, Any]], dict[str, Any]]


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    fn: ToolFn


def _num(value: Any, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer") from None


def _addr(value: Any, name: str) -> int:
    if isinstance(value, str):
        text = value.strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        try:
            return int(text, 16)
        except ValueError:
            pass
        try:
            return int(text, 10)
        except ValueError:
            raise ValueError(f"{name} must be an address") from None
    return _num(value, name)


def _bytes(value: Any, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError(f"{name} must be bytes")
    return bytes(value)


def _frame(session: Session, value: Any, name: str = "frame") -> int:
    frame = _num(value, name)
    if frame < 0 or frame > session.last_frame:
        raise ValueError(f"frame {frame} is out of range 0..{session.last_frame}")
    return frame


def _state(session: Session, frame: int | None = None) -> dict[str, Any]:
    st = session.state(frame)
    regs = st.regs()
    return {
        "frame": int(st.frame()),
        "rip": f"0x{int(st.rip()):x}",
        "regs": {name: f"0x{int(val):x}" for name, val in sorted(regs.items())},
        "dirty_pages": int(st.dirty_page_count()),
        "output": bytes(st.output()).decode("utf-8", "replace"),
    }


def set_input(session: Session, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Load a trace (a .ctrace file or a static ELF to record)."""
    source = kwargs.get("source")
    if not isinstance(source, (str, Path)):
        raise ValueError("source must be a file path")
    path = Path(source)
    image = path.read_bytes()
    if image[:4] == b"CTRC":
        session.trace = core.load_ctrace(image)
    elif image[:4] == b"\x7fELF":
        timeout = _num(kwargs.get("timeout_ms", 0), "timeout_ms")
        max_events = _num(kwargs.get("max_events", 0), "max_events")
        session.trace = core.record(image, timeout, max_events)
    else:
        raise ValueError("source is neither a .ctrace file nor an ELF image")
    session.cursor = 0
    trace = session.trace
    assert trace is not None
    summary = trace.summary()
    return {
        "loaded": True,
        "entry": f"0x{trace.entry():x}",
        "events": int(trace.len()),
        "last_frame": int(trace.frame_count()),
        "image_hash": trace.image_hash(),
        "exit_kind": str(summary.get("exit_kind", "none")),
        "exit_value": int(summary.get("exit_value", 0)),
    }


def run(session: Session, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Advance the cursor; return the state at a frame (default: last)."""
    at = kwargs.get("frame")
    if at is None:
        session.cursor = session.last_frame
    else:
        session.cursor = _frame(session, at)
    return _state(session)


def step_back(session: Session, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Move the cursor backwards; return the state at the new position."""
    count = max(1, _num(kwargs.get("count", 1), "count"))
    session.cursor = max(0, session.cursor - count)
    return _state(session)


def query_memory(session: Session, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Read guest memory; returns real bytes from the recording."""
    addr = _addr(kwargs.get("addr"), "addr")
    length = max(1, _num(kwargs.get("length", 16), "length"))
    at = kwargs.get("frame")
    if at is None:
        at = kwargs.get("at", session.cursor)
    frame = _frame(session, at)
    data = session.state(frame).read_memory(addr, length)
    return {
        "frame": frame,
        "addr": f"0x{addr:x}",
        "length": length,
        "hex": " ".join(f"{b:02x}" for b in data),
        "decoded": bytes(data).decode("utf-8", "replace"),
    }


def diff_register(session: Session, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Compare registers between two frames; only changed ones are reported."""
    a = _frame(session, _num(kwargs.get("a", 0), "a"), name="a")
    b = _frame(session, _num(kwargs.get("b", session.last_frame), "b"), name="b")
    ra = session.state(a).regs()
    rb = session.state(b).regs()
    changed: dict[str, dict[str, str]] = {}
    for name in sorted(set(ra) | set(rb)):
        va = ra.get(name, 0)
        vb = rb.get(name, 0)
        if va != vb:
            changed[name] = {
                "at": f"0x{int(va):x}",
                "at_other": f"0x{int(vb):x}",
            }
    return {"a": a, "b": b, "changed": changed}


def find_callsite(session: Session, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Find the first frame that executed a given instruction address.

    Walks the recorded event stream and returns the first frame whose
    executed instruction was at ``addr``. Real event data only.
    """
    if session.trace is None:
        raise ValueError("trace required")
    addr = _addr(kwargs.get("addr"), "addr")
    trace = session.trace
    for frame in range(1, int(trace.len()) + 1):
        event = trace.event_at(frame)
        if event is None:
            continue
        if str(event.get("kind", "")) == "insn" and _num(event.get("addr"), "addr") == addr:
            size = _num(event.get("size", 0), "size")
            raw = _bytes(event.get("bytes", b""), "bytes")
            proposed: dict[str, Any] = {
                "addr": f"0x{addr:x}",
                "frame": frame,
                "size": size,
                "bytes": " ".join(f"{b:02x}" for b in raw),
                "decoded": raw.decode("utf-8", "replace"),
            }
            return proposed
    return {"addr": f"0x{addr:x}", "frame": None, "size": 0, "bytes": "", "decoded": ""}


def explain_syscall(session: Session, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Explain the most recent syscall before a frame, from real events."""
    if session.trace is None:
        raise ValueError("trace required")
    at = kwargs.get("frame")
    if at is None:
        at = session.cursor
    frame = _frame(session, at)
    trace = session.trace
    for probe in range(frame, 0, -1):
        event = trace.event_at(probe)
        if event is None:
            continue
        kind = str(event.get("kind", ""))
        if kind != "syscall_enter":
            continue
        raw_args = event.get("args", [])
        args: list[int] = []
        if isinstance(raw_args, (list, tuple)):
            for v in raw_args:
                if isinstance(v, (int, str)):
                    with contextlib.suppress(ValueError):
                        args.append(int(v, 0) if isinstance(v, str) else v)
        return {
            "frame": probe,
            "kind": "syscall_enter",
            "name": str(event.get("name", "?")),
            "nr": _num(event.get("nr", -1), "nr"),
            "args": [f"0x{v:x}" for v in args],
        }
    return {"frame": frame, "kind": "none", "name": "-", "nr": -1, "args": []}


def _registry() -> list[ToolSpec]:
    return [
        ToolSpec(
            "set_input",
            "Load a recording: a .ctrace file or a static ELF to record.",
            {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Path to .ctrace or ELF."},
                    "timeout_ms": {"type": "integer", "default": 0},
                    "max_events": {"type": "integer", "default": 0},
                },
                "required": ["source"],
            },
            set_input,
        ),
        ToolSpec(
            "run",
            "Advance the cursor; return the state at a frame (default: last).",
            {
                "type": "object",
                "properties": {"frame": {"type": "integer", "default": None}},
            },
            run,
        ),
        ToolSpec(
            "step_back",
            "Move the cursor backwards and return the state there.",
            {
                "type": "object",
                "properties": {"count": {"type": "integer", "default": 1}},
            },
            step_back,
        ),
        ToolSpec(
            "query_memory",
            "Read guest memory at a frame; returns real bytes.",
            {
                "type": "object",
                "properties": {
                    "addr": {"type": ["string", "integer"]},
                    "length": {"type": "integer", "default": 16},
                    "frame": {"type": "integer", "default": None},
                },
                "required": ["addr"],
            },
            query_memory,
        ),
        ToolSpec(
            "diff_register",
            "Compare registers between two frames.",
            {
                "type": "object",
                "properties": {
                    "a": {"type": "integer", "default": 0},
                    "b": {"type": "integer", "default": None},
                },
            },
            diff_register,
        ),
        ToolSpec(
            "find_callsite",
            "Find the first frame that executed a given address.",
            {
                "type": "object",
                "properties": {"addr": {"type": ["string", "integer"]}},
                "required": ["addr"],
            },
            find_callsite,
        ),
        ToolSpec(
            "explain_syscall",
            "Explain the most recent syscall before a frame.",
            {
                "type": "object",
                "properties": {"frame": {"type": "integer", "default": None}},
            },
            explain_syscall,
        ),
    ]


INTERNAL_REGISTRY: list[ToolSpec] = _registry()

BY_NAME: dict[str, ToolFn] = {spec.name: spec.fn for spec in INTERNAL_REGISTRY}


def tool_names() -> list[str]:
    return [spec.name for spec in INTERNAL_REGISTRY]


def call_tool(session: Session, name: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one tool call. Raises KeyError for unknown tools."""
    fn = BY_NAME.get(name)
    if fn is None:
        raise KeyError(f"unknown tool: {name}")
    return fn(session, dict(kwargs or {}))
