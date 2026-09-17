"""Invariants of a recorded trace and the replay it supports.

The assertions are phrased as properties that must hold for any recording, so
they keep catching regressions even if the fixture binary changes.
"""

from __future__ import annotations

import pytest

from cinema import _core as core
from cinema._core import State, Trace

EXPECTED_OUTPUT: bytes = b"hello, winVpwn\n"
EXPECTED_ENTRY: int = 0x401000

REG_NAMES: frozenset[str] = frozenset(
    {
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "rip",
        "rflags",
    }
)

EVENT_KINDS: frozenset[str] = frozenset(
    {"insn", "reg_write", "mem_write", "syscall_enter", "syscall_exit", "output", "exit"}
)


def _event(trace: Trace, frame: int) -> dict[str, object]:
    event = trace.event_at(frame)
    assert event is not None, f"frame {frame} must have a producing event"
    return event


def _num(event: dict[str, object], key: str) -> int:
    value = event[key]
    assert isinstance(value, int), f"{key} expected int, got {type(value).__name__}"
    return value


def _bytes(event: dict[str, object], key: str) -> bytes:
    value = event[key]
    assert isinstance(value, (bytes, bytearray)), f"{key} expected bytes"
    return bytes(value)


def _all_events(trace: Trace) -> list[dict[str, object]]:
    return trace.events(0, trace.frame_count())


# ---------------------------------------------------------------- shape


def test_recording_shape(trace: Trace) -> None:
    assert trace.len() > 0
    assert not trace.is_empty()
    assert trace.frame_count() == trace.len()
    assert trace.entry() == EXPECTED_ENTRY
    assert trace.base_page_count() > 0
    assert len(trace.image_hash()) == 64


def test_events_cover_every_frame_once(trace: Trace) -> None:
    events = _all_events(trace)
    assert len(events) == trace.len()
    assert [event["frame"] for event in events] == list(range(1, trace.len() + 1))
    assert all(event["kind"] in EVENT_KINDS for event in events)
    assert all(event["label"] for event in events)


def test_final_output_and_exit(trace: Trace) -> None:
    final = trace.state_at(trace.frame_count())
    assert final.output() == EXPECTED_OUTPUT

    last = _event(trace, trace.len())
    assert last["kind"] == "exit"
    assert last["exit_kind"] == "exit"
    assert _num(last, "value") == 0


# ------------------------------------------------------- replay semantics


def test_frame_zero_is_the_initial_state(trace: Trace) -> None:
    state = trace.state_at(0)
    assert state.frame() == 0
    assert state.rip() == trace.entry()
    assert state.output() == b""
    assert trace.event_at(0) is None


def test_event_at_is_the_producing_event(trace: Trace) -> None:
    events = _all_events(trace)
    for index, event in enumerate(events):
        assert _event(trace, index + 1)["frame"] == index + 1
        assert _event(trace, index + 1)["kind"] == event["kind"]


def test_events_and_event_at_agree(trace: Trace) -> None:
    for frame in (1, trace.len() // 2, trace.len()):
        assert trace.events(0, frame)[-1] == trace.event_at(frame)


def test_insn_advances_rip(trace: Trace) -> None:
    events = _all_events(trace)
    for index, event in enumerate(events):
        if event["kind"] != "insn":
            continue
        addr = _num(event, "addr")
        size = _num(event, "size")
        code = _bytes(event, "bytes")
        assert 0 < size <= len(code)
        assert trace.state_at(index + 1).rip() == addr + size


def test_reg_write_is_visible_at_its_own_frame(trace: Trace) -> None:
    events = _all_events(trace)
    seen: set[str] = set()
    for index, event in enumerate(events):
        if event["kind"] != "reg_write":
            continue
        name = str(event["reg"])
        value = _num(event, "value")
        assert name in REG_NAMES
        assert trace.state_at(index + 1).reg(name) == value
        assert trace.state_at(index + 1).regs()[name] == value
        seen.add(name)
    assert "rip" in seen


def test_output_grows_by_prefixes_only(trace: Trace) -> None:
    previous = b""
    for frame in range(0, trace.len() + 1):
        current = trace.state_at(frame).output()
        assert current.startswith(previous)
        if frame and _event(trace, frame)["kind"] != "output":
            assert current == previous
        previous = current


def test_dirty_pages_are_monotone(trace: Trace) -> None:
    previous = 0
    for frame in range(0, trace.len() + 1):
        count = trace.state_at(frame).dirty_page_count()
        assert count >= previous
        previous = count


def test_syscall_pairing(trace: Trace) -> None:
    """A syscall that exits the guest has no exit event; every other one pairs."""
    depth = 0
    for event in _all_events(trace):
        if event["kind"] == "syscall_enter":
            depth += 1
            assert _num(event, "nr") >= 0
            assert str(event["name"])
            assert isinstance(event["args"], list)
        elif event["kind"] == "syscall_exit":
            assert depth > 0, "syscall_exit before syscall_enter"
            depth -= 1
            assert _num(event, "ret") >= 0
        elif event["kind"] == "exit":
            assert depth in (0, 1), "only the terminating syscall may be open"
    assert depth in (0, 1)


def test_snapshot_frames_are_sorted_and_inside(trace: Trace) -> None:
    frames = trace.snapshot_frames()
    assert frames == sorted(frames)
    assert all(0 <= frame <= trace.len() for frame in frames)


# --------------------------------------------------------------- memory


def test_state_and_trace_memory_agree(trace: Trace) -> None:
    frame = max(1, trace.len() // 2)
    state = trace.state_at(frame)
    addr = 0x401000
    assert state.read_memory(addr, 16) == trace.read_memory(frame, addr, 16)


def test_state_reports_known_registers_only(trace: Trace) -> None:
    state = trace.state_at(trace.len())
    assert set(state.regs()) == REG_NAMES
    assert state.reg("rip") == state.rip()
    assert state.reg("no_such_reg") is None


# ------------------------------------------------------------------ io


def test_initial_regs_match_frame_zero(trace: Trace) -> None:
    assert trace.initial_regs() == trace.state_at(0).regs()


def test_summary_matches_the_replay(trace: Trace) -> None:
    summary = trace.summary()
    assert summary["entry"] == trace.entry()
    assert summary["image_hash"] == trace.image_hash()
    assert summary["events"] == trace.len()
    assert summary["base_pages"] == trace.base_page_count()
    assert summary["final_frame"] == trace.len()
    assert summary["snapshots"] == len(trace.snapshot_frames())
    assert summary["exit_kind"] == "exit"
    assert summary["exit_value"] == 0

    final = trace.state_at(trace.len())
    assert summary["final_rip"] == final.rip()
    output = summary["output"]
    assert isinstance(output, (bytes, bytearray))
    assert bytes(output) == EXPECTED_OUTPUT


def test_roundtrip_preserves_the_recording(trace: Trace) -> None:
    again = core.load_ctrace(trace.encode())
    assert again.len() == trace.len()
    assert again.entry() == trace.entry()
    assert again.image_hash() == trace.image_hash()
    assert again.base_page_count() == trace.base_page_count()
    assert again.snapshot_frames() == trace.snapshot_frames()
    assert again.initial_regs() == trace.initial_regs()

    for frame in (0, trace.len() // 2, trace.len()):
        a = trace.state_at(frame)
        b = again.state_at(frame)
        assert a.rip() == b.rip()
        assert a.output() == b.output()
        assert a.dirty_page_count() == b.dirty_page_count()


def test_load_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        core.load_ctrace(b"not a trace at all")
    with pytest.raises(ValueError):
        core.load_ctrace(b"CTRC\x00\x01\x00")
    with pytest.raises(ValueError):
        core.load_ctrace(b"")


def test_record_rejects_garbage(hello_bytes: bytes) -> None:
    with pytest.raises(ValueError):
        core.record(b"MZ\x90\x90")
    with pytest.raises(ValueError):
        core.record(b"")


def test_max_events_is_a_soft_budget(hello_bytes: bytes) -> None:
    for budget in (1, 4, 12):
        trace = core.record(hello_bytes, 0, budget)
        assert trace.len() >= budget
        last = _event(trace, trace.len())
        assert last["kind"] == "exit"
        assert last["exit_kind"] == "stopped"
    assert core.record(hello_bytes, 0, 1).state_at(0).rip() == core.record(
        hello_bytes
    ).entry()


def test_state_is_clamped_to_the_last_frame(trace: Trace) -> None:
    assert trace.state_at(trace.len() + 1000).rip() == trace.state_at(trace.len()).rip()
    assert (
        trace.state_at(trace.len() + 1000).output()
        == trace.state_at(trace.len()).output()
    )


def test_reprs_are_stable(trace: Trace) -> None:
    assert "<Trace" in repr(trace)
    assert "events" in repr(trace)
    state: State = trace.state_at(1)
    assert "<State" in repr(state)
    assert "frame=1" in repr(state)
