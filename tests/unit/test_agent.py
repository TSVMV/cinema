"""End-to-end tests for the controlled tool layer.

A scripted (fake) decider decides *which* tool to call; the tool layer then
executes against a real recording and returns real data. Assertions check
known behaviour of the ``hello_static`` fixture, so every value verified here
comes from an actual emulated run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cinema import _core as core
from cinema._core import Trace
from cinema.agent.decider import Conversation, ScriptedDecider, ToolCall
from cinema.agent.loop import run_agent
from cinema.agent.session import Session
from cinema.agent.tools import call_tool
from conftest import EXPECTED_OUTPUT, HELLO_STATIC

EXPECTED_ENTRY: int = 0x401000
WRITE_BUF: str = "0x402000"
WRITE_LEN: int = 15


def make_session(trace: Trace) -> Session:
    return Session(trace=trace)


def test_scripted_decider_emits_in_order() -> None:
    decider = ScriptedDecider([ToolCall("run", {}), None])
    session = make_session(core.record(HELLO_STATIC.read_bytes()))
    calls = decider.next_call(session, Conversation([]))
    assert calls is not None and calls.name == "run"
    assert decider.next_call(session, Conversation([])) is None


def test_unknown_tool_is_captured_as_a_failed_turn() -> None:
    session = make_session(core.record(HELLO_STATIC.read_bytes()))
    turns = run_agent(session, ScriptedDecider([ToolCall("ls", {}), None]))
    assert len(turns) == 1
    assert turns[0].ok is False
    assert "unknown tool" in (turns[0].error or "")


def test_set_input_records_elf(trace: Trace) -> None:
    session = Session()
    result = call_tool(session, "set_input", {"source": str(HELLO_STATIC)})
    assert result["loaded"] is True
    assert result["entry"] == f"0x{EXPECTED_ENTRY:x}"
    assert result["events"] == int(trace.len())
    assert result["exit_kind"] in ("exit", "stopped")
    assert session.trace is not None


def test_set_input_rejects_fake_file(tmp_path: Path) -> None:
    bogus = tmp_path / "not_a_trace"
    bogus.write_bytes(b"adsf")
    session = Session()
    with pytest.raises(ValueError):
        call_tool(session, "set_input", {"source": str(bogus)})


def test_run_reports_real_final_state(trace: Trace) -> None:
    session = make_session(trace)
    result = call_tool(session, "run", {})
    assert result["frame"] == int(trace.frame_count())
    assert result["output"].endswith(EXPECTED_OUTPUT.decode("utf-8", "replace"))


def test_step_back_moves_cursor_to_a_real_earlier_frame(trace: Trace) -> None:
    session = make_session(trace)
    call_tool(session, "run", {})
    result = call_tool(session, "step_back", {"count": 10})
    middle = int(trace.frame_count()) - 10
    assert result["frame"] == middle
    call_tool(session, "step_back", {"count": 100000})
    zero = call_tool(session, "step_back", {"count": 1})
    assert zero["frame"] == 0


def test_query_memory_returns_real_program_data(trace: Trace) -> None:
    session = make_session(trace)
    result = call_tool(session, "query_memory", {"addr": WRITE_BUF, "length": WRITE_LEN})
    assert result["addr"] == WRITE_BUF
    assert len(result["hex"].split(" ")) == WRITE_LEN
    assert result["decoded"] == EXPECTED_OUTPUT.decode("utf-8", "replace")


def test_query_memory_accepts_hex_string() -> None:
    trace = core.record(HELLO_STATIC.read_bytes())
    session = make_session(trace)
    result = call_tool(session, "query_memory", {"addr": "0x402000", "length": 4})
    assert result["hex"] == "68 65 6c 6c"


def test_diff_register_reports_only_changed(trace: Trace) -> None:
    session = make_session(trace)
    result = call_tool(session, "diff_register", {"a": 0, "b": int(trace.frame_count())})
    assert "rip" in result["changed"]
    assert result["changed"]["rip"]["at"] != result["changed"]["rip"]["at_other"]


def test_find_callsite_finds_entry_instruction(trace: Trace) -> None:
    session = make_session(trace)
    result = call_tool(session, "find_callsite", {"addr": f"0x{EXPECTED_ENTRY:x}"})
    assert result["frame"] is not None and result["frame"] >= 1
    assert result["addr"] == f"0x{EXPECTED_ENTRY:x}"


def test_find_callsite_missing_address(trace: Trace) -> None:
    session = make_session(trace)
    result = call_tool(session, "find_callsite", {"addr": "0xdeadbeef"})
    assert result["frame"] is None


def test_explain_syscall_reports_real_call(trace: Trace) -> None:
    session = make_session(trace)
    result = call_tool(session, "explain_syscall", {"frame": int(trace.len())})
    assert result["kind"] == "syscall_enter"
    assert result["nr"] in (1, 60, 231)
    assert all(arg.startswith("0x") for arg in result["args"])


def test_run_agent_executes_scripted_plan_for_real(trace: Trace) -> None:
    session = make_session(trace)
    script = ScriptedDecider(
        [
            ToolCall("run", {}),
            ToolCall("query_memory", {"addr": WRITE_BUF, "length": WRITE_LEN}),
            ToolCall("step_back", {"count": 5}),
            None,
        ]
    )
    turns = run_agent(session, script)
    assert [t.call.name for t in turns] == ["run", "query_memory", "step_back"]
    assert all(t.ok for t in turns)
    assert turns[1].result["decoded"] == EXPECTED_OUTPUT.decode("utf-8", "replace")


def test_run_agent_without_loaded_trace_fails_honestly() -> None:
    session = Session()
    script = ScriptedDecider([ToolCall("run", {}), None])
    turns = run_agent(session, script)
    assert len(turns) == 1
    assert turns[0].ok is False
