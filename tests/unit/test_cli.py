"""End-to-end tests for the command line interface.

Every command is exercised against the same real recording, so the assertions
cover the whole chain: emulator -> event stream -> .ctrace -> console output.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from typer.testing import CliRunner, Result

from cinema.cli import app
from conftest import EXPECTED_OUTPUT, HELLO_STATIC

KINDS: frozenset[str] = frozenset(
    {"insn", "reg_write", "mem_write", "syscall_enter", "syscall_exit", "output", "exit"}
)

ANSI_ESCAPE: str = "\x1b["


def _invoke(*args: str) -> Result:
    return CliRunner().invoke(app, list(args))


def _payload(result: Any) -> Any:
    """Parse the JSON emitted by a command that ran successfully."""
    assert result.exit_code == 0, f"exit {result.exit_code}: {result.output}"
    return json.loads(result.output)


def test_help_lists_the_commands() -> None:
    result = _invoke("--help")
    assert result.exit_code == 0
    for name in ("record", "info", "trace", "frame"):
        assert name in result.output


def test_record_json_reports_the_real_run() -> None:
    result = _invoke("record", str(HELLO_STATIC), "--json")
    assert result.exit_code == 0, result.output
    payload = _payload(result)
    assert payload["exit_kind"] == "exit"
    assert payload["exit_value"] == 0
    assert payload["output"] == EXPECTED_OUTPUT.decode()
    assert payload["events"] > 0
    assert payload["base_pages"] > 0
    assert len(payload["image_hash"]) == 64


def test_record_writes_a_ctrace(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "hello.ctrace"
    result = _invoke("record", str(HELLO_STATIC), "--out", str(out))
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert out.stat().st_size > 0
    assert out.name in result.output


def test_record_honours_max_events() -> None:
    result = _invoke("record", str(HELLO_STATIC), "--max-events", "4", "--json")
    assert result.exit_code == 4
    payload = json.loads(result.output)
    assert payload["events"] >= 4
    assert payload["exit_kind"] == "stopped"


def test_record_missing_binary(tmp_path: Path) -> None:
    result = _invoke("record", str(tmp_path / "gone"), "--json")
    assert result.exit_code == 2
    assert "error" in result.output


def test_record_garbage_binary(tmp_path: Path) -> None:
    bad = tmp_path / "bad.elf"
    bad.write_bytes(b"MZ\x90\x90\x90")
    result = _invoke("record", str(bad), "--json")
    assert result.exit_code == 2
    assert "error" in result.output


def test_info_reads_back_the_recording(ctrace_path: Path) -> None:
    result = _invoke("info", str(ctrace_path), "--json")
    assert result.exit_code == 0
    assert _payload(result)["events"] > 0


def test_info_missing_file(missing_path: Path) -> None:
    result = _invoke("info", str(missing_path))
    assert result.exit_code == 2
    assert "error" in result.output


def test_info_corrupt_file(corrupt_path: Path) -> None:
    result = _invoke("info", str(corrupt_path))
    assert result.exit_code == 2
    assert "error" in result.output


def test_trace_lists_events(ctrace_path: Path) -> None:
    result = _invoke("trace", str(ctrace_path), "--limit", "100")
    assert result.exit_code == 0
    assert "insn" in result.output


def test_trace_json_range_is_exclusive(ctrace_path: Path) -> None:
    payload = _payload(_invoke("trace", str(ctrace_path), "--from", "1", "--to", "4", "--json"))
    assert isinstance(payload, list)
    assert [event["frame"] for event in payload] == [2, 3, 4]
    assert all(event["kind"] in KINDS for event in payload)


def test_trace_only_filters_the_requested_kind(ctrace_path: Path) -> None:
    payload = _payload(
        _invoke("trace", str(ctrace_path), "--from", "0", "--to", "40", "--only", "reg", "--json")
    )
    assert payload
    assert all(event["kind"] == "reg_write" for event in payload)


def test_trace_reports_an_empty_range(ctrace_path: Path) -> None:
    result = _invoke("trace", str(ctrace_path), "--from", "5", "--to", "3")
    assert result.exit_code == 0
    assert "no events" in result.output


def test_trace_reports_when_no_kind_matches(ctrace_path: Path) -> None:
    result = _invoke("trace", str(ctrace_path), "--only", "output", "--to", "2")
    assert result.exit_code == 0
    assert "no events" in result.output


def test_frame_reconstructs_the_initial_state(ctrace_path: Path) -> None:
    result = _invoke("frame", str(ctrace_path), "0")
    assert result.exit_code == 0
    assert "rip" in result.output


def test_frame_json_with_memory_window(ctrace_path: Path) -> None:
    payload = _payload(
        _invoke("frame", str(ctrace_path), "0", "--mem", "0x401000:16", "--json")
    )
    assert payload["frame"] == 0
    assert isinstance(payload["regs"], Mapping)
    assert payload["event"] is None
    window = payload["memory"]["0x401000"]
    assert window["addr"] == 0x401000
    assert len(window["data"].split()) == 16


def test_frame_reports_the_producing_event(ctrace_path: Path) -> None:
    payload = _payload(_invoke("frame", str(ctrace_path), "1", "--json"))
    assert payload["event"] is not None
    assert payload["event"]["frame"] == 1


def test_frame_out_of_range(ctrace_path: Path) -> None:
    result = _invoke("frame", str(ctrace_path), "999999999")
    assert result.exit_code == 2
    assert "out of range" in result.output


def test_frame_bad_memory_spec(ctrace_path: Path) -> None:
    for spec in ("not-an-addr", "0x1000:0", "0x1000:zz"):
        result = _invoke("frame", str(ctrace_path), "0", "--mem", spec)
        assert result.exit_code == 2, spec
        assert "bad --mem" in result.output


def test_no_color_emits_plain_text(ctrace_path: Path) -> None:
    result = _invoke("info", str(ctrace_path), "--no-color")
    assert result.exit_code == 0
    assert ANSI_ESCAPE not in result.output


def test_record_prints_the_summary_table() -> None:
    result = _invoke("record", str(HELLO_STATIC))
    assert result.exit_code == 0
    assert "recording" in result.output
    assert "exit(0)" in result.output
    assert "hello, winVpwn" in result.output


def test_trace_full_range_covers_every_kind(ctrace_path: Path) -> None:
    payload = _payload(_invoke("trace", str(ctrace_path), "--from", "0", "--json"))
    assert isinstance(payload, list)
    kinds = {event["kind"] for event in payload}
    assert kinds <= KINDS
    assert {"insn", "reg_write", "syscall_enter", "syscall_exit", "output", "exit"} <= kinds


def test_trace_shows_every_detail_style(ctrace_path: Path) -> None:
    payload = _payload(_invoke("trace", str(ctrace_path), "--from", "0", "--json"))
    assert isinstance(payload, list)
    by_kind = {event["kind"]: event for event in payload}
    insn = by_kind["insn"]
    assert "bytes" in insn and "addr" in insn and "size" in insn
    enter = by_kind["syscall_enter"]
    assert enter["name"] in {"write", "exit"}
    assert "ret" in by_kind["syscall_exit"]
    assert "data" in by_kind["output"]
    assert by_kind["exit"]["exit_kind"] == "exit"


def test_frame_at_the_exit_event(ctrace_path: Path) -> None:
    from cinema import _core as core

    last = core.load_ctrace(ctrace_path.read_bytes()).frame_count()
    payload = _payload(_invoke("frame", str(ctrace_path), str(last), "--json"))
    event = payload["event"]
    assert isinstance(event, dict)
    assert event["kind"] == "exit"
    assert event["exit_kind"] == "exit"


def test_info_plain_output(ctrace_path: Path) -> None:
    result = _invoke("info", str(ctrace_path))
    assert result.exit_code == 0
    assert "entry" in result.output
    assert "events" in result.output
    assert "image hash" in result.output
