"""Tests for the static HTML exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner, Result

from cinema import _core as core
from cinema._core import Trace
from cinema.cli import app
from cinema.export import _build_payload, export_trace
from conftest import EXPECTED_OUTPUT

HTML = '<!doctype html>'


def _invoke(*args: str) -> Result:
    return CliRunner().invoke(app, list(args))


def _extract_data(html: str) -> dict[str, Any]:
    marker = '<script id="trace-data" type="application/json">'
    start = html.index(marker) + len(marker)
    end = html.index("</script>", start)
    data = json.loads(html[start:end])
    assert isinstance(data, dict)
    return data


def test_payload_shape(ctrace_path: Path) -> None:
    trace = core.load_ctrace(ctrace_path.read_bytes())
    payload = _build_payload(trace, [(0x401000, 16)])
    assert payload["meta"]["events"] == trace.len()
    assert payload["meta"]["entry"] == "0x401000"
    assert payload["meta"]["exit_kind"] == "exit"
    assert len(payload["reg_names"]) == 18
    assert payload["windows"] == [{"addr": 0x401000, "len": 16}]
    frames = payload["frames"]
    assert len(frames) == trace.len() + 1
    assert frames[0]["f"] == 0
    assert frames[0]["event"] is None
    assert frames[0]["rip"] == payload["meta"]["entry"]
    assert len(frames[0]["regs"]) == 18
    assert "mem" in frames[0]
    last = frames[-1]
    assert last["event"] is not None
    assert last["event"]["kind"] == "exit"
    assert payload["strings"][last["out"]] == EXPECTED_OUTPUT.decode("latin-1")


def test_frames_are_a_prefix_chain(trace: Trace) -> None:
    payload = _build_payload(trace, [])
    frames = payload["frames"]
    outputs = [payload["strings"][f["out"]] for f in frames]
    for earlier, later in zip(outputs, outputs[1:], strict=False):
        assert later.startswith(earlier)


def test_export_writes_self_contained_html(ctrace_path: Path, tmp_path: Path) -> None:
    trace = core.load_ctrace(ctrace_path.read_bytes())
    out = tmp_path / "report.html"
    export_trace(trace, out)
    html = out.read_text(encoding="utf-8")
    assert html.startswith(HTML)
    assert "cinema — replay report" in html
    assert "trace-data" in html
    assert "0x401000" in html
    assert "hello, winVpwn" in html
    assert "exit" in html
    assert "http://" not in html and "https://" not in html


def test_export_with_memory_window(ctrace_path: Path, tmp_path: Path) -> None:
    trace = core.load_ctrace(ctrace_path.read_bytes())
    out = tmp_path / "with-mem.html"
    export_trace(trace, out, [(0x401000, 16)])
    payload = _extract_data(out.read_text(encoding="utf-8"))
    assert payload["windows"][0]["addr"] == 0x401000
    assert payload["frames"][0]["mem"][0] != ""


def test_export_embeds_real_register_values(ctrace_path: Path, tmp_path: Path) -> None:
    trace = core.load_ctrace(ctrace_path.read_bytes())
    out = tmp_path / "regs.html"
    export_trace(trace, out)
    payload = _extract_data(out.read_text(encoding="utf-8"))
    entry_index = payload["reg_names"].index("rip")
    assert payload["frames"][0]["regs"][entry_index] == "0x401000"


def test_export_cli_writes_report(ctrace_path: Path, tmp_path: Path) -> None:
    out = tmp_path / "nested" / "report.html"
    result = _invoke("export", str(ctrace_path), str(out))
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert "exported" in result.output


def test_export_cli_with_mem(ctrace_path: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    result = _invoke("export", str(ctrace_path), str(out), "--mem", "0x401000:8")
    assert result.exit_code == 0, result.output
    assert "0x401000" in out.read_text(encoding="utf-8")


def test_export_cli_bad_mem(ctrace_path: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    result = _invoke("export", str(ctrace_path), str(out), "--mem", "not-an-addr")
    assert result.exit_code == 2
    assert "bad --mem" in result.output


def test_export_cli_missing_trace(tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    result = _invoke("export", str(tmp_path / "absent.ctrace"), str(out))
    assert result.exit_code == 2
    assert "error" in result.output
