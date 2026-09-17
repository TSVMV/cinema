"""Pilot-driven tests for the Textual TUI.

The app is driven headless via Textual's pilot; every assertion reads widget
content that was rendered from the real recording.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from textual.widgets import DataTable, Input, Static

from cinema import _core as core
from cinema._core import Trace
from cinema.tui import CinemaApp

EXPECTED_OUTPUT: bytes = b"hello, winVpwn\n"


def _run(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.run(coro)


def _load(ctrace_path: Path) -> Trace:
    return core.load_ctrace(ctrace_path.read_bytes())


def _text(widget: Static) -> str:
    return str(widget.renderable)


def _render_table(widget: Static) -> str:
    table = widget.renderable
    assert isinstance(table, Table)
    console = Console(width=64, color_system=None, record=True)
    console.print(table)
    return console.export_text()


def test_mounts_at_the_initial_frame(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            events = app.query_one("#events", DataTable)
            assert events.row_count == trace.frame_count() + 1
            assert f"frame 0/{trace.frame_count()}" in _text(app.query_one("#status", Static))
            assert "initial machine state" in _text(app.query_one("#producer", Static))

    _run(scenario())


def test_step_forward_moves_the_frame(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.press("down")
            await pilot.pause()
            assert f"frame 1/{trace.frame_count()}" in _text(app.query_one("#status", Static))
            rendered = _render_table(app.query_one("#regs", Static))
            assert "rax" in rendered
            assert "rip" in rendered

    _run(scenario())


def test_start_frame_is_respected(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace, start_frame=4)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert f"frame 4/{trace.frame_count()}" in _text(app.query_one("#status", Static))

    _run(scenario())


def test_goto_jumps_to_a_frame(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.press("g")
            await pilot.pause()
            goto = app.query_one("#goto", Input)
            assert not goto.has_class("hidden")
            await pilot.press("3")
            await pilot.press("enter")
            await pilot.pause()
            assert f"frame 3/{trace.frame_count()}" in _text(app.query_one("#status", Static))
            assert goto.has_class("hidden")

    _run(scenario())


def test_escape_dismisses_the_goto_input(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.press("g")
            await pilot.pause()
            goto = app.query_one("#goto", Input)
            assert not goto.has_class("hidden")
            await pilot.press("escape")
            await pilot.pause()
            assert goto.has_class("hidden")

    _run(scenario())


def test_end_reaches_the_final_frame(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.press("end")
            await pilot.pause()
            last = trace.frame_count()
            assert f"frame {last}/{last}" in _text(app.query_one("#status", Static))
            assert "exit" in _text(app.query_one("#producer", Static))
            assert "hello, winVpwn" in _text(app.query_one("#output", Static))

    _run(scenario())


def test_home_returns_to_the_start(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace, start_frame=6)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.press("home")
            await pilot.pause()
            assert f"frame 0/{trace.frame_count()}" in _text(app.query_one("#status", Static))

    _run(scenario())


def test_page_down_steps_in_chunks(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.press("page_down")
            await pilot.pause()
            assert f"frame 10/{trace.frame_count()}" in _text(app.query_one("#status", Static))

    _run(scenario())


def test_bad_goto_input_keeps_the_frame(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.press("g")
            await pilot.pause()
            await pilot.press("not-a-frame")
            await pilot.press("enter")
            await pilot.pause()
            assert f"frame 0/{trace.frame_count()}" in _text(app.query_one("#status", Static))
            assert app.query_one("#goto", Input).has_class("hidden")

    _run(scenario())


def test_output_is_empty_before_the_write(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.press("home")
            await pilot.pause()
            assert _text(app.query_one("#output", Static)) == "(no output)"

    _run(scenario())


def test_every_frame_is_reachable_by_stepping(ctrace_path: Path) -> None:
    trace = _load(ctrace_path)

    async def scenario() -> None:
        app = CinemaApp(trace)
        async with app.run_test(size=(120, 40)) as pilot:
            for _ in range(trace.frame_count()):
                await pilot.press("down")
            await pilot.pause()
            last = trace.frame_count()
            assert f"frame {last}/{last}" in _text(app.query_one("#status", Static))

    _run(scenario())
