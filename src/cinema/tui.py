"""Textual TUI: browse a recording frame by frame.

The left pane is the full event stream; the right pane is the reconstructed
machine state at the selected frame. Every number on screen comes from the
trace itself — the TUI never synthesizes data.

    cinema tui run.ctrace
    cinema tui run.ctrace --frame 42
"""

from __future__ import annotations

from typing import Any

from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Input, Static

from cinema._core import Trace
from cinema.ui.format import detail, render_output
from cinema.ui.theme import ACCENT, DIM, OK, PRIMARY, SECONDARY, WARN

_KIND_COLORS: dict[str, str] = {
    "insn": DIM,
    "reg_write": PRIMARY,
    "mem_write": SECONDARY,
    "syscall_enter": ACCENT,
    "syscall_exit": DIM,
    "output": OK,
    "exit": WARN,
}

_REG_ORDER: tuple[str, ...] = (
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
)

_CSS = """
#body {
    height: 1fr;
}
#left {
    width: 55%;
}
#right {
    width: 45%;
}
#status {
    height: 1;
    padding: 0 1;
    color: $text-muted;
}
#regs-scroll {
    height: 1fr;
    border: round $border;
}
#output-scroll {
    height: 9;
    border: round $border;
}
#producer-scroll {
    height: 7;
    border: round $border;
}
#goto {
    dock: bottom;
}
.hidden {
    display: none;
}
"""


class FrameInput(Input):
    """Frame-number input; its only job is to hold a frame number."""


class CinemaApp(App[None]):
    """A frame-stepping viewer over a recorded trace."""

    TITLE = "cinema"
    SUB_TITLE = "replay projector"
    CSS = _CSS

    BINDINGS = [
        Binding("up,j", "step(-1)", "step back", priority=True),
        Binding("down,k", "step(1)", "step forward", priority=True),
        Binding("page_up,[", "step(-10)", "back 10", priority=True),
        Binding("page_down,]", "step(10)", "forward 10", priority=True),
        Binding("home", "home", "start", priority=True),
        Binding("end", "end", "last frame", priority=True),
        Binding("g", "goto", "goto frame"),
        Binding("escape", "dismiss_goto", "close input", priority=True),
        Binding("q", "quit", "quit"),
    ]

    frame: reactive[int] = reactive(0)

    def __init__(self, trace: Trace, start_frame: int = 0) -> None:
        super().__init__()
        self.trace = trace
        self.last = trace.frame_count()
        self._start = max(0, min(start_frame, self.last))
        self._active = False
        self._table: DataTable[object]
        self._regs: Static
        self._output: Static
        self._producer: Static
        self._status: Static
        self._goto: FrameInput

    # ------------------------------------------------------------- wiring

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield ScrollableContainer(
                    DataTable(id="events", cursor_type="row"), id="events-scroll"
                )
            with Vertical(id="right"):
                yield Static("", id="status")
                yield ScrollableContainer(Static("", id="regs"), id="regs-scroll")
                yield ScrollableContainer(Static("", id="output"), id="output-scroll")
                yield ScrollableContainer(Static("", id="producer"), id="producer-scroll")
        yield FrameInput(placeholder="frame number, e.g. 120", id="goto", classes="hidden")
        yield Footer()

    def on_mount(self) -> None:
        self._table = self.query_one("#events", DataTable)
        self._regs = self.query_one("#regs", Static)
        self._output = self.query_one("#output", Static)
        self._producer = self.query_one("#producer", Static)
        self._status = self.query_one("#status", Static)
        self._goto = self.query_one("#goto", FrameInput)
        self._build_events()
        self._active = True
        self.frame = self._start
        self._table.move_cursor(row=self._start, animate=False)
        self._table.focus()

    def _build_events(self) -> None:
        table = self._table
        table.add_columns("#", "kind", "detail")
        table.add_row("0", "---", "initial machine state")
        for frame in range(1, self.last + 1):
            event = self.trace.event_at(frame)
            if event is None:
                continue
            kind = str(event.get("kind", ""))
            cell = Text(kind, style=_KIND_COLORS.get(kind, ""))
            table.add_row(str(frame), cell, detail(kind, event))

    # ------------------------------------------------------------- state

    def watch_frame(self, old: int, new: int) -> None:
        if self._active:
            self._render()

    def _render(self) -> None:
        frame = self.frame
        state = self.trace.state_at(frame)
        self._status.update(self._status_line(frame, state))
        self._render_regs(state)
        self._render_output(state.output())
        self._render_event(frame)

    def _status_line(self, frame: int, state: Any) -> str:
        parts = [
            f"frame {frame}/{self.last}",
            f"rip 0x{state.rip():x}",
            f"dirty pages {state.dirty_page_count()}",
        ]
        if frame in self.trace.snapshot_frames():
            parts.append("snapshot")
        return "  .  ".join(parts)

    def _render_regs(self, state: Any) -> None:
        table = Table(box=None, show_header=False, pad_edge=False)
        table.add_column(no_wrap=True, style=DIM)
        table.add_column(no_wrap=True)
        regs = state.regs()
        for name in _REG_ORDER:
            value = int(regs[name])
            cell = Text(f"0x{value:x}", style=PRIMARY) if name == "rip" else Text(f"0x{value:x}")
            table.add_row(Text(name), cell)
        self._regs.update(table)

    def _render_output(self, data: bytes) -> None:
        self._output.update(render_output(data))

    def _render_event(self, frame: int) -> None:
        event = self.trace.event_at(frame)
        if event is None:
            self._producer.update(Text("frame 0  ---  initial machine state", style=DIM))
            return
        kind = str(event.get("kind", ""))
        text = Text(f"frame {frame}  ---  {kind}: ")
        text.append(detail(kind, event))
        self._producer.update(text)

    # ------------------------------------------------------------- nav

    def _goto_frame(self, frame: int) -> None:
        target = max(0, min(frame, self.last))
        self.frame = target
        self._table.move_cursor(row=target, animate=False)

    def action_step(self, delta: int) -> None:
        self._goto_frame(self.frame + delta)

    def action_home(self) -> None:
        self._goto_frame(0)

    def action_end(self) -> None:
        self._goto_frame(self.last)

    def action_goto(self) -> None:
        self._show_goto()

    def _show_goto(self) -> None:
        self._goto.remove_class("hidden")
        self._goto.focus()

    def action_dismiss_goto(self) -> None:
        if not self._goto.has_class("hidden"):
            self._goto.add_class("hidden")
            self._table.focus()

    @on(FrameInput.Submitted)
    def _on_goto_submitted(self, message: FrameInput.Submitted) -> None:
        try:
            frame = int(message.value, 0)
        except ValueError:
            frame = None
        if frame is not None:
            self._goto_frame(frame)
        self._goto.add_class("hidden")
        self._table.focus()

    def on_data_table_row_highlighted(self, message: DataTable.RowHighlighted) -> None:
        if self._active:
            self.frame = message.cursor_row
