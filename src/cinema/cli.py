"""Command line interface for the replay projector.

Four commands cover the Stage 1 workflow:

    cinema record  binary --out run.ctrace
    cinema info    run.ctrace
    cinema trace   run.ctrace --from 100 --to 120
    cinema frame   run.ctrace 100 --mem 0x401000:32
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from cinema import _core as core
from cinema._core import Trace
from cinema.ui.format import detail as _detail
from cinema.ui.format import hex_bytes as _hex
from cinema.ui.tables import base_table
from cinema.ui.theme import ACCENT, DIM, ERROR, OK, PRIMARY, SECONDARY, WARN

app = typer.Typer(
    name="cinema",
    help="Record a binary's execution and seek back to any frame.",
    no_args_is_help=True,
)

_default_console = Console(highlight=False)

_KIND_COLORS: dict[str, str] = {
    "insn": DIM,
    "reg_write": PRIMARY,
    "mem_write": SECONDARY,
    "syscall_enter": ACCENT,
    "syscall_exit": DIM,
    "output": OK,
    "exit": WARN,
}

_KIND_SHORT: dict[str, str] = {
    "insn": "insn",
    "reg_write": "reg",
    "mem_write": "mem",
    "syscall_enter": "syscall",
    "syscall_exit": "syscall",
    "output": "output",
    "exit": "exit",
}

_DEFAULT_MEM_LEN = 32


def _console(no_color: bool = False) -> Console:
    if no_color:
        return Console(highlight=False, color_system=None)
    return _default_console


def _int(value: Any, default: int = 0) -> int:
    return int(value) if isinstance(value, int) else default


def _payload_json(payload: Mapping[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """Make a dict JSON-serializable by decoding the named byte fields."""
    out = dict(payload)
    for key in keys:
        if isinstance(out.get(key), (bytes, bytearray)):
            out[key] = bytes(out[key]).decode("utf-8", "replace")
    return out


def _load(path: Path, console: Console) -> Trace:
    if path.suffix != ".ctrace":
        console.print(f"[{WARN}]warning[/] {path.name} does not look like a .ctrace file")
    try:
        return core.load_ctrace(path.read_bytes())
    except (OSError, ValueError) as exc:
        console.print(f"[{ERROR}]error[/] {exc}")
        raise typer.Exit(code=2) from exc


@app.command()
def record(
    binary: Path = typer.Argument(..., help="Path to a static ET_EXEC x86_64 ELF."),
    out: Path | None = typer.Option(None, "--out", help="Write the .ctrace file here."),
    timeout: int = typer.Option(0, "--timeout", help="Execution budget in milliseconds."),
    max_events: int = typer.Option(0, "--max-events", help="Stop after this many events."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
) -> None:
    """Run an ELF under the emulator and record every observable change."""
    console = _console(no_color=no_color)
    try:
        image = binary.read_bytes()
        trace = core.record(image, timeout, max_events)
    except (OSError, ValueError) as exc:
        console.print(f"[{ERROR}]error[/] {exc}")
        raise typer.Exit(code=2) from exc

    payload = trace.summary()
    if out is not None:
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(trace.encode())
        except OSError as exc:
            console.print(f"[{ERROR}]error[/] write {out}: {exc}")
            raise typer.Exit(code=2) from exc

    if json_out:
        console.print_json(data=_payload_json(payload, ("output",)))
        raise typer.Exit(code=_exit_code(payload))

    if out is not None:
        console.print(f"[{OK}]recorded[/] {out} ({out.stat().st_size} bytes)")
    _print_summary(console, payload)
    raise typer.Exit(code=_exit_code(payload))


def _exit_code(payload: Mapping[str, Any]) -> int:
    kind = str(payload.get("exit_kind", "none"))
    if kind == "exit":
        code = _int(payload.get("exit_value"))
        return code if code < 256 else 1
    if kind == "falloff":
        return 3
    if kind == "stopped":
        return 4
    return 2


@app.command()
def info(
    trace_path: Path = typer.Argument(..., help="Path to a .ctrace file."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
) -> None:
    """Show what a recording contains."""
    console = _console(no_color=no_color)
    trace = _load(trace_path, console)
    payload = trace.summary()
    if json_out:
        console.print_json(data=_payload_json(payload, ("output",)))
        raise typer.Exit(code=0)
    _print_summary(console, payload)
    raise typer.Exit(code=0)


def _print_summary(console: Console, payload: Mapping[str, Any]) -> None:
    table = base_table(title="recording")
    table.add_column("", style=DIM, no_wrap=True)
    table.add_column("")
    table.add_row("entry", f"0x{_int(payload.get('entry')):x}")
    table.add_row("events", str(payload.get("events", 0)))
    table.add_row("final frame", str(payload.get("final_frame", 0)))
    table.add_row("snapshots", str(payload.get("snapshots", 0)))
    table.add_row("base pages", str(payload.get("base_pages", 0)))
    table.add_row("image hash", str(payload.get("image_hash", "")))
    console.print(table)

    kind = str(payload.get("exit_kind", "none"))
    number = _int(payload.get("exit_value"))
    if kind == "exit":
        style = OK if number == 0 else WARN
        console.print(f"  [{style}]exit({number})[/]")
    elif kind == "falloff":
        console.print(f"  [{WARN}]instruction falloff at 0x{number:x}[/]")
    elif kind == "stopped":
        console.print(f"  [{WARN}]stopped without exit[/]")
    else:
        console.print(f"  [{DIM}]no exit recorded[/]")

    output = payload.get("output")
    if isinstance(output, bytes) and output:
        console.print(f"  [{DIM}]output:[/] {output.decode('utf-8', 'replace')!r}")


@app.command("trace")
def trace_events(
    trace_path: Path = typer.Argument(..., help="Path to a .ctrace file."),
    from_frame: int = typer.Option(0, "--from", help="First frame to show."),
    to_frame: int = typer.Option(-1, "--to", help="Frame one past the last to show."),
    only: str = typer.Option(
        "",
        "--only",
        help="Show only these kinds, comma separated: insn,reg,mem,syscall,output,exit.",
    ),
    limit: int = typer.Option(200, "--limit", help="Cap on the rows shown."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
) -> None:
    """List the events of a recording."""
    console = _console(no_color=no_color)
    trace = _load(trace_path, console)
    last = trace.frame_count()
    start = max(0, min(from_frame, last))
    end = last if to_frame < 0 else max(0, min(to_frame, last))
    events = trace.events(start, end)
    wanted = {part.strip() for part in only.split(",") if part.strip()}
    if wanted:
        events = [e for e in events if _KIND_SHORT.get(str(e.get("kind", ""))) in wanted]
    shown = events[:limit]

    if json_out:
        console.print_json(data=_events_json(shown))
        raise typer.Exit(code=0)

    if not events:
        console.print(f"[{DIM}]no events in frames {start + 1}..{end}[/]")
        raise typer.Exit(code=0)

    table = base_table(title=f"frames {start + 1}-{end}")
    table.add_column("#", style=DIM, no_wrap=True)
    table.add_column("kind", no_wrap=True)
    table.add_column("detail")
    for event in shown:
        kind = str(event.get("kind", ""))
        table.add_row(str(event.get("frame", "")), kind, _detail(kind, event))
    console.print(table)
    if len(events) > limit:
        console.print(f"[{DIM}]{len(events) - limit} more events not shown[/]")
    raise typer.Exit(code=0)


def _events_json(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for event in events:
        copy = dict(event)
        for key in ("bytes", "data"):
            if isinstance(copy.get(key), (bytes, bytearray)):
                copy[key] = _hex(bytes(copy[key]))
        out.append(copy)
    return out


@app.command()
def frame(
    trace_path: Path = typer.Argument(..., help="Path to a .ctrace file."),
    at: int = typer.Argument(..., help="The frame to reconstruct."),
    mem: list[str] | None = typer.Option(
        None,
        "--mem",
        metavar="ADDR[:LEN]",
        help="Memory window to print; may be given several times.",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
) -> None:
    """Reconstruct the full machine state at one frame."""
    console = _console(no_color=no_color)
    trace = _load(trace_path, console)
    last = trace.frame_count()
    if at < 0 or at > last:
        console.print(f"[{ERROR}]error[/] frame {at} is out of range 0..{last}")
        raise typer.Exit(code=2)

    windows: list[tuple[int, int]] = []
    for spec in mem or []:
        parsed = _parse_mem_spec(spec)
        if parsed is None:
            console.print(f"[{ERROR}]error[/] bad --mem spec {spec!r}, expected ADDR[:LEN]")
            raise typer.Exit(code=2)
        windows.append(parsed)

    state = trace.state_at(at)
    window_data: dict[str, dict[str, Any]] = {
        f"0x{addr:x}": {"addr": addr, "data": state.read_memory(addr, length).hex(" ")}
        for addr, length in windows
    }

    if json_out:
        payload: dict[str, Any] = {
            "frame": at,
            "rip": state.rip(),
            "regs": state.regs(),
            "output": state.output(),
            "dirty_pages": state.dirty_page_count(),
            "memory": window_data,
            "event": trace.event_at(at),
        }
        payload = _payload_json(payload, ("output",))
        if isinstance(payload.get("event"), dict):
            payload["event"] = _events_json([payload["event"]])[0]
        console.print_json(data=payload)
        raise typer.Exit(code=0)

    table = base_table(title=f"frame {at}")
    table.add_column("reg", style=DIM, no_wrap=True)
    table.add_column("value", no_wrap=True)
    for name, value in state.regs().items():
        if name == "rip":
            table.add_row(name, f"[{PRIMARY}]0x{int(value):x}[/]")
        else:
            table.add_row(name, f"0x{int(value):x}")
    console.print(table)

    output = state.output()
    console.print(f"[{DIM}]output so far:[/] {output.decode('utf-8', 'replace')!r}")
    console.print(f"[{DIM}]dirty pages:[/] {state.dirty_page_count()}")

    event = trace.event_at(at)
    if event is not None:
        console.print(f"[{DIM}]producing event:[/] {_detail(str(event.get('kind', '')), event)}")
    else:
        console.print(f"[{DIM}]frame 0 is the initial state[/]")

    for addr, length in windows:
        console.print(f"[{DIM}]memory 0x{addr:x}:[/] {_hex(state.read_memory(addr, length), length)}")
    raise typer.Exit(code=0)


@app.command()
def tui(
    trace_path: Path = typer.Argument(..., help="Path to a .ctrace file."),
    at: int = typer.Option(0, "--frame", "-f", help="Frame to start at."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
) -> None:
    """Browse a recording frame by frame in the terminal."""
    console = _console(no_color=no_color)
    trace = _load(trace_path, console)
    from cinema.tui import CinemaApp

    CinemaApp(trace, start_frame=at).run()


@app.command()
def export(
    trace_path: Path = typer.Argument(..., help="Path to a .ctrace file."),
    out: Path = typer.Argument(..., help="Where to write the HTML report."),
    mem: list[str] | None = typer.Option(
        None,
        "--mem",
        metavar="ADDR[:LEN]",
        help="Memory window to embed; may be given several times.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
) -> None:
    """Export a recording as a self-contained HTML report."""
    console = _console(no_color=no_color)
    trace = _load(trace_path, console)
    windows: list[tuple[int, int]] = []
    for spec in mem or []:
        parsed = _parse_mem_spec(spec)
        if parsed is None:
            console.print(f"[{ERROR}]error[/] bad --mem spec {spec!r}, expected ADDR[:LEN]")
            raise typer.Exit(code=2)
        windows.append(parsed)
    try:
        from cinema.export import export_trace

        export_trace(trace, out, windows)
    except OSError as exc:
        console.print(f"[{ERROR}]error[/] write {out}: {exc}")
        raise typer.Exit(code=2) from exc
    console.print(f"[{OK}]exported[/] {out} ({out.stat().st_size} bytes)")
    raise typer.Exit(code=0)


def _parse_mem_spec(spec: str) -> tuple[int, int] | None:
    parts = spec.split(":")
    if not parts or len(parts) > 2:
        return None
    try:
        addr = int(parts[0], 0)
    except ValueError:
        return None
    length = _DEFAULT_MEM_LEN
    if len(parts) == 2:
        try:
            length = int(parts[1], 0)
        except ValueError:
            return None
        if length <= 0:
            return None
    return addr, length


def main() -> None:
    app(prog_name="cinema")


if __name__ == "__main__":
    main()
