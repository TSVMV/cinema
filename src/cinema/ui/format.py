"""Shared formatting for events and memory windows.

Both the CLI and the TUI render the same event stream; keeping the
formatting in one place guarantees the two views cannot drift apart.
"""

from __future__ import annotations

from typing import Any


def hex_bytes(data: bytes, limit: int = 64) -> str:
    """Render bytes as space-separated hex, truncating with an explicit tail."""
    shown = data[:limit]
    tail = "" if len(data) == len(shown) else f" ... ({len(data)} bytes)"
    return " ".join(f"{b:02x}" for b in shown) + tail


def detail(kind: str, event: dict[str, Any]) -> str:
    """One-line human description of an event."""
    if kind == "insn":
        addr = int(event.get("addr", 0))
        size = int(event.get("size", 0))
        code = bytes(event.get("bytes", b""))
        return f"0x{addr:x}  {size} bytes  {hex_bytes(code)}"
    if kind == "reg_write":
        return f"{event.get('reg', '?')} = 0x{int(event.get('value', 0)):x}"
    if kind == "mem_write":
        addr = int(event.get("addr", 0))
        data = bytes(event.get("data", b""))
        return f"0x{addr:x}  {len(data)} bytes  {hex_bytes(data, 32)}"
    if kind == "syscall_enter":
        args = ", ".join(f"0x{int(a):x}" for a in event.get("args", []))
        return f"{event.get('name', '?')} ({event.get('nr', '?')}) {args}"
    if kind == "syscall_exit":
        return f"ret = {event.get('ret', '?')}"
    if kind == "output":
        data = bytes(event.get("data", b""))
        return repr(data.decode("utf-8", "replace"))
    if kind == "exit":
        return f"{event.get('exit_kind', '?')} {int(event.get('value', 0))}"
    return str(event.get("label", ""))


def render_output(data: bytes, width: int = 60) -> str:
    """Render captured output for a terminal line.

    Printable text is shown as-is; anything else falls back to hex so no
    control byte ever corrupts the terminal.
    """
    if not data:
        return "(no output)"
    safe = all((32 <= b < 127) or b in (9, 10, 13) for b in data)
    if safe:
        return data.decode("utf-8", "replace")
    return hex_bytes(data)
