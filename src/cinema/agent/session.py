"""Mutable session state for the agent tool layer.

A session wraps a trace and a cursor. Tools query or move the cursor and
always answer from the recording; nothing here is fabricated.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cinema._core import State, Trace


@dataclass
class Session:
    trace: Trace | None = None
    cursor: int = 0
    log: list[dict[str, object]] = field(default_factory=list)

    @property
    def last_frame(self) -> int:
        if self.trace is None:
            return 0
        return int(self.trace.frame_count())

    def state(self, frame: int | None = None) -> State:
        if self.trace is None:
            raise RuntimeError("no trace loaded")
        at = int(self.cursor if frame is None else frame)
        return self.trace.state_at(at)

    def note(self, kind: str, detail: str, data: dict[str, object] | None = None) -> None:
        entry: dict[str, object] = {"kind": kind, "detail": detail}
        if data is not None:
            entry["data"] = data
        self.log.append(entry)
