"""Decision layer: given the history of tool calls, pick the next one.

A ``Decider`` only decides *which* tool to call (or that it has enough to
answer). It never fabricates results. The fake decider used in tests is a
scripted stub that follows a fixed schedule; the tool layer underneath still
executes for real.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from cinema.agent.session import Session


@dataclass
class ToolCall:
    name: str
    kwargs: dict[str, Any]


@dataclass
class Conversation:
    """Immutable transcript passed to a decider."""

    turns: list[dict[str, Any]]

    def last(self) -> dict[str, Any] | None:
        return self.turns[-1] if self.turns else None

    def results(self) -> list[dict[str, Any]]:
        return [t for t in self.turns if t.get("role") == "tool"]

    def session_state(self, kind: str, detail: str) -> dict[str, Any]:
        return {"kind": kind, "detail": detail}


class Decider(Protocol):
    def next_call(self, session: Session, conversation: Conversation) -> ToolCall | None:
        """Return the next tool to call, or ``None`` when done."""
        ...


class ScriptedDecider:
    """A scripted stub used for tests: emits a fixed sequence of calls."""

    def __init__(self, calls: Sequence[ToolCall | str | None]):
        self.calls = list(calls)

    def next_call(self, session: Session, conversation: Conversation) -> ToolCall | None:
        if not self.calls:
            return None
        head = self.calls.pop(0)
        if head is None:
            return None
        if isinstance(head, str):
            return ToolCall(head, {})
        return head
