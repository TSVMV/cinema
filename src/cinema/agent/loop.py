"""Agent loop: repeatedly ask a decider for the next tool call and execute it.

The loop itself never decides anything; it only executes whatever the
decider returns, records the real outcome into the conversation, and stops
when the decider signals it is done.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cinema.agent.decider import Conversation, Decider, ToolCall
from cinema.agent.session import Session


@dataclass
class Turn:
    call: ToolCall
    ok: bool
    result: dict[str, Any]
    error: str | None = None


def run_agent(
    session: Session,
    decider: Decider,
    max_turns: int = 64,
    logger: Any = None,
    user_goal: str | None = None,
) -> list[Turn]:
    """Drive ``decider`` to completion against a real session.

    Every tool call is executed for real; its captured result (or the error)
    is the truth recorded in the ``Turn`` returned to the caller. No result
    is ever synthesized.

    If ``user_goal`` is given, it is delivered to the decider as the very
    first message (the task the agent must solve by calling tools).
    """
    turns: list[Turn] = []
    initial: list[dict[str, Any]] = (
        [{"role": "user", "content": user_goal}] if user_goal is not None else []
    )
    conversation = Conversation(initial)
    for _ in range(max_turns):
        decision = decider.next_call(session, conversation)
        if decision is None:
            break
        try:
            from cinema.agent.tools import call_tool

            result = call_tool(session, decision.name, decision.kwargs)
            turn = Turn(decision, True, result)
            if logger is not None:
                logger(decision, result)
        except Exception as exc:  # tool contract violation must not kill loop
            turn = Turn(decision, False, {}, error=str(exc))
            if logger is not None:
                logger(decision, {"error": str(exc)})
        turns.append(turn)
        conversation.turns.append(
            {"role": "tool", "name": decision.name, "kwargs": decision.kwargs, "result": turn.result}
        )
    return turns


def replay(decisions: Sequence[ToolCall | str | None], session: Session) -> list[Turn]:
    """Run a fixed script of tool calls (tests)."""
    from cinema.agent.decider import ScriptedDecider

    return run_agent(session, ScriptedDecider(decisions))
