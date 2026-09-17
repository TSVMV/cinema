"""Tests for the LLM-backed decider against a local OpenAI-compatible mock.

The mock is a real HTTP server that answers chat completions with scripted
responses, so the full request/response path (auth headers, JSON body, tool
schema, argument parsing) is exercised for real.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from cinema._core import Trace
from cinema.agent.decider import Conversation, ToolCall
from cinema.agent.llm import LLMConfigError, LLMDecider
from cinema.agent.loop import run_agent
from cinema.agent.session import Session


@contextmanager
def _make_server(script: list[dict[str, Any]]) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    received: list[dict[str, Any]] = []

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 (HTTP method name)
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            received.append({"path": self.path, "headers": dict(self.headers), "body": body})
            choice = script.pop(0) if script else {}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": choice}]}).encode("utf-8"))

        def log_message(self, *args: Any) -> None:  # noqa: D102
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/v1"
    try:
        yield url, received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def _llm(script: list[dict[str, Any]], **kwargs: Any) -> Iterator[tuple[LLMDecider, list[dict[str, Any]]]]:
    with _make_server(script) as (url, received):
        decider = LLMDecider(api_key="test-key", base_url=url, model="mock", **kwargs)
        yield decider, received


def test_env_config_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CINEMA_LLM_API_KEY", raising=False)
    with pytest.raises(LLMConfigError):
        LLMDecider()


def test_llm_decider_issues_a_tool_call(trace: Trace) -> None:
    with _llm(
        [
            {
                "tool_calls": [
                    {"function": {"name": "run", "arguments": json.dumps({})}}
                ]
            }
        ]
    ) as (decider, received):
        session = Session(trace=trace)
        call = decider.next_call(session, Conversation([]))
        assert isinstance(call, ToolCall)
        assert call.name == "run"
        assert call.kwargs == {}
        body = received[-1]["body"]
        assert body["model"] == "mock"
        assert body["messages"][0]["role"] == "system"
        tool_names = [t["function"]["name"] for t in body["tools"]]
        assert "query_memory" in tool_names and "find_callsite" in tool_names


def test_llm_decider_returns_none_on_plain_text() -> None:
    with _llm([{"content": "the answer is exit(0)"}]) as (decider, _received):
        assert decider.next_call(Session(), Conversation([])) is None


def test_run_agent_with_llm_decider_full_cycle(trace: Trace) -> None:
    responses: list[dict[str, Any]] = [
        {"tool_calls": [{"function": {"name": "query_memory", "arguments": json.dumps({"addr": "0x402000", "length": 4})}}]},
        {"tool_calls": [{"function": {"name": "run", "arguments": json.dumps({})}}]},
        {"content": "done"},
    ]
    with _llm(responses) as (decider, _received):
        session = Session(trace=trace)
        turns = run_agent(session, decider)
        assert [t.call.name for t in turns] == ["query_memory", "run"]
        assert all(t.ok for t in turns)
        assert turns[0].result["decoded"] == "hell"


def test_llm_decider_sends_auth_header_and_tool_schema() -> None:
    with _llm([{"content": "ok"}]) as (decider, received):
        decider.next_call(Session(), Conversation([]))
        last = received[-1]
        assert last["headers"].get("Authorization") == "Bearer test-key"
        assert last["path"].endswith("/chat/completions")


def test_llm_decider_passes_tool_results_back(trace: Trace) -> None:
    responses: list[dict[str, Any]] = [
        {"tool_calls": [{"function": {"name": "run", "arguments": "{}"}}]},
        {"content": "final"},
    ]
    with _llm(responses) as (decider, received):
        session = Session(trace=trace)
        conversation = Conversation(
            [
                {
                    "role": "tool",
                    "name": "run",
                    "kwargs": {"frame": 5},
                    "result": {"frame": 5, "rip": "0x40101e"},
                }
            ]
        )
        decider.next_call(session, conversation)
        messages = received[-1]["body"]["messages"]
        roles = [m["role"] for m in messages]
        assert "assistant" in roles and "tool" in roles
        tool_msg = next(m for m in messages if m["role"] == "tool")
        assert "0x40101e" in tool_msg["content"]


def test_llm_decider_forwards_user_goal_without_keyerror() -> None:
    with _llm([{"content": "ok"}]) as (decider, received):
        conversation = Conversation([{"role": "user", "content": "what did it print?"}])
        assert decider.next_call(Session(), conversation) is None
        roles = [m["role"] for m in received[-1]["body"]["messages"]]
        assert roles[:2] == ["system", "user"]
        assert received[-1]["body"]["messages"][1]["content"] == "what did it print?"


def test_run_agent_delivers_user_goal_before_tools(trace: Trace) -> None:
    responses: list[dict[str, Any]] = [
        {"tool_calls": [{"function": {"name": "run", "arguments": "{}"}}]},
        {"content": "hello, winVpwn"},
    ]
    with _llm(responses) as (decider, received):
        session = Session(trace=trace)
        turns = run_agent(session, decider, user_goal="what text does it write?")
        assert [t.call.name for t in turns] == ["run"]
        first_messages = received[0]["body"]["messages"]
        assert first_messages[1]["role"] == "user"
        assert first_messages[1]["content"] == "what text does it write?"


class _FlushedLogger:
    flushed = True
    calls: list[str]

    def __init__(self) -> None:
        self.calls = []

    def __call__(self, call: ToolCall, result: dict[str, Any]) -> None:
        self.calls.append(call.name)


def test_run_agent_does_not_stop_on_logger_flushed(trace: Trace) -> None:
    responses: list[dict[str, Any]] = [
        {"tool_calls": [{"function": {"name": "run", "arguments": json.dumps({"frame": 0})}}]},
        {"tool_calls": [{"function": {"name": "step_back", "arguments": json.dumps({"count": 1})}}]},
        {"content": "done"},
    ]
    logger = _FlushedLogger()
    with _llm(responses) as (decider, _received):
        session = Session(trace=trace)
        turns = run_agent(session, decider, logger=logger)
        assert [t.call.name for t in turns] == ["run", "step_back"]
        assert logger.calls == ["run", "step_back"]
