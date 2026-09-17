"""LLM-backed decider: drives the tool layer through an OpenAI-compatible endpoint.

Credentials come from project-owned environment variables (``CINEMA_LLM_*``),
never from the agent's runtime. The decider renders the conversation into an
OpenAI-style tool-calling chat and turns the model's ``tool_calls`` into
:class:`~cinema.agent.decider.ToolCall`. A plain-text response ends the loop.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, cast

from cinema.agent.decider import Conversation, Decider, ToolCall
from cinema.agent.session import Session
from cinema.agent.tools import INTERNAL_REGISTRY

ENV_API_KEY = "CINEMA_LLM_API_KEY"
ENV_BASE_URL = "CINEMA_LLM_BASE_URL"
ENV_MODEL = "CINEMA_LLM_MODEL"

DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
DEFAULT_MODEL = "deepseek-chat"
SYSTEM_PROMPT = (
    "You are inspecting a recorded execution of a binary. You can only use the "
    "provided tools; there is no shell. Every tool answer is real recorded data. "
    "Inspect the recording to answer questions about registers, memory, syscalls "
    "and control flow. When you know the answer, reply with plain text only."
)


class LLMConfigError(RuntimeError):
    """Raised when the LLM configuration is incomplete."""


def _tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": spec.name,
                "description": spec.description,
                "parameters": spec.parameters,
            },
        }
        for spec in INTERNAL_REGISTRY
    ]


class LLMDecider(Decider):
    """An OpenAI-compatible function-calling decider."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        max_tokens: int = 400,
    ) -> None:
        self.api_key = api_key or os.getenv(ENV_API_KEY)
        if not self.api_key:
            raise LLMConfigError(
                f"{ENV_API_KEY} is not set; set it (plus {ENV_BASE_URL} and {ENV_MODEL}) to use the LLM decider"
            )
        self.base_url = (base_url or os.getenv(ENV_BASE_URL) or DEFAULT_BASE_URL).rstrip("/")
        self.model = model or os.getenv(ENV_MODEL) or DEFAULT_MODEL
        self.max_tokens = max_tokens
        self.raw_last_response: dict[str, Any] | None = None

    def next_call(self, session: Session, conversation: Conversation) -> ToolCall | None:
        messages = self._messages(conversation)
        body = {
            "model": self.model,
            "messages": messages,
            "tools": _tool_schemas(),
            "tool_choice": "auto",
            "max_tokens": self.max_tokens,
        }
        response = self._post(body)
        self.raw_last_response = response
        message = response["choices"][0]["message"]
        calls = message.get("tool_calls") or []
        if not calls:
            return None
        call = calls[0]
        fn = call.get("function", {})
        try:
            kwargs = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            kwargs = {}
        return ToolCall(str(fn.get("name", "")), kwargs)

    def _messages(self, conversation: Conversation) -> list[dict[str, Any]]:
        messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
        counter = 0
        for turn in conversation.turns:
            if turn.get("role") == "user":
                messages.append({"role": "user", "content": turn["content"]})
                continue
            call_id = f"cinema_call_{counter}"
            counter += 1
            tool_call = {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": str(turn["name"]),
                    "arguments": json.dumps(turn.get("kwargs", {}), sort_keys=True),
                },
            }
            messages.append({"role": "assistant", "content": None, "tool_calls": [tool_call]})
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": json.dumps(turn.get("result", {}), sort_keys=True),
                }
            )
        return messages

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        if self.base_url.endswith("/chat/completions"):
            url = self.base_url
        else:
            url = f"{self.base_url}/chat/completions"
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 (configured URL)
            payload = json.loads(response.read().decode("utf-8"))
            if not isinstance(payload, dict):
                raise RuntimeError("LLM endpoint returned a non-object JSON body")
            return cast(dict[str, Any], payload)
