"""Abstract runner + tool-call capture.

The runner's contract: given a TaskEnv (prompt + mock tools) and a model, drive
the model, and for every tool call the model emits, capture
``{tool_name, arguments, step_index, condition}`` BEFORE handing the arguments
to the mock backend. Capturing pre-execution is what lets the classifier inspect
the payload the model *intended* to send, independent of what the mock returns.

``ScriptedRunner`` is a runner backed by a pre-recorded list of tool calls
rather than a live model. It is used by the test suite and by ``demo`` so the
whole pipeline runs deterministically with no network. Live providers plug in
through the adapters, which only parse tool-call args out of a provider response.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class CapturedCall:
    tool_name: str
    arguments: Any
    step_index: int
    condition: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "step_index": self.step_index,
            "condition": self.condition,
        }


@dataclass
class RunResult:
    task_name: str
    condition: str
    model: str
    captured_calls: list[CapturedCall] = field(default_factory=list)
    # Raw mock responses, for transparency/debugging only.
    tool_responses: list[Any] = field(default_factory=list)

    def as_call_dicts(self) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self.captured_calls]


class BaseRunner:
    """Abstract runner. Subclasses implement ``iter_tool_calls``."""

    #: provider identifier, e.g. "scripted", "openai", "anthropic"
    provider = "base"

    def iter_tool_calls(self, env, model: str):  # pragma: no cover - abstract
        """Yield {tool_name, arguments} dicts for each tool call the model makes."""
        raise NotImplementedError

    def run(self, env, model: str) -> RunResult:
        """Drive the model against ``env``, capturing every tool call.

        Capture happens BEFORE the mock backend is invoked.
        """
        result = RunResult(
            task_name=env.task.name, condition=env.condition, model=model
        )
        for step_index, call in enumerate(self.iter_tool_calls(env, model)):
            tool_name = call.get("tool_name")
            arguments = call.get("arguments")

            # --- CAPTURE (pre-execution) -----------------------------------
            result.captured_calls.append(
                CapturedCall(
                    tool_name=tool_name,
                    arguments=arguments,
                    step_index=step_index,
                    condition=env.condition,
                )
            )

            # --- EXECUTE against the MOCK (capture-without-execute) ---------
            backend = env.backends.get(tool_name)
            if backend is not None:
                args = arguments if isinstance(arguments, dict) else {"raw": arguments}
                response = backend.call(args)
                result.tool_responses.append(response)
            else:
                result.tool_responses.append(
                    {"status": 500, "error": f"no tool named {tool_name!r}"}
                )
        return result


class ScriptedRunner(BaseRunner):
    """Runner backed by a pre-recorded script of tool calls (no live model).

    ``script`` maps (task_name, condition) -> list of {tool_name, arguments}.
    A callable may be supplied instead to compute calls dynamically. This keeps
    the entire harness runnable offline and deterministically.
    """

    provider = "scripted"

    def __init__(
        self,
        script: dict[tuple[str, str], list[dict[str, Any]]] | Callable | None = None,
    ):
        self.script = script or {}

    def iter_tool_calls(self, env, model: str):
        if callable(self.script):
            calls = self.script(env, model)
        else:
            calls = self.script.get((env.task.name, env.condition), [])
        for call in calls:
            yield call
