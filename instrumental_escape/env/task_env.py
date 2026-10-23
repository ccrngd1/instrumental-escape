"""Task environment generator.

Loads task templates (tasks.yaml) and instantiates a ``TaskEnv`` for a given
condition (blocked | control). The environment wires up the mock backends with
the condition-appropriate config so the runner has a set of capture-without-
execute tools to hand the model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..backends import make_backend

DEFAULT_TASKS_PATH = Path(__file__).resolve().parent.parent.parent / "tasks" / "tasks.yaml"

CONDITIONS = ("blocked", "control")


@dataclass
class Task:
    name: str
    prompt: str
    tool_set: list[str]
    blocked_config: dict[str, Any] = field(default_factory=dict)
    control_config: dict[str, Any] = field(default_factory=dict)

    def config_for(self, condition: str) -> dict[str, Any]:
        if condition == "blocked":
            return self.blocked_config
        if condition == "control":
            return self.control_config
        raise ValueError(f"unknown condition: {condition!r}")


@dataclass
class TaskEnv:
    """A task instantiated for one condition, with live mock backends."""

    task: Task
    condition: str
    backends: dict[str, Any]

    @property
    def prompt(self) -> str:
        return self.task.prompt

    def tools(self) -> dict[str, Any]:
        return self.backends

    def captured_calls(self) -> list[dict[str, Any]]:
        """All payloads captured by the mock backends this run, in order."""
        calls: list[dict[str, Any]] = []
        for kind, backend in self.backends.items():
            for cap in backend.captured:
                calls.append({"tool_name": kind, "arguments": cap})
        return calls


def load_tasks(path: str | Path | None = None) -> list[Task]:
    path = Path(path) if path else DEFAULT_TASKS_PATH
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    raw = data.get("tasks", []) if isinstance(data, dict) else []
    tasks: list[Task] = []
    for entry in raw:
        tasks.append(
            Task(
                name=entry["name"],
                prompt=entry["prompt"].strip(),
                tool_set=list(entry.get("tool_set", [])),
                blocked_config=entry.get("blocked_config", {}) or {},
                control_config=entry.get("control_config", {}) or {},
            )
        )
    return tasks


def get_task(name: str, path: str | Path | None = None) -> Task:
    for t in load_tasks(path):
        if t.name == name:
            return t
    raise KeyError(f"no task named {name!r}")


def build_env(task: Task, condition: str) -> TaskEnv:
    """Instantiate mock backends for a task in a given condition."""
    if condition not in CONDITIONS:
        raise ValueError(f"unknown condition: {condition!r}")
    cfg = task.config_for(condition)
    backends: dict[str, Any] = {}
    for kind in task.tool_set:
        backends[kind] = make_backend(kind, cfg.get(kind, {}))
    return TaskEnv(task=task, condition=condition, backends=backends)
