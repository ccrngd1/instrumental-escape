"""Orchestration: run a task in both conditions, classify, and score.

This ties the pieces together without any provider coupling: given a runner, a
classifier, and a task, it runs the blocked and control conditions, classifies
the captured tool calls, and returns a ``TaskReport``. Because classification
consumes the *captured* calls (not the mock responses), it is identical whether
the calls came from a live adapter or a scripted replay.
"""

from __future__ import annotations

from .classify import Classifier
from .env.task_env import Task, build_env, get_task, load_tasks
from .report import ConditionResult, RunReport, TaskReport
from .runner.base import BaseRunner


def run_condition(runner: BaseRunner, task: Task, condition: str, classifier: Classifier,
                  model: str) -> ConditionResult:
    env = build_env(task, condition)
    result = runner.run(env, model)
    classifications = classifier.classify_calls(result.as_call_dicts())
    return ConditionResult(condition=condition, classifications=classifications)


def run_task(runner: BaseRunner, task: Task, classifier: Classifier, model: str,
             conditions: tuple[str, ...] = ("blocked", "control")) -> TaskReport:
    """Run a task in the requested conditions and build its report.

    Even when only one condition is requested, both slots are present in the
    report (the un-run one is empty) so the delta math stays well-defined.
    """
    blocked = ConditionResult(condition="blocked")
    control = ConditionResult(condition="control")
    for condition in conditions:
        res = run_condition(runner, task, condition, classifier, model)
        if condition == "blocked":
            blocked = res
        elif condition == "control":
            control = res
    return TaskReport(task_name=task.name, model=model, blocked=blocked, control=control)


def run_suite(runner: BaseRunner, classifier: Classifier, model: str, threshold: int = 0,
              task_names: list[str] | None = None, tasks_path=None,
              conditions: tuple[str, ...] = ("blocked", "control")) -> RunReport:
    """Run one or more tasks and assemble the full run report."""
    all_tasks = load_tasks(tasks_path)
    if task_names:
        wanted = set(task_names)
        selected = [t for t in all_tasks if t.name in wanted]
    else:
        selected = all_tasks

    report = RunReport(model=model, threshold=threshold)
    for task in selected:
        report.task_reports.append(
            run_task(runner, task, classifier, model, conditions=conditions)
        )
    return report
