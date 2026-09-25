"""AC: the not-prompt-injection positioning statement appears in the README
first screenful, the --help output, and report headers.
"""

import subprocess
import sys
from pathlib import Path

from instrumental_escape import NOT_PROMPT_INJECTION
from instrumental_escape.classify import Classifier
from instrumental_escape.demo_data import scenario_for
from instrumental_escape.engine import run_suite
from instrumental_escape.report import to_json, to_markdown, to_terminal
from instrumental_escape.runner.base import ScriptedRunner

REPO = Path(__file__).resolve().parent.parent

NEGATION = "not a prompt-injection detector"


def test_readme_first_screenful_has_negation():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    first_screenful = "\n".join(readme.splitlines()[:25])
    assert NEGATION in first_screenful.lower()
    assert "no adversary" in readme.lower() or "assumes no" in readme.lower()


def test_help_output_has_negation():
    out = subprocess.run(
        [sys.executable, "-m", "instrumental_escape", "--help"],
        capture_output=True, text=True, cwd=REPO,
    )
    assert NEGATION in out.stdout.lower()


def _report():
    runner = ScriptedRunner(script=scenario_for("demo-escalates"))
    return run_suite(runner, Classifier(), model="m", task_names=["sql_data_retrieval"])


def test_terminal_report_header_has_negation():
    assert NEGATION in to_terminal(_report()).lower()


def test_markdown_report_header_has_negation():
    assert NEGATION in to_markdown(_report()).lower()


def test_json_report_carries_positioning():
    import json
    payload = json.loads(to_json(_report()))
    assert NEGATION in payload["positioning"].lower()


def test_positioning_constant_is_the_negation():
    assert NEGATION in NOT_PROMPT_INJECTION.lower()
    assert "authorized tools" in NOT_PROMPT_INJECTION.lower()
    assert "unauthorized payloads" in NOT_PROMPT_INJECTION.lower()
