"""The Rego policy and the Python policy must give the same decision for the same request.

Runs only where the `opa` binary is installed (CI installs it). Both policies are evaluated
over a grid of requests; any difference fails the test. This is how the 60-69 risk gap
between the two was found on 2026-11-22.
"""
import itertools
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app import gateway as gateway_module
from app.data_inspector import inspect_outbound
from app.domain import ActionRequest
from app.gateway import ToolGateway
from app.opa_client import build_input

OPA = shutil.which("opa")
POLICY_DIR = Path(__file__).resolve().parents[2] / "policy" / "opa"

pytestmark = pytest.mark.skipif(OPA is None, reason="opa binary not installed")

RISKS = [0, 30, 45, 55, 59, 60, 65, 69, 70, 75, 79, 80, 90]
CLASSES = ["public", "pii", "secret"]
ACTIONS = ["send_email", "export_data"]
TARGETS = ["https://api.example.com", "external-crm", "http://legacy.example.com"]
# an email address is a low-severity finding (no approval by itself); a password is high-severity
CONTENTS = [None, "contact me at someone@example.com", "password: hunter2"]


def cases():
    for risk, cls, action, target, content in itertools.product(RISKS, CLASSES, ACTIONS, TARGETS, CONTENTS):
        yield ActionRequest(agent_id="agent", action=action, target=target,
                            data_classification=cls, risk_score=risk, content=content)


def test_rego_and_python_policies_agree(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway_module.settings, "opa_url", None)
    requests = list(cases())

    python_decisions = [ToolGateway._evaluate(r)[0].decision.value for r in requests]
    # the gateway passes only blocking (high-severity) findings to the policy, so the parity test does too
    inputs = [build_input(r, inspect_outbound(r.content, r.execution_payload)["blocking"]) for r in requests]

    (tmp_path / "cases.json").write_text(json.dumps({"cases": inputs}))
    (tmp_path / "parity.rego").write_text(
        "package parity\n\nimport rego.v1\n\n"
        "results := [d | some c in data.cases; d := data.agentguard.decision with input as c]\n"
    )
    out = subprocess.run(
        [OPA, "eval", "--format", "json", "-d", str(POLICY_DIR), "-d", str(tmp_path / "parity.rego"),
         "-d", str(tmp_path / "cases.json"), "data.parity.results"],
        capture_output=True, text=True, check=True,
    )
    rego_decisions = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]

    mismatches = [
        (r.risk_score, r.data_classification, r.action, r.target, bool(r.content), py, rg)
        for r, py, rg in zip(requests, python_decisions, rego_decisions, strict=True)
        if py != rg
    ]
    assert not mismatches, f"{len(mismatches)} mismatches, first: {mismatches[:5]}"
