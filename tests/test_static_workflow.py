"""The reusable static scan is the --static-only path, not a second apktool gate."""

from __future__ import annotations

from pathlib import Path

import yaml

from maya.static.scan import FAIL_ON_LEVELS

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "maya-static-scan.yml"
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def test_reusable_workflow_installs_maya_from_its_own_commit() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = _load(WORKFLOW)
    assert "apktool" not in text
    assert "static-gate" not in text
    assert "GITHUB_WORKFLOW_REF" not in text
    assert "github.workflow_sha" not in text
    assert "github.workflow_ref" not in text
    assert "pip install ." not in text

    call = workflow["on"]["workflow_call"]["inputs"]
    assert call["apk_path"]["required"] is True
    assert call["fail_on"]["default"] == "none"
    dispatch = workflow["on"]["workflow_dispatch"]["inputs"]
    assert tuple(dispatch["fail_on"]["options"]) == FAIL_ON_LEVELS

    assert "security-events" not in workflow["permissions"]
    scan = workflow["jobs"]["scan"]
    upload = workflow["jobs"]["upload-sarif"]
    assert "security-events" not in scan["permissions"]
    assert scan["permissions"]["contents"] == "read"
    assert upload["permissions"]["security-events"] == "write"
    assert upload["needs"] == "scan"

    app = _step(scan, "Checkout the calling repository")
    assert app["with"]["repository"] == "${{ github.repository }}"
    assert app["with"]["ref"] == "${{ github.sha }}"
    assert app["with"]["persist-credentials"] is False

    maya = _step(scan, "Checkout Maya")
    assert maya["with"]["repository"] == "${{ job.workflow_repository }}"
    assert maya["with"]["ref"] == "${{ job.workflow_sha }}"
    assert maya["with"]["path"] == ".maya-src"
    assert maya["with"]["persist-credentials"] is False

    install = _step(scan, "Install Maya from this workflow's commit")["run"]
    assert "./.maya-src" in install
    command = _step(scan, "Run Maya static scan")["run"]
    assert "maya --static-only" in command
    assert "--fail-on" in command
    assert "apktool" not in command


def test_ci_calls_the_static_scan_without_failing_the_lab_apk() -> None:
    ci = _load(CI)
    assert "security-events" not in ci["permissions"]
    job = ci["jobs"]["maya-static-scan"]
    assert job["uses"] == "./.github/workflows/maya-static-scan.yml"
    assert job["with"]["apk_path"] == "dvba_v1.1.0.apk"
    assert job["with"]["fail_on"] == "none"
    assert job["permissions"]["contents"] == "read"
    assert job["permissions"]["actions"] == "write"
    assert job["permissions"]["security-events"] == "write"
    for name, other in ci["jobs"].items():
        if name == "maya-static-scan":
            continue
        assert "security-events" not in (other.get("permissions") or {})


def _step(job: dict, name: str) -> dict:
    return next(step for step in job["steps"] if step.get("name") == name)


def _load(path: Path) -> dict:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if True in loaded and "on" not in loaded:
        loaded["on"] = loaded.pop(True)
    return loaded
