"""Explicit, isolated installed-product first-delivery verification."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time

from puppetmaster.models import ArtifactType, TaskStatus
from puppetmaster.store_factory import create_store
from puppetmaster.win_process import _owned_posix_pids, stop_owned_process
from puppetmaster.win_console import effective_creationflags

_DEADLINE_SECONDS = 120
_CLEANUP_SECONDS = 3
_SCOPE = "Verifies the requested route and end-to-end delivery, not independent provider-serving identity."


@dataclass(frozen=True)
class FirstRunRequest:
    model: str


@dataclass(frozen=True)
class FirstRunResult:
    passed: bool
    reason: str
    scope: str = _SCOPE


def _payload(model: str, fixture: Path) -> dict:
    return {
        "model": model, "pinned_model": model, "auto_route": False,
        "allowed_model_ids": [model], "cwd": str(fixture.parent),
        "read_only": True, "sandbox": "read-only", "approval_policy": "never",
        "dangerously_bypass_approvals_and_sandbox": False,
        "ephemeral": True, "skip_git_repo_check": True,
        "skip_working_set_reuse": True, "disable_memory": True,
        "disable_codegraph": True, "inject_skills": False,
        "retrieved_memory": [], "injected_skills": [],
        "timeout_seconds": _DEADLINE_SECONDS,
        "max_timeout_seconds": _DEADLINE_SECONDS,
        "extra_args": ["-c", "project_doc_max_bytes=0",
                       "-c", "features.skip_host_skill_discovery=true",
                       "-c", "features.skill_search=false", "-c", "features.plugins=false",
                       "-c", "features.memories=false", "-c", "features.hooks=false",
                       "-c", "features.apps=false", "-c", "features.multi_agent=false",
                       "-c", "mcp_servers={}"],
    }


def _environment(state: Path) -> dict:
    env = dict(os.environ)
    for key in ("PUPPETMASTER_LAUNCH_KEY", "PUPPETMASTER_EFFORT_ID", "PYTHONPATH",
                "PYTHONHOME", "PUPPETMASTER_OUTPUT_STYLE_TEXT",
                "PUPPETMASTER_OUTPUT_STYLE_FILE", "PUPPETMASTER_OUTPUT_STYLE"):
        env.pop(key, None)
    env.update({"PUPPETMASTER_STATE_DIR": str(state),
                "PUPPETMASTER_WORKING_SET": "0",
                "PUPPETMASTER_JOB_BRIEF": "0",
                "PUPPETMASTER_WORKING_SET_REUSE": "0",
                "PUPPETMASTER_INJECT_HERMES_SKILLS": "0"})
    return env


def _validate(store, model: str, nonce: str, fixture: Path) -> str:
    jobs = store.list_jobs()
    if len(jobs) != 1:
        return "Expected exactly one fresh job; inspect the installed runtime."
    job = jobs[0]
    tasks = store.list_tasks(job.id)
    if len(tasks) != 1:
        return "Expected exactly one task; disable retries and reuse."
    task = tasks[0]
    payload = task.payload
    wire = str(payload.get("pinned_adapter_model_name") or "")
    identity = {"model": wire, "pinned_model": model,
                "pinned_adapter_model_name": wire, "router_model_id": model,
                "auto_route": False, "allowed_model_ids": [model]}
    if task.adapter != "codex" or any(payload.get(k) != v for k, v in identity.items()):
        return "Persisted model identity differs from the exact requested pin; check the model registry."
    if task.status != TaskStatus.COMPLETE or task.attempts != 1 or not task.completed_at:
        return "Task did not complete in one fresh attempt; check Codex authentication and runtime diagnostics."
    delivery = store.status_snapshot(job.id, compact=True).get("delivery") or {}
    if (delivery.get("verdict") != "delivered" or delivery.get("stale_task_ids")
            or delivery.get("incomplete_tasks")):
        return "Delivery was empty, degraded, blocked, or stale; inspect Codex output and retry."
    attempts = store.list_attempts(job.id)
    if (len(attempts) != 1 or attempts[0].task_id != task.id
            or attempts[0].adapter != "codex" or attempts[0].model != wire):
        return "Execution ledger does not prove one fresh attempt on the requested model."
    observations = store.list_usage_observations(job.id, attempt_id=attempts[0].attempt_id)
    if not any(o.usage_state == "measured" and type(o.tokens_in) is int
               and type(o.tokens_out) is int and o.tokens_in > 0 and o.tokens_out > 0
               for o in observations):
        return "Measured input/output usage is missing; update Codex and retry."
    artifacts = store.list_artifacts(job.id)
    verifications = [a for a in artifacts if a.type == ArtifactType.VERIFICATION
                     and a.task_id == task.id and "adapter:codex" in a.evidence]
    if not verifications or any(
        a.payload.get("result") != "passed" or a.payload.get("returncode") != 0
        or a.payload.get("model") != wire or a.payload.get("sandbox") != "read-only"
        or a.payload.get("approval_policy") != "never" or a.payload.get("turn_failed")
        or "bypass:dangerously-bypass-approvals-and-sandbox" in a.evidence
        for a in verifications
    ):
        return "Codex execution was not a successful read-only invocation of the requested model."
    findings = [a for a in artifacts if a.type == ArtifactType.FINDING and a.task_id == task.id]
    if len(findings) == 1:
        artifact = findings[0]
        try:
            artifact.validate()
        except (ValueError, TypeError):
            return "Fixture finding is invalid; retry."
        validation = artifact.payload.get("validation") or {}
        if (artifact.payload.get("claim") == f"FIRST_RUN_PROOF nonce={nonce} sum=46"
                and artifact.evidence == [str(fixture)]
                and isinstance(validation, dict)
                and validation.get("status") not in {"stale", "reused", "superseded"}):
            return ""
    return "Expected one canonical FIRST_RUN_PROOF claim with the exact nonce, sum, and file evidence; retry."


def _run_owned(command: list[str], cwd: str, env: dict, deadline: float) -> int:
    remaining = deadline - time.monotonic() - _CLEANUP_SECONDS
    if remaining <= 0:
        raise subprocess.TimeoutExpired(command, _DEADLINE_SECONDS)
    owner = secrets.token_hex(32)
    if os.name == "posix":
        # Fail before launching when the host forbids descendant discovery.
        _owned_posix_pids(owner, remaining)
    if deadline - time.monotonic() <= _CLEANUP_SECONDS:
        raise subprocess.TimeoutExpired(command, _DEADLINE_SECONDS)
    child_env = dict(env, PUPPETMASTER_PROCESS_OWNER=owner)
    options = ({"creationflags": effective_creationflags(0)} if os.name == "nt"
               else {"start_new_session": True})
    from puppetmaster.win_process import popen_owned, close_owned_process
    process = popen_owned(command, cwd=cwd, env=child_env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, **options)
    try:
        remaining = deadline - time.monotonic() - _CLEANUP_SECONDS
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, _DEADLINE_SECONDS)
        return process.wait(timeout=remaining)
    finally:
        try:
            stop_owned_process(process, owner, min(deadline, time.monotonic() + _CLEANUP_SECONDS))
        finally:
            close_owned_process(process)


def _inspect(state: str, model: str, fixture_name: str, output: str) -> None:
    """Bound SQLite reads by running them under the same outer deadline."""
    fixture = Path(fixture_name)
    nonce = fixture.read_text(encoding="utf-8").split("nonce=", 1)[1].strip()
    reason = _validate(create_store("sqlite", state), model, nonce, fixture)
    Path(output).write_text(json.dumps({"reason": reason}), encoding="utf-8")


def verify_first_run(request: FirstRunRequest) -> FirstRunResult:
    """Execute one explicit Codex probe; never install or alter host setup."""
    deadline = time.monotonic() + _DEADLINE_SECONDS
    if not isinstance(request.model, str) or not re.fullmatch(r"codex/[A-Za-z0-9][A-Za-z0-9._-]*", request.model):
        return FirstRunResult(False, "Use an exact canonical codex/<model> registry ID.")
    try:
        with tempfile.TemporaryDirectory(prefix="pm-first-run-state-") as root, \
                tempfile.TemporaryDirectory(prefix="pm-first-run-fixture-") as fixture_root:
            state = Path(root).resolve() / "state"
            fixture = Path(fixture_root).resolve() / "verification.txt"
            nonce = secrets.token_hex(32)
            fixture.write_text(f"First-run verification fixture\nleft=17\nright=29\nnonce={nonce}\n", encoding="utf-8")
            instruction = (
                f"Read {fixture}. Return exactly one structured finding. Its claim must state "
                "exactly FIRST_RUN_PROOF nonce=<nonce> sum=<sum>, replacing <nonce> with the "
                "exact nonce read from the file and <sum> with the decimal sum of left and right. "
                "Do not add any other text to the claim. "
                f"Set evidence to an array containing exactly the absolute file path {fixture}. "
                "Do not change files. Do not consult memory, skills, or CodeGraph."
            )
            config = Path(root) / "probe.json"
            config.write_text(json.dumps({"workers": [{"role": "explore", "adapter": "codex",
                "instruction": instruction, "payload": _payload(request.model, fixture)}]}), encoding="utf-8")
            # Starting outside the checkout and removing PYTHONPATH makes an
            # uninstalled checkout fail rather than masquerade as an installation.
            command = [sys.executable, "-m", "puppetmaster", "--state-dir", str(state),
                       "--backend", "sqlite", "run", "Verify first-run fixture delivery",
                       "--config", str(config), "--worker-mode", "inline", "--disable-memory",
                       "--label", "Setup first-run verification"]
            env = _environment(state)
            rc = _run_owned(command, str(fixture.parent), env, deadline)
            if not (state / "state.sqlite3").is_file():
                return FirstRunResult(False, f"Installed CLI exited {rc} without isolated SQLite state; check the Puppetmaster installation and retry.")
            output = Path(root) / "result.json"
            inspect_command = [sys.executable, "-c",
                "import sys; from puppetmaster.setup_verification import _inspect; _inspect(*sys.argv[1:])",
                str(state), request.model, str(fixture), str(output)]
            if _run_owned(inspect_command, str(fixture.parent), env, deadline) != 0:
                return FirstRunResult(False, "Could not validate persisted delivery; update the installed Puppetmaster package and retry.")
            reason = json.loads(output.read_text(encoding="utf-8"))["reason"]
            if rc != 0:
                return FirstRunResult(False, reason or f"Installed CLI exited {rc}; check Codex login, model registry, and platform lock.")
            return FirstRunResult(not reason, reason or f"First run delivered through {request.model}.")
    except subprocess.TimeoutExpired:
        return FirstRunResult(False, "120-second deadline exceeded; check Codex login/connectivity and retry.")
    except (OSError, ValueError, sqlite3.Error) as exc:
        return FirstRunResult(False, f"Verification could not finish ({type(exc).__name__}); check installation and writable temporary storage.")
