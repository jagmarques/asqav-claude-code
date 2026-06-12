"""Unit tests for the Asqav Claude Code hook: buffer, receipt assembly, fail-open.

Run with plain pytest from the repo root: ``pytest tests/ -q``.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "asqav_hook.py")
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import asqav_hook  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_buffer(tmp_path, monkeypatch):
    monkeypatch.setenv("ASQAV_BUFFER_DIR", str(tmp_path / "buffers"))
    yield


def run_hook(event: dict, env_overrides: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update(env_overrides or {})
    return subprocess.run(
        [sys.executable, SCRIPT],
        input=json.dumps(event).encode("utf-8"),
        capture_output=True,
        env=env,
        timeout=60,
    )


def git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "a.txt").write_text("hello\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    return repo


# ---------------------------------------------------------------------------
# Buffer
# ---------------------------------------------------------------------------


def test_pre_and_post_buffer_file_hashes(tmp_path):
    repo = git_repo(tmp_path)
    target = repo / "a.txt"
    sid = "sess-buffer-1"
    pre = {
        "session_id": sid,
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "cwd": str(repo),
        "tool_input": {"file_path": str(target), "old_string": "hello", "new_string": "bye"},
    }
    assert run_hook(pre).returncode == 0
    target.write_text("bye\n")
    post = dict(pre, hook_event_name="PostToolUse", tool_response={"success": True})
    assert run_hook(post).returncode == 0

    records = asqav_hook.load_records(sid)
    assert len(records) == 2
    assert records[0]["pre_sha256"] == hashlib.sha256(b"hello\n").hexdigest()
    assert records[1]["post_sha256"] == hashlib.sha256(b"bye\n").hexdigest()
    assert records[0]["git_head"]


def test_bash_records_hash_never_the_command_line(tmp_path):
    sid = "sess-bash-1"
    secret_cmd = "curl -H 'Authorization: Bearer sk_live_SECRET' https://example.com"
    event = {
        "session_id": sid,
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": secret_cmd},
        "tool_response": {"stdout": "ok", "stderr": "", "exit_code": 0},
    }
    assert run_hook(event).returncode == 0
    records = asqav_hook.load_records(sid)
    assert len(records) == 1
    rec = records[0]
    assert rec["command_sha256"] == hashlib.sha256(secret_cmd.encode()).hexdigest()
    assert rec["program"] == "curl"
    raw = json.dumps(records)
    assert "SECRET" not in raw
    assert "Authorization" not in raw


# ---------------------------------------------------------------------------
# Receipt assembly
# ---------------------------------------------------------------------------


def test_sign_request_matches_code_authorship_wire_surface(tmp_path):
    repo = git_repo(tmp_path)
    sid = "sess-wire-1"
    records = [
        {"event": "pre", "file_path": "a.txt", "pre_sha256": "x" * 64, "git_head": "f" * 40},
        {"event": "post", "file_path": "a.txt", "post_sha256": "y" * 64},
        {"event": "post", "command_sha256": "z" * 64, "program": "pytest"},
    ]
    summary = asqav_hook.build_session_summary(sid, records)
    body = asqav_hook.build_sign_request(
        summary=summary, agent_id="agt_test", cwd=str(repo), session_id=sid
    )
    assert body is not None
    # Cloud guards for protectmcp:lifecycle:code_authorship (verified against
    # the live /.well-known/governance.json wire_vocabulary.guards):
    assert body["receipt_type"] == "protectmcp:lifecycle:code_authorship"
    assert body["compliance_mode"] is True
    assert body["policy_decision"] == "none"
    assert body["repo_ref"]
    assert len(body["commit_sha"]) == 40
    # change_digest wire form: sha256:<64 lowercase hex>
    assert body["change_digest"].startswith("sha256:")
    hex_part = body["change_digest"][len("sha256:"):]
    assert len(hex_part) == 64 and all(c in "0123456789abcdef" for c in hex_part)
    # hash-only compliance sign needs hash + payload_size
    assert body["hash"] == body["change_digest"]
    assert body["payload_size"] > 0
    # authored_by must carry attestation_source so the model attribution is
    # never read as Asqav-verified.
    assert body["authored_by"]["attestation_source"] == "claude-code-hooks"
    assert body["change_class"] == "write"
    # change_digest is re-derivable from the canonical summary bytes
    canonical = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()
    assert hex_part == hashlib.sha256(canonical).hexdigest()


def test_sign_request_none_outside_git_repo(tmp_path):
    bare = tmp_path / "no-repo"
    bare.mkdir()
    summary = asqav_hook.build_session_summary("s", [])
    body = asqav_hook.build_sign_request(
        summary=summary, agent_id="agt_test", cwd=str(bare), session_id="s"
    )
    assert body is None


def test_change_class_execute_for_bash_only():
    summary = asqav_hook.build_session_summary(
        "s", [{"event": "post", "command_sha256": "a" * 64, "program": "ls"}]
    )
    assert asqav_hook.change_class_for(summary) == "execute"


# ---------------------------------------------------------------------------
# Fail-open
# ---------------------------------------------------------------------------


def test_fail_open_when_api_down(tmp_path):
    """Asqav API unreachable: the Stop hook must warn and exit 0."""
    repo = git_repo(tmp_path)
    sid = "sess-failopen-1"
    pre = {
        "session_id": sid,
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "cwd": str(repo),
        "tool_input": {"file_path": str(repo / "a.txt"), "content": "x"},
        "tool_response": {"success": True},
    }
    assert run_hook(pre).returncode == 0
    stop = {"session_id": sid, "hook_event_name": "Stop", "cwd": str(repo)}
    result = run_hook(
        stop,
        {
            "ASQAV_API_KEY": "sk_test_unreachable",
            "ASQAV_AGENT_ID": "agt_unreachable",
            # Closed local port: connection refused instantly, no real call.
            "ASQAV_API_URL": "http://127.0.0.1:1",
        },
    )
    assert result.returncode == 0
    assert b"warning" in result.stderr
    assert b"session is unaffected" in result.stderr


def test_fail_open_on_garbage_stdin():
    result = subprocess.run(
        [sys.executable, SCRIPT], input=b"not json {{{", capture_output=True, timeout=30
    )
    assert result.returncode == 0
    assert b"warning" in result.stderr


def test_stop_without_api_key_warns_and_exits_zero(tmp_path):
    repo = git_repo(tmp_path)
    sid = "sess-nokey-1"
    event = {
        "session_id": sid,
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "cwd": str(repo),
        "tool_input": {"command": "echo hi"},
        "tool_response": {"stdout": "hi", "stderr": "", "exit_code": 0},
    }
    assert run_hook(event).returncode == 0
    env = {k: "" for k in ("ASQAV_API_KEY", "ASQAV_AGENT_ID")}
    result = run_hook({"session_id": sid, "hook_event_name": "Stop", "cwd": str(repo)}, env)
    assert result.returncode == 0
    assert b"ASQAV_API_KEY" in result.stderr


def test_stop_with_empty_buffer_is_silent(tmp_path):
    result = run_hook({"session_id": "sess-empty", "hook_event_name": "Stop", "cwd": str(tmp_path)})
    assert result.returncode == 0
    assert result.stderr == b""


def test_buffer_rotation_prevents_double_sign(tmp_path, monkeypatch):
    """After a successful sign the buffer rotates; a second Stop signs nothing."""
    sid = "sess-rotate-1"
    asqav_hook.append_record(sid, {"event": "post", "command_sha256": "a" * 64, "program": "ls"})
    assert asqav_hook.load_records(sid)
    asqav_hook.rotate_buffer(sid)
    assert asqav_hook.load_records(sid) == []
