"""Unit tests for the Asqav Claude Code hook: buffer, receipt assembly, fail-open.

Run with plain pytest from the repo root: ``pytest tests/ -q``.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
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


def test_enforcement_mode_is_observe_only_fail_open(tmp_path):
    """795: the hook is evidence, never a gate. Every event kind exits 0 and
    emits no blocking decision, and the source never uses exit code 2."""
    import pathlib
    import re

    source = pathlib.Path(SCRIPT).read_text()
    assert not re.search(r"\b_?exit\s*\(\s*2\s*[,)]", source), "blocking exit code in use"
    sid = "sess-mode-1"
    for event_name in ("PreToolUse", "PostToolUse", "Stop", "SessionEnd"):
        event = {
            "session_id": sid,
            "hook_event_name": event_name,
            "tool_name": "Write",
            "cwd": str(tmp_path),
            "tool_input": {"file_path": str(tmp_path / "a.txt"), "content": "x"},
        }
        result = run_hook(event)
        assert result.returncode == 0, event_name
        assert b"decision" not in result.stdout, event_name


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


# ---------------------------------------------------------------------------
# User-visible output (hook JSON systemMessage)
# ---------------------------------------------------------------------------


def test_stop_success_emits_system_message_json(tmp_path, monkeypatch, capsys):
    """The receipt line reaches the user via the documented systemMessage field.

    Plain stdout from a Stop hook never reaches the user, so the success
    path must print exactly one JSON object with systemMessage.
    """
    repo = git_repo(tmp_path)
    sid = "sess-sysmsg-1"
    asqav_hook.append_record(sid, {"event": "post", "command_sha256": "a" * 64, "program": "ls"})
    monkeypatch.setenv("ASQAV_API_KEY", "sk_test_fake")
    monkeypatch.setenv("ASQAV_AGENT_ID", "agt_fake")
    fake = {
        "signature_id": "sig_TESTONLY",
        "verification_url": "https://asqav.com/verify/sig_TESTONLY",
    }
    monkeypatch.setattr(asqav_hook, "sign_via_sdk", lambda *a, **k: fake)
    monkeypatch.setattr(asqav_hook, "sign_via_https", lambda *a, **k: fake)
    asqav_hook.handle_stop({"session_id": sid, "hook_event_name": "Stop", "cwd": str(repo)})
    out = capsys.readouterr().out.strip()
    payload = json.loads(out)  # entire stdout is one parseable JSON object
    assert "sig_TESTONLY" in payload["systemMessage"]
    assert "https://asqav.com/verify/sig_TESTONLY" in payload["systemMessage"]


def test_stop_without_api_key_emits_system_message(tmp_path):
    """The missing-key warning is user-visible, not only a stderr line."""
    repo = git_repo(tmp_path)
    sid = "sess-nokey-2"
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
    payload = json.loads(result.stdout)
    assert "ASQAV_API_KEY" in payload["systemMessage"]


# ---------------------------------------------------------------------------
# Buffer permissions
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_buffer_dir_and_files_are_private(tmp_path):
    """Fresh buffer dir is 0700 and buffer files are 0600 (temp dir is shared on Linux)."""
    sid = "sess-perms-1"
    asqav_hook.append_record(sid, {"event": "post", "command_sha256": "a" * 64, "program": "ls"})
    dir_mode = stat.S_IMODE(os.stat(asqav_hook.buffer_dir()).st_mode)
    file_mode = stat.S_IMODE(os.stat(asqav_hook.buffer_path(sid)).st_mode)
    assert dir_mode == 0o700
    assert file_mode == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_buffer_dir_reclaims_loose_permissions(tmp_path, monkeypatch):
    """A pre-existing world-readable buffer dir is tightened to 0700."""
    loose = tmp_path / "loose-buffers"
    loose.mkdir(mode=0o755)
    monkeypatch.setenv("ASQAV_BUFFER_DIR", str(loose))
    asqav_hook.buffer_dir()
    assert stat.S_IMODE(os.stat(loose).st_mode) == 0o700


def test_broken_sdk_falls_back_to_https(monkeypatch, capsys):
    """A broken asqav module (AttributeError) must still sign via HTTPS."""
    import json as _json

    import scripts.asqav_hook as h

    def boom(*a, **k):
        raise AttributeError("module 'asqav' has no attribute 'init'")

    captured = {}

    def fake_https(body, *, api_key, agent_id):
        captured["used"] = True
        return {"signature_id": "sig_test", "verify_url": "https://asqav.com/verify/sig_test"}

    monkeypatch.setattr(h, "sign_via_sdk", boom)
    monkeypatch.setattr(h, "sign_via_https", fake_https)
    monkeypatch.setenv("ASQAV_API_KEY", "sk_test_x")
    monkeypatch.setenv("ASQAV_AGENT_ID", "agt_x")
    h.rotate_buffer("t-fallback")
    h.handle_post_tool_use(
        {
            "session_id": "t-fallback",
            "tool_name": "Edit",
            "tool_input": {"file_path": "scripts/asqav_hook.py"},
            "tool_response": {},
        }
    )
    capsys.readouterr()
    h.handle_stop({"session_id": "t-fallback", "cwd": "."})
    out = capsys.readouterr().out
    assert captured.get("used") is True, "HTTPS fallback was not used"
    msg = _json.loads(out)
    assert "sig_test" in msg.get("systemMessage", "")


# ---------------------------------------------------------------------------
# OpenAI Codex: same hook protocol, apply_patch edits, argv shell commands
# ---------------------------------------------------------------------------

CODEX = ["--harness", "codex"]


def run_codex_hook(event: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, SCRIPT, *CODEX],
        input=json.dumps(event).encode("utf-8"),
        capture_output=True,
        env=os.environ.copy(),
        timeout=60,
    )


def test_codex_apply_patch_hashes_every_touched_file(tmp_path):
    repo = git_repo(tmp_path)
    sid = "codex-patch-1"
    patch = (
        "*** Begin Patch\n"
        "*** Update File: a.txt\n@@\n-hello\n+bye\n"
        "*** Add File: b.txt\n+new\n"
        "*** End Patch\n"
    )
    pre = {
        "session_id": sid,
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "turn_id": "t1",
        "cwd": str(repo),
        "tool_input": {"command": patch},
    }
    assert run_codex_hook(pre).returncode == 0
    (repo / "a.txt").write_text("bye\n")
    (repo / "b.txt").write_text("new\n")
    assert run_codex_hook(dict(pre, hook_event_name="PostToolUse", tool_response="ok")).returncode == 0

    summary = asqav_hook.build_session_summary(sid, asqav_hook.load_records(sid))
    files = {os.path.basename(p): v for p, v in summary["files"].items()}
    assert files["a.txt"]["pre_sha256"] == hashlib.sha256(b"hello\n").hexdigest()
    assert files["a.txt"]["post_sha256"] == hashlib.sha256(b"bye\n").hexdigest()
    assert files["b.txt"]["pre_sha256"] is None
    assert files["b.txt"]["post_sha256"] == hashlib.sha256(b"new\n").hexdigest()


def test_codex_patch_under_edit_alias_still_parsed(tmp_path):
    paths = asqav_hook.file_paths_from_input(
        "Edit", {"command": "*** Begin Patch\n*** Delete File: old.py\n*** End Patch\n"}, "/r"
    )
    assert paths == ["/r/old.py"]


def test_codex_shell_argv_is_hashed_never_stored(tmp_path):
    sid = "codex-shell-1"
    event = {
        "session_id": sid,
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": ["bash", "-lc", "curl -H 'token: s3cret' x"]},
        "tool_response": "done",
    }
    assert run_codex_hook(event).returncode == 0
    raw = open(asqav_hook.buffer_path(sid), encoding="utf-8").read()
    assert "s3cret" not in raw
    record = asqav_hook.load_records(sid)[0]
    assert record["program"] == "bash"
    assert record["command_sha256"] == asqav_hook.sha256_text("bash -lc curl -H 'token: s3cret' x")


def test_codex_receipt_names_codex_as_the_producer(tmp_path, monkeypatch):
    repo = git_repo(tmp_path)
    monkeypatch.setattr(sys, "argv", ["asqav_hook.py", *CODEX])
    summary = asqav_hook.build_session_summary("codex-wire", [{"event": "post", "file_path": "a.txt", "post_sha256": "y" * 64}])
    body = asqav_hook.build_sign_request(summary=summary, agent_id="agt_test", cwd=str(repo), session_id="codex-wire")
    assert body["authored_by"]["tool"] == "codex"
    assert body["authored_by"]["attestation_source"] == "codex-hooks"
    assert body["change_ref"] == "codex:session:codex-wire"


def test_harness_env_selects_codex(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["asqav_hook.py"])
    monkeypatch.setenv("ASQAV_HARNESS", "codex")
    assert asqav_hook.harness()["tool"] == "codex"
    monkeypatch.delenv("ASQAV_HARNESS")
    assert asqav_hook.harness()["tool"] == "claude-code"
