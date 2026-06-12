#!/usr/bin/env python3
"""Asqav receipts for Claude Code.

One script handles every hook event. Claude Code pipes the hook event JSON
on stdin; the script dispatches on ``hook_event_name``:

- ``PreToolUse`` (Edit/Write/NotebookEdit): hash the file's pre-state.
- ``PostToolUse`` (Edit/Write/NotebookEdit/Bash): hash the file's post-state,
  or the Bash command and its response.
- ``Stop`` / ``SessionEnd``: aggregate the buffered tool activity and sign one
  Asqav ``protectmcp:lifecycle:code_authorship`` receipt for it, then rotate
  the buffer so nothing is ever signed twice.

Honest scope: the receipt binds what the hooks observed (file paths, content
hashes, command hashes, the git HEAD before and after) plus the Asqav agent
key. Everything is producer-asserted and recorded, never verified by Asqav.
Model authorship is always sent under
``authored_by.attestation_source="claude-code-hooks"`` so it can never be
read as an Asqav-verified attribution.

Privacy: the buffer stores SHA-256 hashes, file paths, and the first token of
Bash commands (the program name). It never stores file contents, full command
lines, or command output, so secrets in either never leave the machine.

FAIL OPEN: this hook is evidence, not a gate. Any failure (no API key, API
down, malformed input) prints a one-line warning and exits 0 so the Claude
Code session is never blocked. Exit code 2 (the blocking code) is never used.

User-facing output uses the documented hook JSON ``systemMessage`` field:
plain stdout from a Stop hook on exit 0 goes to Claude and the debug log,
never to the user, so the receipt line and Stop-time warnings are emitted
as ``{"systemMessage": ...}`` on stdout.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

__version__ = "0.1.0"

RECEIPT_TYPE = "protectmcp:lifecycle:code_authorship"
ACTION_TYPE = "code:authorship"
ATTESTATION_SOURCE = "claude-code-hooks"
# The api.asqav.com edge rejects bare Python-urllib UAs (Cloudflare error
# 1010), so identify with a real product token like the asqav SDK does.
USER_AGENT = f"asqav-claude-code/{__version__} (+https://www.asqav.com)"
DEFAULT_API_URL = "https://api.asqav.com"

FILE_TOOLS = {"Edit", "MultiEdit", "Write", "NotebookEdit"}
_SESSION_ID_SAFE = re.compile(r"[^A-Za-z0-9_-]")


# ---------------------------------------------------------------------------
# Buffer
# ---------------------------------------------------------------------------


def buffer_dir() -> str:
    """Session buffers live OUTSIDE the project tree (never committed).

    The directory is owner-only (0700): on Linux the system temp dir is
    shared, so a 0755 directory would expose file paths and program names
    to every local user. The chmod also reclaims a directory left behind
    by an earlier version with looser permissions.
    """
    base = os.environ.get("ASQAV_BUFFER_DIR") or os.path.join(
        tempfile.gettempdir(), "asqav-claude-code"
    )
    os.makedirs(base, mode=0o700, exist_ok=True)
    if os.name == "posix":
        os.chmod(base, 0o700)
    return base


def open_private(path: str, *, append: bool = False):
    """Open ``path`` for writing with owner-only permissions (0600).

    ``os.open`` applies the mode at creation, before any bytes land, so the
    file is never observable with broader permissions. The mode argument is
    a no-op on Windows, which has no POSIX permission bits.
    """
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "a" if append else "w", encoding="utf-8")


def buffer_path(session_id: str) -> str:
    safe = _SESSION_ID_SAFE.sub("_", session_id or "unknown")[:80]
    return os.path.join(buffer_dir(), f"session_{safe}.jsonl")


def append_record(session_id: str, record: dict[str, Any]) -> None:
    with open_private(buffer_path(session_id), append=True) as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def load_records(session_id: str) -> list[dict[str, Any]]:
    path = buffer_path(session_id)
    if not os.path.exists(path):
        return []
    records: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    return records


def rotate_buffer(session_id: str) -> None:
    """Mark the buffer signed so a later Stop never signs the same activity twice."""
    path = buffer_path(session_id)
    if os.path.exists(path):
        os.replace(path, f"{path}.signed-{int(time.time())}")


# ---------------------------------------------------------------------------
# Hashing and git facts
# ---------------------------------------------------------------------------


def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _git(cwd: str, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", cwd, *args],
            capture_output=True,
            timeout=10,
            check=True,
        )
        value = out.stdout.decode("utf-8", errors="replace").strip()
        return value or None
    except (OSError, subprocess.SubprocessError):
        return None


def git_head(cwd: str) -> str | None:
    return _git(cwd, "rev-parse", "HEAD")


def repo_ref(cwd: str) -> str | None:
    ref = os.environ.get("ASQAV_REPO_REF") or _git(cwd, "remote", "get-url", "origin")
    if not ref:
        toplevel = _git(cwd, "rev-parse", "--show-toplevel")
        ref = toplevel
    return ref[:256] if ref else None


def file_path_from_input(tool_name: str, tool_input: dict[str, Any]) -> str | None:
    if tool_name == "NotebookEdit":
        return tool_input.get("notebook_path") or tool_input.get("file_path")
    return tool_input.get("file_path")


# ---------------------------------------------------------------------------
# User-visible output
# ---------------------------------------------------------------------------


def emit_system_message(message: str) -> None:
    """Show ``message`` to the user via the documented hook JSON output.

    Plain stdout from a Stop hook on exit 0 is shown to Claude and written
    to the debug log, never to the user. The ``systemMessage`` field of the
    hook JSON output is the documented way to put a line in front of the
    user, so anything they must see goes through here.
    """
    print(json.dumps({"systemMessage": message}))


def warn_user(message: str) -> None:
    """Warn on stderr (debug log) and as a user-visible system message."""
    line = f"asqav: warning: {message}"
    print(line, file=sys.stderr)
    emit_system_message(line)


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------


def handle_pre_tool_use(event: dict[str, Any]) -> None:
    tool_name = event.get("tool_name", "")
    if tool_name not in FILE_TOOLS:
        return
    tool_input = event.get("tool_input") or {}
    path = file_path_from_input(tool_name, tool_input)
    if not path:
        return
    append_record(
        event.get("session_id", ""),
        {
            "ts": time.time(),
            "event": "pre",
            "tool_name": tool_name,
            "file_path": path,
            "pre_sha256": sha256_file(path),
            "cwd": event.get("cwd"),
            "git_head": git_head(event.get("cwd") or os.getcwd()),
        },
    )


def handle_post_tool_use(event: dict[str, Any]) -> None:
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    session_id = event.get("session_id", "")
    record: dict[str, Any] = {
        "ts": time.time(),
        "event": "post",
        "tool_name": tool_name,
        "cwd": event.get("cwd"),
    }
    if tool_name in FILE_TOOLS:
        path = file_path_from_input(tool_name, tool_input)
        if not path:
            return
        record["file_path"] = path
        record["post_sha256"] = sha256_file(path)
    elif tool_name == "Bash":
        command = tool_input.get("command") or ""
        # Never store the command line itself: only its hash and the program
        # name (first token), so secrets in arguments stay on the machine.
        record["command_sha256"] = sha256_text(command)
        record["program"] = command.strip().split(" ", 1)[0][:64] if command.strip() else ""
        response = event.get("tool_response")
        if response is not None:
            record["response_sha256"] = sha256_text(
                json.dumps(response, sort_keys=True, default=str)
            )
    else:
        return
    append_record(session_id, record)


def build_session_summary(
    session_id: str, records: list[dict[str, Any]]
) -> dict[str, Any]:
    """Aggregate buffered records into the canonical session summary.

    The summary is the producer-declared canonical representation of the
    session's change set; ``change_digest`` is the SHA-256 over its canonical
    JSON bytes, so anyone holding the summary file can re-derive the digest.
    """
    files: dict[str, dict[str, Any]] = {}
    bash_calls: list[dict[str, Any]] = []
    for rec in records:
        path = rec.get("file_path")
        if path:
            entry = files.setdefault(path, {"pre_sha256": None, "post_sha256": None})
            if rec.get("event") == "pre" and entry["pre_sha256"] is None:
                entry["pre_sha256"] = rec.get("pre_sha256")
            if rec.get("event") == "post" and rec.get("post_sha256") is not None:
                entry["post_sha256"] = rec.get("post_sha256")
        elif rec.get("command_sha256"):
            bash_calls.append(
                {
                    "command_sha256": rec["command_sha256"],
                    "program": rec.get("program", ""),
                    "response_sha256": rec.get("response_sha256"),
                }
            )
    return {
        "producer": USER_AGENT,
        "session_id": session_id,
        "files": files,
        "bash_calls": bash_calls,
        "tool_call_count": len(records),
    }


def change_class_for(summary: dict[str, Any]) -> str:
    if summary["files"]:
        return "write"
    if summary["bash_calls"]:
        return "execute"
    return "read"


def build_sign_request(
    *,
    summary: dict[str, Any],
    agent_id: str,
    cwd: str,
    session_id: str,
) -> dict[str, Any] | None:
    """Build the SignRequest body for the code_authorship receipt.

    Returns None when the required git facts (repo_ref + commit_sha) are
    unavailable; the cloud requires both on this receipt type.
    """
    head = git_head(cwd)
    ref = repo_ref(cwd)
    if not head or not ref:
        return None
    canonical = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    authored_by: dict[str, Any] = {
        "agent_id": agent_id,
        "tool": "claude-code",
        "attestation_source": ATTESTATION_SOURCE,
    }
    model_id = os.environ.get("ASQAV_MODEL_ID")
    if model_id:
        authored_by["model_id"] = model_id
    body: dict[str, Any] = {
        "action_type": ACTION_TYPE,
        "hash": f"sha256:{digest}",
        "hash_algo": "sha256",
        "payload_size": len(canonical),
        "metadata": {
            "agent_id": agent_id,
            "action_type": ACTION_TYPE,
            "session_id": session_id,
        },
        "session_id": session_id,
        "receipt_type": RECEIPT_TYPE,
        "compliance_mode": True,
        "policy_decision": "none",
        "repo_ref": ref,
        "commit_sha": head,
        "change_digest": f"sha256:{digest}",
        "change_ref": f"claude-code:session:{session_id}"[:256],
        "change_class": change_class_for(summary),
        "authored_by": authored_by,
    }
    return body


def _base_sha_from_records(records: list[dict[str, Any]]) -> str | None:
    for rec in records:
        head = rec.get("git_head")
        if head:
            return head
    return None


def api_base() -> str:
    base = (os.environ.get("ASQAV_API_URL") or DEFAULT_API_URL).rstrip("/")
    if not base.endswith("/api/v1"):
        base = f"{base}/api/v1"
    return base


def sign_via_https(body: dict[str, Any], *, api_key: str, agent_id: str) -> dict[str, Any]:
    """Raw HTTPS fallback when the asqav SDK is not installed (stdlib only)."""
    url = f"{api_base()}/agents/{agent_id}/sign"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def sign_via_sdk(body: dict[str, Any], *, api_key: str, agent_id: str) -> dict[str, Any]:
    """Sign through the asqav Python SDK when it is importable.

    base_url is passed explicitly: the SDK reads ASQAV_API_URL as a full base
    that already includes /api/v1, while this plugin documents the bare-host
    form (https://api.asqav.com). api_base() normalizes both.
    """
    import asqav

    asqav.init(api_key=api_key, base_url=api_base())
    agent = asqav.Agent.get(agent_id)
    response = agent.sign(
        body["action_type"],
        context={"change_digest": body["change_digest"], "session_id": body["session_id"]},
        receipt_type=RECEIPT_TYPE,
        compliance_mode=True,
        policy_decision="none",
        repo_ref=body["repo_ref"],
        commit_sha=body["commit_sha"],
        base_sha=body.get("base_sha"),
        change_digest=body["change_digest"],
        change_ref=body.get("change_ref"),
        change_class=body["change_class"],
        authored_by=body["authored_by"],
    )
    return {
        "signature_id": response.signature_id,
        "verification_url": response.verification_url,
    }


def handle_stop(event: dict[str, Any]) -> None:
    session_id = event.get("session_id", "")
    records = load_records(session_id)
    if not records:
        return  # nothing buffered, nothing to sign
    api_key = os.environ.get("ASQAV_API_KEY")
    if not api_key:
        warn_user("ASQAV_API_KEY not set; session activity buffered, no receipt signed.")
        return
    agent_id = os.environ.get("ASQAV_AGENT_ID")
    if not agent_id:
        warn_user(
            "ASQAV_AGENT_ID not set; create an agent at "
            "https://www.asqav.com/dashboard (or POST /api/v1/agents/create) "
            "and export it."
        )
        return
    cwd = event.get("cwd") or os.getcwd()
    summary = build_session_summary(session_id, records)
    body = build_sign_request(
        summary=summary, agent_id=agent_id, cwd=cwd, session_id=session_id
    )
    if body is None:
        warn_user(
            "not inside a git repository (repo_ref/commit_sha "
            "unavailable); no code_authorship receipt signed."
        )
        return
    base = _base_sha_from_records(records)
    if base and base != body["commit_sha"]:
        body["base_sha"] = base

    # Persist the canonical summary next to the buffer so the change_digest
    # stays re-derivable after signing.
    summary_path = buffer_path(session_id).replace(".jsonl", ".summary.json")
    with open_private(summary_path) as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)

    try:
        try:
            import asqav  # noqa: F401

            result = sign_via_sdk(body, api_key=api_key, agent_id=agent_id)
        except Exception:  # noqa: BLE001 - any broken or partial SDK install
            # The stdlib HTTPS path covers a missing, old, or broken asqav module.
            result = sign_via_https(body, api_key=api_key, agent_id=agent_id)
    except Exception as exc:  # noqa: BLE001 - fail open, never block the session
        detail = ""
        if isinstance(exc, urllib.error.HTTPError):
            try:
                detail = f" {exc.read().decode('utf-8', errors='replace')[:200]}"
            except Exception:  # noqa: BLE001
                detail = ""
        warn_user(
            f"receipt signing failed ({exc}{detail}); your session is unaffected."
        )
        return

    rotate_buffer(session_id)
    receipt_path = buffer_path(session_id).replace(".jsonl", ".receipt.json")
    with open_private(receipt_path) as fh:
        json.dump(result, fh, indent=2, sort_keys=True, default=str)
    sig_id = result.get("signature_id", "")
    verify_url = result.get("verification_url", "")
    message = f"asqav: signed code_authorship receipt {sig_id}"
    if verify_url:
        message += f" verify at {verify_url}"
    emit_system_message(message)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


HANDLERS = {
    "PreToolUse": handle_pre_tool_use,
    "PostToolUse": handle_post_tool_use,
    "Stop": handle_stop,
    "SessionEnd": handle_stop,
}


def main() -> int:
    """Always returns 0: the receipt is evidence, not a gate."""
    try:
        raw = sys.stdin.read()
        event = json.loads(raw)
        handler = HANDLERS.get(event.get("hook_event_name", ""))
        if handler is not None:
            handler(event)
    except Exception as exc:  # noqa: BLE001 - fail open by contract
        print(f"asqav: warning: hook error ({exc}); your session is unaffected.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
