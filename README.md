# Asqav receipts for Claude Code

Signed evidence of what your coding agent did.

This plugin watches a Claude Code session through hooks and, when the session stops, signs one Asqav `code_authorship` receipt summarizing it: which files changed (content hashes before and after), which commands ran (hashed), and the git context. The receipt is cryptographically signed, timestamped, and verifiable by anyone with the link.

Teams adopting Claude Code are being asked for an audit trail of AI-generated code. The EU AI Act's record-keeping obligations start applying to many providers on 2 August 2026, and SOC 2 auditors already ask how production code gets written. A log file you can edit is weak evidence. A signed receipt is not.

## Quickstart (about 5 minutes)

1. Create an Asqav account and an agent at [asqav.com/dashboard](https://asqav.com/dashboard), and copy an API key. The free tier covers this.

2. Export the credentials:

```bash
export ASQAV_API_KEY=sk_...
export ASQAV_AGENT_ID=agt_...
```

3. Install the plugin. Either load it directly:

```bash
git clone https://github.com/jagmarques/asqav-claude-code.git
claude --plugin-dir ./asqav-claude-code
```

or paste the hooks block from [`examples/settings-snippet.json`](examples/settings-snippet.json) into your `.claude/settings.json` (fix the script path first).

4. Run a Claude Code session inside a git repository. Edit a file, run a command, then stop the session. Claude Code shows the receipt as a system message:

```
asqav: signed code_authorship receipt sig_... verify at https://asqav.com/verify/sig_...
```

5. Open the verify URL. That page is public, so you can hand it to a reviewer or an auditor as is.

Requirements: Python 3.10+, git, and network access to `api.asqav.com`. No pip packages needed. If the `asqav` Python SDK happens to be installed, the hook signs through it, otherwise it uses the standard library.

## What gets captured

Per tool call, buffered to a local JSONL file outside your repo:

- File edits (Edit, Write, NotebookEdit): the file path and the SHA-256 of the file content before and after the change.
- Bash commands: the SHA-256 of the command line and the program name (the first token, like `pytest` or `git`). Output is recorded as a hash too.
- Session context: timestamps, working directory, git HEAD at the start of the session.

At Stop, the buffer is aggregated into one canonical summary. Its SHA-256 becomes the receipt's `change_digest`, and the summary file stays on your machine so the digest can be re-derived later. After a successful sign, the buffer rotates so the same activity is never signed twice.

## What never leaves the machine

- File contents. Only hashes travel.
- Command lines and command output. Only hashes and the program name travel. A token in a `curl` argument stays local.
- Prompts and transcripts. The plugin never reads them.

The receipt records what the hooks observed, asserted by you as the producer and signed with your agent key. Model attribution always carries `authored_by.attestation_source: "claude-code-hooks"` so nobody can read it as an Asqav-verified claim about which model wrote the code.

## Fail open, always

This hook is evidence, not a gate. Missing API key, network down, malformed input, not in a git repo: every failure path warns and exits 0. Failures at session stop (missing credentials, signing errors) also surface as a system message so you see why no receipt was signed. Your Claude Code session is never blocked because signing failed. The only network call happens once, at session stop.

## Configuration

- `ASQAV_API_KEY` (required): your Asqav API key.
- `ASQAV_AGENT_ID` (required): the agent that signs the receipt.
- `ASQAV_API_URL` (optional): API base, default `https://api.asqav.com`. Works with or without the `/api/v1` suffix.
- `ASQAV_MODEL_ID` (optional): model id to record in `authored_by`.
- `ASQAV_REPO_REF` (optional): overrides the repository reference, default is the git `origin` URL.
- `ASQAV_BUFFER_DIR` (optional): where session buffers live, default is the system temp dir.

## Compliance angle

A signed `code_authorship` receipt supports:

- EU AI Act record-keeping: a tamper-evident record of AI involvement in code changes, bound to a commit SHA and an independent timestamp.
- SOC 2 evidence collection: change-management evidence for code written with an AI agent, verifiable without trusting the machine that produced it.

Asqav receipts support these processes. They do not by themselves make a system compliant with any regulation or framework, and your counsel or auditor decides what evidence is sufficient.

## License and contact

MIT. Questions or pilot inquiries: info@asqav.com.
