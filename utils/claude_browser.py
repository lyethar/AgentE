"""
Claude Code + Chrome bridge.

Drives the `claude` CLI headlessly from Python with the --chrome flag so the
agent can open pages, read rendered results, and return structured data. Used
by the exposure stage (Stage 7) for Google dorking, where the value is in what
a browser actually renders rather than a raw HTTP body.

All calls are best-effort: if the `claude` CLI is not installed the caller is
expected to fall back to a non-browser method or skip gracefully.
"""
import json
import logging
import re
import shutil
import subprocess

log = logging.getLogger("agente.claude_browser")


def claude_available() -> bool:
    """True if the `claude` CLI is resolvable on PATH."""
    return shutil.which("claude") is not None


def run_claude_browser_task(
    prompt: str,
    cwd: str = ".",
    permission_mode: str = "acceptEdits",
    timeout: int = 600,
    max_turns: int | None = None,
    max_budget_usd: float | None = None,
) -> dict:
    """
    Run a single Claude Code browser task and return the parsed JSON envelope.

    Mirrors the documented scripting pattern:
        claude -p <prompt> --chrome --output-format json
               --permission-mode <mode> [--max-turns N] [--max-budget-usd X]

    --permission-mode acceptEdits reduces interruptions for routine actions.
    --max-turns / --max-budget-usd bound runtime and cost when scripting.
    --output-format json yields a structured envelope including the agent's
    final answer plus cost/duration/turn metadata for auditing.

    Returns the decoded JSON object (with the agent's answer under "result"),
    or {"raw": <stdout>} if stdout was not valid JSON.

    Raises RuntimeError if the CLI is missing or exits non-zero.
    """
    if not claude_available():
        raise RuntimeError("claude CLI not found in PATH")

    cmd = [
        "claude",
        "-p", prompt,
        "--chrome",
        "--output-format", "json",
        "--permission-mode", permission_mode,
    ]
    if max_turns is not None:
        cmd += ["--max-turns", str(int(max_turns))]
    if max_budget_usd is not None:
        cmd += ["--max-budget-usd", str(max_budget_usd)]

    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Claude Code failed (exit {result.returncode}): "
            f"{(result.stderr or '').strip()[:500]}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw": result.stdout}


def result_text(envelope: dict) -> str:
    """Pull the agent's final answer text out of a --output-format json envelope."""
    if not isinstance(envelope, dict):
        return str(envelope)
    for key in ("result", "response", "text", "raw"):
        val = envelope.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return json.dumps(envelope)


def extract_json(text: str):
    """
    Best-effort extraction of a JSON array/object embedded in a model's text
    answer (it may wrap JSON in prose or ```json fences). Returns the decoded
    value, or None if nothing parseable is found.
    """
    if not text:
        return None
    # Strip code fences if present
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    candidate = fenced.group(1).strip() if fenced else text.strip()

    # Try the whole candidate first
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    # Fall back to the widest [...] or {...} span
    for open_ch, close_ch in (("[", "]"), ("{", "}")):
        start = candidate.find(open_ch)
        end = candidate.rfind(close_ch)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(candidate[start:end + 1])
            except json.JSONDecodeError:
                continue
    return None
