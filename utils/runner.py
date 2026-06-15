import asyncio
import itertools
import logging
import platform
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("agente.runner")

# Local tools/bin/ directory created by install_tools.py — checked before system PATH
_LOCAL_BIN = Path(__file__).parent.parent / "tools" / "bin"
_IS_WINDOWS = platform.system() == "Windows"

# ──────────────────────────────────────────────────────────────────────────────
# Per-tool progress tracking
# A registry of tools currently executing, so the orchestrator can report what is
# still running. The event loop is single-threaded, so a plain dict is safe.
# ──────────────────────────────────────────────────────────────────────────────
_active_tools: dict[int, dict] = {}
_tool_counter = itertools.count(1)


def _register_tool(tool_name: str) -> int:
    token = next(_tool_counter)
    _active_tools[token] = {"tool": tool_name, "start": time.monotonic()}
    return token


def _deregister_tool(token: int) -> None:
    _active_tools.pop(token, None)


def active_tools() -> list[tuple[str, float]]:
    """List of (tool_name, elapsed_seconds) for every tool currently running."""
    now = time.monotonic()
    return [(info["tool"], now - info["start"]) for info in _active_tools.values()]


async def progress_monitor(interval: float = 30.0) -> None:
    """
    Background heartbeat: every `interval` seconds, log which tools are still
    executing and for how long. Runs until cancelled. Because tools can run
    without a timeout, this is how long-running tools (bbot, cloud_enum, …)
    stay observable instead of being silently killed.
    """
    if interval <= 0:
        return
    try:
        while True:
            await asyncio.sleep(interval)
            running = active_tools()
            if running:
                summary = ", ".join(
                    f"{name} ({elapsed:.0f}s)"
                    for name, elapsed in sorted(running, key=lambda x: -x[1])
                )
                log.info("[progress] %d tool(s) running: %s", len(running), summary)
    except asyncio.CancelledError:
        return


@dataclass
class ToolResult:
    tool:       str
    cmd:        list[str]
    returncode: int
    stdout:     str
    stderr:     str
    duration:   float
    success:    bool = field(init=False)
    skipped:    bool = False
    skip_reason: str = ""

    def __post_init__(self):
        self.success = self.returncode == 0 and not self.skipped


def resolve_tool(name: str) -> str | None:
    """
    Return the executable path for *name*, checking tools/bin/ before system PATH.
    On Windows the .bat wrapper takes priority.
    """
    if _IS_WINDOWS:
        for ext in (".bat", ".cmd", ""):
            candidate = _LOCAL_BIN / f"{name}{ext}"
            if candidate.exists():
                return str(candidate)
    else:
        candidate = _LOCAL_BIN / name
        if candidate.exists():
            return str(candidate)
    return shutil.which(name)


def check_tool(name: str) -> bool:
    return resolve_tool(name) is not None


async def run_tool(
    cmd: list[str],
    tool_name: str,
    cwd: Path | None = None,
    env: dict | None = None,
    timeout: int | None = None,
    stdin_data: str | None = None,
) -> ToolResult:
    """
    Run an external tool to completion.

    timeout: seconds to wait before killing the process. None (the default), 0,
    or any non-positive value means *no timeout* — the tool runs until it exits
    on its own. This is what lets long-running tools (bbot, cloud_enum, …) finish
    before the next stage starts; the progress_monitor keeps them observable.
    """
    resolved = resolve_tool(cmd[0])
    if resolved is None:
        log.warning("Tool not found: %s — skipping", cmd[0])
        return ToolResult(
            tool=tool_name, cmd=cmd, returncode=-1,
            stdout="", stderr="",
            duration=0.0, skipped=True,
            skip_reason=f"'{cmd[0]}' not found in PATH or tools/bin/",
        )

    use_timeout = timeout is not None and timeout > 0

    # Swap bare name for resolved path so the subprocess exec is unambiguous
    resolved_cmd = [resolved, *cmd[1:]]
    start = time.monotonic()
    token = _register_tool(tool_name)
    log.info("[%s] Started (%s)", tool_name,
             f"timeout {timeout}s" if use_timeout else "no timeout")
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *[str(c) for c in resolved_cmd],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data else None,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
        stdin_bytes = stdin_data.encode() if stdin_data else None
        if use_timeout:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes), timeout=timeout
            )
        else:
            # No timeout — wait for the process to finish on its own.
            stdout_b, stderr_b = await proc.communicate(input=stdin_bytes)
        duration = time.monotonic() - start
        result = ToolResult(
            tool=tool_name, cmd=cmd,
            returncode=proc.returncode,
            stdout=stdout_b.decode("utf-8", errors="replace"),
            stderr=stderr_b.decode("utf-8", errors="replace"),
            duration=duration,
        )
        if result.success:
            log.info("[%s] Finished in %.1fs", tool_name, duration)
        else:
            log.warning("[%s] Exited %d in %.1fs", tool_name, proc.returncode, duration)
        return result
    except asyncio.TimeoutError:
        log.error("[%s] Timed out after %ds — killing process", tool_name, timeout)
        if proc is not None:
            proc.kill()
            # Reap the killed process so it doesn't linger as a zombie
            try:
                await proc.communicate()
            except Exception:
                pass
        return ToolResult(
            tool=tool_name, cmd=cmd, returncode=-2,
            stdout="", stderr="Timed out",
            duration=time.monotonic() - start, skipped=True,
            skip_reason=f"Timeout after {timeout}s",
        )
    except Exception as exc:
        log.error("[%s] Unexpected error: %s", tool_name, exc)
        return ToolResult(
            tool=tool_name, cmd=cmd, returncode=-3,
            stdout="", stderr=str(exc),
            duration=time.monotonic() - start,
        )
    finally:
        _deregister_tool(token)


async def run_parallel(*coros, max_concurrency: int = 4):
    sem = asyncio.Semaphore(max_concurrency)

    async def bounded(coro):
        async with sem:
            return await coro

    return await asyncio.gather(*[bounded(c) for c in coros])
