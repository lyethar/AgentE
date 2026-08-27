import asyncio
import itertools
import logging
import platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

log = logging.getLogger("agente.runner")

# Local tools/bin/ directory created by install_tools.py — checked before system PATH
_LOCAL_BIN = Path(__file__).parent.parent / "tools" / "bin"
_IS_WINDOWS = platform.system() == "Windows"

# ──────────────────────────────────────────────────────────────────────────────
# Verbose per-tool execution logging
# Every external command AgentE runs is recorded so users can see exactly what
# ran, when, for how long, and with what output — and screenshot it for a report.
#   logs/commands.log        one chronological line per invocation (an index)
#   logs/tools/NNN_<tool>.log full detail: command, timestamps, rc, stdout/stderr
# The directory is configured once at startup via set_tool_log_dir().
# ──────────────────────────────────────────────────────────────────────────────
_TOOL_LOG_DIR: Path | None = None
_log_counter = itertools.count(1)


def set_tool_log_dir(path: Path | None) -> None:
    """Point per-tool execution logging at *path* (the run's logs/ dir)."""
    global _TOOL_LOG_DIR
    _TOOL_LOG_DIR = Path(path) if path else None
    if _TOOL_LOG_DIR:
        (_TOOL_LOG_DIR / "tools").mkdir(parents=True, exist_ok=True)


def _sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "tool"


def _record_invocation(result: "ToolResult", cwd: Path | None,
                       started: datetime, finished: datetime, mode: str) -> None:
    """
    Persist one command invocation to the logs directory: a full per-tool detail
    file plus a one-line entry in the chronological commands index. Never raises
    — logging must never break a scan.
    """
    if not _TOOL_LOG_DIR:
        return
    try:
        seq = next(_log_counter)
        cmd_str = " ".join(str(c) for c in result.cmd) if result.cmd else "(no command)"
        status = ("skipped" if result.skipped
                  else "success" if result.success else f"exit {result.returncode}")
        detail_name = f"{seq:04d}_{_sanitize(result.tool)}.log"
        detail_path = _TOOL_LOG_DIR / "tools" / detail_name

        lines = [
            "=" * 78,
            f"Tool        : {result.tool}",
            f"Command     : {cmd_str}",
            f"Working dir : {cwd if cwd else Path.cwd()}",
            f"Mode        : {mode}",
            f"Started     : {started.isoformat(timespec='seconds')}",
            f"Finished    : {finished.isoformat(timespec='seconds')}",
            f"Duration    : {result.duration:.1f}s",
            f"Return code : {result.returncode}",
            f"Status      : {status}",
        ]
        if result.skip_reason:
            lines.append(f"Skip reason : {result.skip_reason}")
        lines.append("=" * 78)
        lines.append("")
        lines.append("----- STDOUT -----")
        lines.append(result.stdout if result.stdout else "(none captured)")
        lines.append("")
        lines.append("----- STDERR -----")
        lines.append(result.stderr if result.stderr else "(none captured)")
        lines.append("")
        detail_path.write_text("\n".join(lines), encoding="utf-8")

        cwd_label = Path(cwd).name if cwd else ""
        index_line = (
            f"{started.isoformat(timespec='seconds')}  "
            f"{result.tool:<18} rc={result.returncode:<4} "
            f"{result.duration:6.1f}s  {status:<10} "
            f"cwd={cwd_label:<16} ::  {cmd_str}  ->  tools/{detail_name}\n"
        )
        with open(_TOOL_LOG_DIR / "commands.log", "a", encoding="utf-8") as fh:
            fh.write(index_line)
    except Exception as exc:  # pragma: no cover - logging must not break a scan
        log.debug("Could not record invocation for %s: %s", result.tool, exc)

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
    interactive: bool = False,
) -> ToolResult:
    """
    Run an external tool to completion.

    timeout: seconds to wait before killing the process. None (the default), 0,
    or any non-positive value means *no timeout* — the tool runs until it exits
    on its own. This is what lets long-running tools (bbot, cloud_enum, …) finish
    before the next stage starts; the progress_monitor keeps them observable.

    interactive: when True, the child inherits the terminal's stdin/stdout/stderr
    instead of piped output. Use this for tools that prompt for user input or
    whose live output must be visible (e.g. linkedin2username's browser-login
    flow). Output is not captured, so ToolResult.stdout/stderr stay empty.
    """
    resolved = resolve_tool(cmd[0])
    if resolved is None:
        log.warning("Tool not found: %s — skipping", cmd[0])
        now = datetime.now()
        result = ToolResult(
            tool=tool_name, cmd=cmd, returncode=-1,
            stdout="", stderr="",
            duration=0.0, skipped=True,
            skip_reason=f"'{cmd[0]}' not found in PATH or tools/bin/",
        )
        _record_invocation(result, cwd, now, now, "not found")
        return result

    use_timeout = timeout is not None and timeout > 0

    # Swap bare name for resolved path so the subprocess exec is unambiguous
    resolved_cmd = [resolved, *cmd[1:]]
    start = time.monotonic()
    started_dt = datetime.now()
    token = _register_tool(tool_name)
    mode = ("interactive, no timeout" if interactive and not use_timeout
            else "interactive" if interactive
            else f"timeout {timeout}s" if use_timeout else "no timeout")
    # Echo the full command into agente.log so the main log shows exactly what ran.
    log.info("[%s] Started (%s): %s", tool_name, mode, " ".join(str(c) for c in cmd))
    proc = None
    try:
        if interactive:
            # Inherit the terminal (no PIPE) so prompts and live output are
            # visible to the user and stdin can be answered. Output isn't captured.
            proc = await asyncio.create_subprocess_exec(
                *[str(c) for c in resolved_cmd],
                cwd=str(cwd) if cwd else None,
                env=env,
            )
            if use_timeout:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            else:
                await proc.wait()
            duration = time.monotonic() - start
            result = ToolResult(
                tool=tool_name, cmd=cmd, returncode=proc.returncode,
                stdout="", stderr="", duration=duration,
            )
        else:
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
        _record_invocation(result, cwd, started_dt, datetime.now(), mode)
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
        result = ToolResult(
            tool=tool_name, cmd=cmd, returncode=-2,
            stdout="", stderr="Timed out",
            duration=time.monotonic() - start, skipped=True,
            skip_reason=f"Timeout after {timeout}s",
        )
        _record_invocation(result, cwd, started_dt, datetime.now(), mode)
        return result
    except Exception as exc:
        log.error("[%s] Unexpected error: %s", tool_name, exc)
        result = ToolResult(
            tool=tool_name, cmd=cmd, returncode=-3,
            stdout="", stderr=str(exc),
            duration=time.monotonic() - start,
        )
        _record_invocation(result, cwd, started_dt, datetime.now(), mode)
        return result
    finally:
        _deregister_tool(token)


def spawn_detached(
    cmd: list[str],
    tool_name: str,
    cwd: Path | None = None,
    env: dict | None = None,
    log_file: Path | None = None,
) -> dict:
    """
    Launch a long-lived background service and return WITHOUT waiting for it.

    Used for processes that are meant to keep running after the pipeline moves
    on — e.g. ``gowitness report server``, which serves a web UI indefinitely.
    The child is fully detached so it is never killed when AgentE exits, and its
    output is redirected to *log_file* (or discarded) so it does not clutter the
    console. Returns a dict describing the launch (never raises).
    """
    resolved = resolve_tool(cmd[0])
    if resolved is None:
        log.warning("Service not found: %s — not started", cmd[0])
        return {"tool": tool_name, "started": False, "pid": None,
                "reason": f"'{cmd[0]}' not found in PATH or tools/bin/"}

    resolved_cmd = [str(resolved), *[str(c) for c in cmd[1:]]]
    out = open(log_file, "ab") if log_file else subprocess.DEVNULL

    # Detach from the parent process group so the service survives our exit.
    kwargs: dict = {"cwd": str(cwd) if cwd else None, "env": env,
                    "stdout": out, "stderr": out,
                    "stdin": subprocess.DEVNULL}
    if _IS_WINDOWS:
        kwargs["creationflags"] = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )
    else:
        kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(resolved_cmd, **kwargs)  # noqa: S603
    except Exception as exc:
        log.warning("[%s] Failed to launch background service: %s", tool_name, exc)
        return {"tool": tool_name, "started": False, "pid": None, "reason": str(exc)}
    finally:
        if log_file and out not in (subprocess.DEVNULL,):
            try:
                out.close()
            except Exception:
                pass

    log.info("[%s] Background service started (pid=%s) — left running", tool_name, proc.pid)
    return {"tool": tool_name, "started": True, "pid": proc.pid, "reason": ""}


async def run_parallel(*coros, max_concurrency: int = 4):
    sem = asyncio.Semaphore(max_concurrency)

    async def bounded(coro):
        async with sem:
            return await coro

    return await asyncio.gather(*[bounded(c) for c in coros])
