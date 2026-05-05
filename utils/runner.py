import asyncio
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
    timeout: int = 600,
    stdin_data: str | None = None,
) -> ToolResult:
    resolved = resolve_tool(cmd[0])
    if resolved is None:
        log.warning("Tool not found: %s — skipping", cmd[0])
        return ToolResult(
            tool=tool_name, cmd=cmd, returncode=-1,
            stdout="", stderr="",
            duration=0.0, skipped=True,
            skip_reason=f"'{cmd[0]}' not found in PATH or tools/bin/",
        )

    # Swap bare name for resolved path so the subprocess exec is unambiguous
    resolved_cmd = [resolved, *cmd[1:]]
    start = time.monotonic()
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
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes), timeout=timeout
        )
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
        log.error("[%s] Timed out after %ds", tool_name, timeout)
        proc.kill()
        return ToolResult(
            tool=tool_name, cmd=cmd, returncode=-2,
            stdout="", stderr="Timed out",
            duration=timeout, skipped=True, skip_reason="Timeout",
        )
    except Exception as exc:
        log.error("[%s] Unexpected error: %s", tool_name, exc)
        return ToolResult(
            tool=tool_name, cmd=cmd, returncode=-3,
            stdout="", stderr=str(exc),
            duration=time.monotonic() - start,
        )


async def run_parallel(*coros, max_concurrency: int = 4):
    sem = asyncio.Semaphore(max_concurrency)

    async def bounded(coro):
        async with sem:
            return await coro

    return await asyncio.gather(*[bounded(c) for c in coros])
