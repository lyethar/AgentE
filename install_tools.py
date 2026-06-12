#!/usr/bin/env python3
"""
AgentE Tool Installer
Clones, installs, and wires up tools that live on GitHub rather than PyPI/Go.

Usage:
  python install_tools.py                     # install all managed tools
  python install_tools.py pycroburst          # install one tool
  python install_tools.py pycroburst l2u      # install by name or alias
  python install_tools.py --list              # show managed tools and status
  python install_tools.py --reinstall         # force re-clone even if present
"""
import argparse
import os
import platform
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).parent.resolve()
TOOLS_DIR    = PROJECT_ROOT / "tools"
BIN_DIR      = TOOLS_DIR / "bin"
IS_WINDOWS   = platform.system() == "Windows"

# ──────────────────────────────────────────────────────────────────────────────
# Tool Definitions
# Each entry describes one manageable tool.
#
# entry_point: path *relative to the cloned repo root* that gets invoked.
#   If a list is given, a wrapper is created for each (name -> first entry,
#   extra aliases for the rest).
# wrapper_name: the binary name callers use (e.g. "pycroburst").
# aliases: short names accepted on the CLI of this installer.
# ──────────────────────────────────────────────────────────────────────────────
MANAGED_TOOLS: list[dict] = [
    {
        "name":         "pycroburst",
        "aliases":      ["pcb", "pycroburst"],
        "repo":         "https://github.com/NetSPI/PycroBurst",
        "clone_dir":    "pycroburst",
        # Two runnable scripts inside the repo
        "entry_points": [
            {"wrapper": "pycroburst",            "script": "enumerateAzureBlobs.py"},
            {"wrapper": "pycroburst-subdomains",  "script": "enumerateAzureSubDomains.py"},
        ],
        "description":  "Azure blob storage & subdomain enumerator (NetSPI)",
    },
    {
        "name":         "linkedin2username",
        "aliases":      ["l2u", "linkedin2username"],
        "repo":         "https://github.com/initstring/linkedin2username",
        "clone_dir":    "linkedin2username",
        "entry_points": [
            {"wrapper": "linkedin2username", "script": "linkedin2username.py"},
        ],
        "description":  "LinkedIn username enumeration via employee scraping",
    },
    {
        "name":         "gitminer3",
        "aliases":      ["gitminer", "gitminer3", "gm3"],
        "repo":         "https://github.com/unkl4b/Gitminer3",
        "clone_dir":    "gitminer3",
        "entry_points": [
            {"wrapper": "gitminer3", "script": "gitminer_v3.py"},
        ],
        "description":  "GitHub secret/dork mining (Stage 7) — needs a GITHUB_TOKEN",
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _color(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m"

ok   = lambda t: _color("32;1", t)
warn = lambda t: _color("33;1", t)
err  = lambda t: _color("31;1", t)
dim  = lambda t: _color("90",   t)
bold = lambda t: _color("1",    t)


def _run(cmd: list[str], cwd: Path | None = None, capture: bool = False) -> subprocess.CompletedProcess:
    kwargs: dict = dict(cwd=str(cwd) if cwd else None, check=True)
    if capture:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return subprocess.run(cmd, **kwargs)  # noqa: S603


def _git_available() -> bool:
    return shutil.which("git") is not None


def _python() -> str:
    return sys.executable


def _clone(repo_url: str, dest: Path, reinstall: bool) -> bool:
    """Clone repo into dest. Returns True if clone happened, False if already present."""
    if dest.exists():
        if reinstall:
            print(f"  {warn('[!]')} Removing existing directory: {dest.name}")
            shutil.rmtree(dest)
        else:
            print(f"  {dim('[~]')} Already cloned: {dest.name}  (use --reinstall to re-clone)")
            return False

    print(f"  {bold('[*]')} Cloning {repo_url} ...")
    _run(["git", "clone", "--depth", "1", repo_url, str(dest)])
    return True


def _pip_install(clone_dir: Path) -> None:
    req = clone_dir / "requirements.txt"
    setup = clone_dir / "setup.py"
    pyproject = clone_dir / "pyproject.toml"

    if req.exists():
        print(f"  {bold('[*]')} pip install -r requirements.txt ...")
        _run([
            _python(), "-m", "pip", "install",
            "--break-system-packages",
            "-r", str(req),
        ])
    elif setup.exists() or pyproject.exists():
        print(f"  {bold('[*]')} pip install -e . ...")
        _run([
            _python(), "-m", "pip", "install",
            "--break-system-packages",
            "-e", str(clone_dir),
        ])
    else:
        print(f"  {warn('[!]')} No requirements.txt or setup file found — skipping pip step")


def _write_unix_wrapper(wrapper_name: str, script_abs: Path) -> Path:
    wrapper = BIN_DIR / wrapper_name
    wrapper.write_text(
        textwrap.dedent(f"""\
            #!/bin/sh
            exec "{_python()}" "{script_abs}" "$@"
        """),
        encoding="utf-8",
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return wrapper


def _write_windows_wrapper(wrapper_name: str, script_abs: Path) -> Path:
    wrapper = BIN_DIR / f"{wrapper_name}.bat"
    wrapper.write_text(
        f'@echo off\n"{_python()}" "{script_abs}" %*\n',
        encoding="utf-8",
    )
    return wrapper


def _write_wrapper(wrapper_name: str, script_abs: Path) -> Path:
    if IS_WINDOWS:
        return _write_windows_wrapper(wrapper_name, script_abs)
    return _write_unix_wrapper(wrapper_name, script_abs)


def _verify_wrapper(wrapper_name: str) -> bool:
    """Check that the wrapper is now resolvable via tools/bin/."""
    if IS_WINDOWS:
        return (BIN_DIR / f"{wrapper_name}.bat").exists()
    return (BIN_DIR / wrapper_name).exists()


# ──────────────────────────────────────────────────────────────────────────────
# Core install logic
# ──────────────────────────────────────────────────────────────────────────────

def install_tool(tool: dict, reinstall: bool) -> bool:
    name      = tool["name"]
    clone_dir = TOOLS_DIR / tool["clone_dir"]

    print()
    print(bold(f"=== Installing: {name} ==="))
    print(dim(f"    {tool['description']}"))

    if not _git_available():
        print(err("  [!] git not found in PATH — cannot clone"))
        return False

    BIN_DIR.mkdir(parents=True, exist_ok=True)

    try:
        _clone(tool["repo"], clone_dir, reinstall)
        _pip_install(clone_dir)

        for ep in tool["entry_points"]:
            script_abs = clone_dir / ep["script"]
            if not script_abs.exists():
                print(warn(f"  [!] Entry point not found: {ep['script']} — wrapper skipped"))
                continue
            wrapper = _write_wrapper(ep["wrapper"], script_abs)
            print(f"  {ok('[+]')} Wrapper written: {wrapper}")

        # Verify at least the primary wrapper exists
        primary = tool["entry_points"][0]["wrapper"]
        if _verify_wrapper(primary):
            print(ok(f"  [+] {name} installed successfully"))
            return True
        else:
            print(err(f"  [-] Wrapper verification failed for {primary}"))
            return False

    except subprocess.CalledProcessError as exc:
        print(err(f"  [-] Command failed (exit {exc.returncode}): {' '.join(exc.cmd)}"))
        return False
    except Exception as exc:
        print(err(f"  [-] Unexpected error: {exc}"))
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Status display
# ──────────────────────────────────────────────────────────────────────────────

def _tool_status(tool: dict) -> str:
    clone_dir = TOOLS_DIR / tool["clone_dir"]
    primary   = tool["entry_points"][0]["wrapper"]
    cloned    = clone_dir.exists()
    wrapper_ok = _verify_wrapper(primary)
    if cloned and wrapper_ok:
        return ok("[installed]")
    if cloned:
        return warn("[cloned, no wrapper]")
    return err("[not installed]")


def list_tools() -> None:
    print()
    print(bold("  Managed Tools"))
    print("  " + "-" * 58)
    for tool in MANAGED_TOOLS:
        status = _tool_status(tool)
        print(f"  {tool['name']:<24} {status}")
        for ep in tool["entry_points"]:
            wrapper_path = BIN_DIR / (f"{ep['wrapper']}.bat" if IS_WINDOWS else ep["wrapper"])
            exists = "[+]" if wrapper_path.exists() else "[ ]"
            print(f"    {dim(exists)}  {ep['wrapper']:<22} -> {ep['script']}")
    print()
    print(f"  {dim('Wrappers live in:')} {BIN_DIR}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _resolve_tool(name: str) -> dict | None:
    name = name.lower()
    for tool in MANAGED_TOOLS:
        if name in tool["aliases"] or name == tool["name"]:
            return tool
    return None


def main() -> int:
    p = argparse.ArgumentParser(
        description="AgentE — Tool Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python install_tools.py                   # install all
              python install_tools.py pycroburst        # install one
              python install_tools.py l2u pcb           # install by alias
              python install_tools.py --list            # show status
              python install_tools.py --reinstall       # force re-clone all
        """),
    )
    p.add_argument("tools",      nargs="*", help="Tool names/aliases to install (default: all)")
    p.add_argument("--list",     action="store_true", help="Show status of all managed tools and exit")
    p.add_argument("--reinstall",action="store_true", help="Remove and re-clone even if already present")
    args = p.parse_args()

    if args.list:
        list_tools()
        return 0

    targets: list[dict] = []
    if args.tools:
        for name in args.tools:
            tool = _resolve_tool(name)
            if tool is None:
                print(err(f"Unknown tool: {name}"))
                print(f"  Known names/aliases: {', '.join(a for t in MANAGED_TOOLS for a in t['aliases'])}")
                return 1
            if tool not in targets:
                targets.append(tool)
    else:
        targets = MANAGED_TOOLS

    print()
    print(bold("  AgentE — Tool Installer"))
    print(f"  {dim('Tools dir:')} {TOOLS_DIR}")
    print(f"  {dim('Python:   ')} {_python()}")

    results = {t["name"]: install_tool(t, reinstall=args.reinstall) for t in targets}

    print()
    print(bold("  Summary"))
    print("  " + "-" * 40)
    all_ok = True
    for name, success in results.items():
        mark = ok("[+]") if success else err("[-]")
        print(f"  {mark}  {name}")
        if not success:
            all_ok = False
    print()

    if all_ok:
        print(ok("  All tools installed."))
        print()
        print(f"  {bold('Next step:')} the orchestrator resolves tools from:")
        print(f"  {dim(str(BIN_DIR))}")
        print()
    else:
        print(warn("  Some tools failed to install — check output above."))
        print()

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
