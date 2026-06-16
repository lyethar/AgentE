"""
Stage 6 — Cloud Infrastructure Enumeration
Tools: cloud_enum → pyCroBurst
Discovers cloud storage buckets, blobs, and functions across AWS/Azure/GCP.
"""
import logging
import re
from pathlib import Path

from utils.runner import ToolResult, run_tool

log = logging.getLogger("agente.cloud")

_S3_RE    = re.compile(r"s3://[^\s]+|(?:https?://)?[a-z0-9\-\.]+\.s3(?:[-\.][a-z0-9\-]+)?\.amazonaws\.com[^\s]*", re.I)
_AZURE_RE = re.compile(r"(?:https?://)?[a-z0-9\-]+\.blob\.core\.windows\.net[^\s]*", re.I)
_GCP_RE   = re.compile(r"(?:https?://)?storage\.googleapis\.com/[^\s]+|gs://[^\s]+", re.I)
_FUNC_RE  = re.compile(r"(?:https?://)?[a-z0-9\-]+\.azurewebsites\.net[^\s]*"
                        r"|(?:https?://)?[a-z0-9\-]+\.cloudfunctions\.net[^\s]*"
                        r"|(?:https?://)?[a-z0-9\-]+\.lambda-url\.[a-z0-9\-]+\.on\.aws[^\s]*", re.I)


def _parse_cloud_enum_output(text: str) -> dict:
    return {
        "s3":       _S3_RE.findall(text),
        "azure":    _AZURE_RE.findall(text),
        "gcp":      _GCP_RE.findall(text),
        "functions":_FUNC_RE.findall(text),
    }


async def run_cloud_enum(keyword: str, outdir: Path, cfg: dict) -> ToolResult:
    """
    cloud_enum: bruteforce cloud storage names derived from keyword.
    Expects `cloud_enum` (or `cloud_enum.py`) in PATH.
    """
    out_file = outdir / "cloud_enum.txt"
    cmd = [
        "cloud_enum",
        "-k", keyword,
        "--logfile", str(out_file),
        *cfg.get("extra_args", []),
    ]
    return await run_tool(cmd, "cloud_enum", timeout=cfg.get("timeout"))


async def run_pycroburst(keyword: str, outdir: Path, cfg: dict) -> ToolResult:
    """
    pyCroBurst (NetSPI): Azure blob storage enumerator.
    Entry point: enumerateAzureBlobs.py, exposed via the 'pycroburst' wrapper
    created by install_tools.py.
    Flags: -a <account_name_keyword>  [-b <brute_list>]
    """
    out_file = outdir / "pycroburst.txt"
    wordlist = cfg.get("wordlist", "")
    cmd = [
        "pycroburst",
        "-a", keyword,
        *(["-b", wordlist] if wordlist else []),
        *cfg.get("extra_args", []),
    ]
    result = await run_tool(cmd, "pyCroBurst", timeout=cfg.get("timeout"))
    # pyCroBurst writes to stdout — persist it
    if not result.skipped and result.stdout:
        out_file.write_text(result.stdout, encoding="utf-8")
    return result


async def enumerate_cloud(domain: str, outdir: Path, cfg: dict) -> dict:
    log.info("=== Stage 6: Cloud Infrastructure Enumeration ===")
    cloud_cfg = cfg.get("cloud", {})

    # Derive keyword from domain (strip TLD)
    keyword = domain.split(".")[0]

    # cloud_enum runs first, pyCroBurst refines afterward
    ce_result = await run_cloud_enum(keyword, outdir, cloud_cfg.get("cloud_enum", {}))

    ce_text = ""
    ce_file = outdir / "cloud_enum.txt"
    if not ce_result.skipped:
        ce_text = ce_result.stdout
        if ce_file.exists():
            ce_text += "\n" + ce_file.read_text(errors="replace")

    ce_assets = _parse_cloud_enum_output(ce_text)

    # pyCroBurst: deeper bucket bruteforce
    pcb_result = await run_pycroburst(keyword, outdir, cloud_cfg.get("pycroburst", {}))
    pcb_text   = ""
    pcb_file   = outdir / "pycroburst.txt"
    if not pcb_result.skipped:
        pcb_text = pcb_result.stdout
        if pcb_file.exists():
            pcb_text += "\n" + pcb_file.read_text(errors="replace")

    pcb_assets = _parse_cloud_enum_output(pcb_text)

    # Merge deduped
    def merge_lists(a: list, b: list) -> list:
        return sorted(set(a) | set(b))

    all_assets = {
        "s3":        merge_lists(ce_assets["s3"],        pcb_assets["s3"]),
        "azure":     merge_lists(ce_assets["azure"],     pcb_assets["azure"]),
        "gcp":       merge_lists(ce_assets["gcp"],       pcb_assets["gcp"]),
        "functions": merge_lists(ce_assets["functions"], pcb_assets["functions"]),
    }
    total = sum(len(v) for v in all_assets.values())

    log.info(
        "Cloud assets — S3=%d  Azure=%d  GCP=%d  Functions=%d  total=%d",
        len(all_assets["s3"]), len(all_assets["azure"]),
        len(all_assets["gcp"]), len(all_assets["functions"]), total,
    )

    return {
        "assets": all_assets,
        "total":  total,
        "tool_results": [
            {"tool": r.tool, "duration": r.duration, "skipped": r.skipped, "skip_reason": r.skip_reason}
            for r in [ce_result, pcb_result]
        ],
    }
