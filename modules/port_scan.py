"""
Stage 3 (port scanning) — Nmap integration.

Runs **only** against the in-scope hosts supplied via ``--ip-list`` and executes
*before* the Nuclei vulnerability scan in Stage 3. The scan is two-phase, per the
classic recon pattern:

    1. Fast Top-1000 port scan   (nmap -Pn -T4 -iL <ips> --open -v)
    2. Parse the open ports
    3. Targeted service + default-script scan of just those open ports
       (nmap -Pn -T4 -sV -sC -p <open-ports> <host>)

Phase 1 sweeps every target quickly to find what is listening; phase 2 then
fingerprints only the ports that are actually open, so the expensive ``-sV -sC``
work is scoped tightly. All raw nmap output (normal + XML) is written into the
Stage 3 directory, and every invocation is captured by the verbose command log.

Authorized use only — scan only hosts you have explicit permission to assess.
"""
import asyncio
import logging
from pathlib import Path
from xml.etree import ElementTree as ET

from utils.runner import ToolResult, run_tool

log = logging.getLogger("agente.port_scan")


def _empty(skip_reason: str = "", enabled: bool = True) -> dict:
    return {
        "enabled": enabled,
        "skipped": True,
        "skip_reason": skip_reason,
        "targets": [],
        "hosts": [],
        "open_ports_total": 0,
        "hosts_up": 0,
        "hosts_scanned": 0,
        "fast_file": "",
        "tool_results": [],
    }


def _tr(r: ToolResult) -> dict:
    return {"tool": r.tool, "duration": r.duration,
            "skipped": r.skipped, "skip_reason": r.skip_reason}


# ──────────────────────────────────────────────────────────────────────────────
# nmap XML parsing
# ──────────────────────────────────────────────────────────────────────────────

def _parse_nmap_xml(xml_file: Path) -> dict[str, dict]:
    """
    Parse an nmap XML report into ``{ip: {"hostname", "state", "ports": {...}}}``.
    ``ports`` maps ``"proto/port"`` to a port dict. Only ``open`` ports are kept.
    Missing/malformed files parse to an empty dict (never raises).
    """
    hosts: dict[str, dict] = {}
    if not xml_file.exists():
        return hosts
    try:
        root = ET.parse(xml_file).getroot()
    except ET.ParseError as exc:
        log.warning("nmap: could not parse %s: %s", xml_file.name, exc)
        return hosts

    for host_el in root.findall("host"):
        # Prefer the ipv4/ipv6 address; fall back to any address element.
        ip = ""
        for addr in host_el.findall("address"):
            atype = addr.get("addrtype", "")
            if atype in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
            ip = ip or addr.get("addr", "")
        if not ip:
            continue

        status_el = host_el.find("status")
        state = status_el.get("state", "") if status_el is not None else ""

        hostname = ""
        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        entry = hosts.setdefault(ip, {"hostname": hostname, "state": state, "ports": {}})
        if hostname and not entry["hostname"]:
            entry["hostname"] = hostname
        if state:
            entry["state"] = state

        for port_el in host_el.findall("ports/port"):
            st = port_el.find("state")
            if st is None or st.get("state") != "open":
                continue
            proto = port_el.get("protocol", "tcp")
            portid = port_el.get("portid", "")
            key = f"{proto}/{portid}"

            svc = port_el.find("service")
            scripts: dict[str, str] = {}
            for sc in port_el.findall("script"):
                sid = sc.get("id", "")
                out = (sc.get("output", "") or "").strip()
                if sid:
                    scripts[sid] = out

            port_rec = {
                "port": int(portid) if portid.isdigit() else portid,
                "proto": proto,
                "state": "open",
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                "scripts": scripts,
            }
            # Merge: a later (service-scan) parse enriches the fast-scan entry.
            existing = entry["ports"].get(key, {})
            merged = {**existing, **{k: v for k, v in port_rec.items()
                                     if v or k not in existing}}
            if existing.get("scripts") and not scripts:
                merged["scripts"] = existing["scripts"]
            entry["ports"][key] = merged

    return hosts


# ──────────────────────────────────────────────────────────────────────────────
# nmap invocations
# ──────────────────────────────────────────────────────────────────────────────

async def _run_fast_scan(targets_file: Path, stage_dir: Path, cfg: dict) -> ToolResult:
    """Phase 1 — fast Top-N port sweep of every in-scope target."""
    top_ports = int(cfg.get("top_ports", 1000))
    cmd = [
        "nmap", "-Pn", "-T4", "--open", "-v",
        "--top-ports", str(top_ports),
        "-iL", targets_file.name,
        "-oX", "nmap_fast.xml",
        "-oN", "nmap_fast.txt",
        *cfg.get("extra_args", []),
    ]
    return await run_tool(cmd, "nmap-fast", cwd=stage_dir, timeout=cfg.get("timeout"))


async def _run_service_scan(ip: str, ports: list[str], stage_dir: Path,
                            cfg: dict) -> ToolResult:
    """Phase 2 — targeted service (-sV) + default-script (-sC) scan of open ports."""
    safe = ip.replace(":", "_").replace("/", "_")
    port_arg = ",".join(ports)
    cmd = ["nmap", "-Pn", "-T4", "-sV"]
    if cfg.get("script_scan", True):
        cmd.append("-sC")
    cmd += [
        "-p", port_arg, ip,
        "-oX", f"nmap_service_{safe}.xml",
        "-oN", f"nmap_service_{safe}.txt",
        *cfg.get("service_extra_args", []),
    ]
    return await run_tool(cmd, f"nmap-svc-{ip}", cwd=stage_dir, timeout=cfg.get("timeout"))


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

async def run_nmap_scan(targets: list[str], stage_dir: Path, cfg: dict) -> dict:
    """
    Two-phase Nmap scan of the in-scope ``--ip-list`` targets.

    targets: IP addresses to scan (already parsed/validated upstream). When empty
    the scan is skipped. Returns a structured result consumed by the Stage 3
    report, the run summary, and the Markdown report.
    """
    targets = [t.strip() for t in targets if t and t.strip()]
    if not targets:
        return _empty("no --ip-list targets to scan")

    log.info("Nmap: scanning %d in-scope --ip-list target(s)", len(targets))
    stage_dir.mkdir(parents=True, exist_ok=True)
    targets_file = stage_dir / "nmap-targets.txt"
    targets_file.write_text("\n".join(targets), encoding="utf-8")

    tool_results: list[ToolResult] = []

    # ── Phase 1: fast top-ports sweep ──
    fast_result = await _run_fast_scan(targets_file, stage_dir, cfg)
    tool_results.append(fast_result)
    if fast_result.skipped and fast_result.returncode == -1:
        # nmap binary not present — surface a clean skip.
        log.warning("Nmap: binary not found — port scanning skipped")
        data = _empty(fast_result.skip_reason or "nmap not installed")
        data["skipped"] = True
        data["targets"] = targets
        data["tool_results"] = [_tr(r) for r in tool_results]
        return data

    hosts = _parse_nmap_xml(stage_dir / "nmap_fast.xml")

    # Determine which hosts have open ports worth a targeted service scan.
    to_scan = {ip: sorted(str(p["port"]) for p in h["ports"].values())
               for ip, h in hosts.items() if h["ports"]}
    log.info("Nmap: fast scan found open ports on %d/%d host(s)",
             len(to_scan), len(targets))

    # ── Phase 2: targeted -sV -sC scan of only the open ports (per host) ──
    if cfg.get("service_scan", True) and to_scan:
        max_conc = int(cfg.get("max_concurrency", 5))
        sem = asyncio.Semaphore(max_conc)

        async def _bounded(ip: str, ports: list[str]) -> ToolResult:
            async with sem:
                return await _run_service_scan(ip, ports, stage_dir, cfg)

        svc_results = await asyncio.gather(
            *[_bounded(ip, ports) for ip, ports in to_scan.items()]
        )
        tool_results.extend(svc_results)

        # Merge enriched service/script data back over the fast-scan ports.
        for ip in to_scan:
            safe = ip.replace(":", "_").replace("/", "_")
            enriched = _parse_nmap_xml(stage_dir / f"nmap_service_{safe}.xml")
            if ip in enriched:
                for key, port in enriched[ip]["ports"].items():
                    base = hosts[ip]["ports"].get(key, {})
                    hosts[ip]["ports"][key] = {**base, **port}

    # Flatten to a stable, report-friendly structure.
    host_list = []
    open_total = 0
    for ip in sorted(hosts):
        ports = sorted(hosts[ip]["ports"].values(),
                       key=lambda p: (p["proto"], p["port"] if isinstance(p["port"], int) else 0))
        open_total += len(ports)
        host_list.append({
            "ip": ip,
            "hostname": hosts[ip].get("hostname", ""),
            "state": hosts[ip].get("state", ""),
            "ports": ports,
        })

    hosts_up = sum(1 for h in host_list if h["state"] == "up")
    log.info("Nmap: %d open port(s) across %d host(s) (%d up)",
             open_total, len(to_scan), hosts_up)

    return {
        "enabled": True,
        "skipped": False,
        "skip_reason": "",
        "targets": targets,
        "hosts": host_list,
        "open_ports_total": open_total,
        "hosts_up": hosts_up or len(to_scan),
        "hosts_scanned": len(targets),
        "fast_file": str(stage_dir / "nmap_fast.xml"),
        "tool_results": [_tr(r) for r in tool_results],
    }
