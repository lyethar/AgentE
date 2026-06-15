"""
Optional pre-stage — IP → FQDN resolution & validation.

Enabled with `--ip-list <file>`. Given a file of IP addresses (and/or CIDR
ranges), each address is reverse-resolved to its fully-qualified domain
name(s) via PTR records, then validated with forward-confirmed reverse DNS
(FCrDNS): a PTR hostname is only considered valid if it forward-resolves back
to the original IP. This filters out stale or spoofed PTR records.

Outputs:
    ip_resolution.json   full per-IP results (ptr, fqdns, validated, status)
    ip_fqdns.txt         FCrDNS-validated FQDNs (one per line)
    ip_fqdns_all.txt     every PTR-derived FQDN (validated or not)

Validated FQDNs are optionally folded into the subdomain pool so they flow
through the normal validation / crawl stages.

Authorized use only — resolve only addresses you have permission to assess.
"""
import asyncio
import ipaddress
import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

log = logging.getLogger("agente.ip_resolve")


def _empty(errors: list[str] | None = None) -> dict:
    return {
        "results": [], "errors": errors or [],
        "total_ips": 0, "resolved": 0,
        "fqdns": [], "validated_fqdns": [],
        "tool_results": [{"tool": "ip-fqdn-resolver", "duration": 0.0,
                          "skipped": True, "skip_reason": "no IPs to resolve"}],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Input parsing
# ──────────────────────────────────────────────────────────────────────────────

def _parse_ip_file(path: Path, max_cidr_hosts: int) -> tuple[list[str], list[str]]:
    """
    Parse a file of IPs / CIDR ranges (one entry per line). Inline comments
    (#) and surrounding whitespace are ignored. Returns (ordered_unique_ips,
    errors). CIDR ranges are expanded up to `max_cidr_hosts` for safety.
    """
    ips: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()

    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Take the first whitespace/comma-delimited token (tolerate "ip  # note")
        token = line.split("#")[0].strip().split()[0].split(",")[0].strip()
        if not token:
            continue
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                hosts = list(net.hosts()) or [net.network_address]
                if len(hosts) > max_cidr_hosts:
                    errors.append(f"{token}: range too large "
                                  f"({len(hosts)} > {max_cidr_hosts}) — skipped")
                    continue
                candidates = [str(h) for h in hosts]
            else:
                candidates = [str(ipaddress.ip_address(token))]
        except ValueError:
            errors.append(f"{line}: not a valid IP address or CIDR range")
            continue

        for ip in candidates:
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)

    return ips, errors


# ──────────────────────────────────────────────────────────────────────────────
# Resolution
# ──────────────────────────────────────────────────────────────────────────────

def _resolve_one(ip: str) -> dict:
    """Reverse-resolve a single IP, then forward-confirm (FCrDNS)."""
    entry = {"ip": ip, "ptr": [], "fqdns": [], "validated_fqdns": [],
             "validated": False, "status": "no_ptr"}

    # Reverse DNS (PTR)
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        names = sorted({n.rstrip(".").lower() for n in [host, *aliases] if n})
    except (socket.herror, socket.gaierror):
        return entry                       # no PTR record
    except Exception as exc:               # pragma: no cover - defensive
        entry["status"] = "error"
        entry["error"] = str(exc)[:200]
        return entry

    entry["ptr"] = names
    entry["fqdns"] = names
    entry["status"] = "resolved"

    # Forward-confirmed reverse DNS: the hostname must resolve back to this IP
    validated: list[str] = []
    for name in names:
        try:
            infos = socket.getaddrinfo(name, None)
            forward_ips = {info[4][0] for info in infos}
        except (socket.gaierror, socket.herror):
            continue
        except Exception:                  # pragma: no cover - defensive
            continue
        if ip in forward_ips:
            validated.append(name)

    if validated:
        entry["validated"] = True
        entry["validated_fqdns"] = validated
        entry["status"] = "validated"
    return entry


def _resolve_blocking(ips: list[str], cfg: dict) -> list[dict]:
    workers = int(cfg.get("workers", 20))
    timeout = float(cfg.get("timeout", 5))

    # gethostbyaddr/getaddrinfo have no per-call timeout; bound them with the
    # process-wide default socket timeout, restoring it afterwards.
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    results: list[dict] = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(_resolve_one, ip): ip for ip in ips}
            done = 0
            for fut in as_completed(future_map):
                results.append(fut.result())
                done += 1
                if done % 50 == 0 or done == len(ips):
                    log.info("IP resolve: %d/%d processed", done, len(ips))
    finally:
        socket.setdefaulttimeout(old_timeout)

    # Restore input order for stable reporting
    order = {ip: i for i, ip in enumerate(ips)}
    results.sort(key=lambda r: order.get(r["ip"], 0))
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

async def resolve_ips(ip_file: Path, outdir: Path, cfg: dict) -> dict:
    log.info("=== IP → FQDN Resolution ===")
    ipcfg = cfg.get("ip_resolve", {})

    if not ip_file.exists():
        log.warning("IP list file not found: %s", ip_file)
        return _empty([f"file not found: {ip_file}"])

    ips, errors = _parse_ip_file(ip_file, int(ipcfg.get("max_cidr_hosts", 4096)))
    for err in errors:
        log.warning("IP parse: %s", err)

    if not ips:
        log.warning("IP resolve: no valid IP addresses found in %s", ip_file)
        return _empty(errors)

    log.info("IP resolve: %d unique address(es) to resolve", len(ips))
    results = await asyncio.to_thread(_resolve_blocking, ips, ipcfg)

    all_fqdns = sorted({f for r in results for f in r.get("fqdns", [])})
    validated_fqdns = sorted({f for r in results for f in r.get("validated_fqdns", [])})
    resolved = sum(1 for r in results if r.get("fqdns"))

    (outdir / "ip_resolution.json").write_text(
        json.dumps({"results": results, "errors": errors}, indent=2), encoding="utf-8"
    )
    (outdir / "ip_fqdns.txt").write_text("\n".join(validated_fqdns), encoding="utf-8")
    (outdir / "ip_fqdns_all.txt").write_text("\n".join(all_fqdns), encoding="utf-8")

    log.info("IP resolve: %d/%d had a PTR record, %d FCrDNS-validated FQDN(s)",
             resolved, len(ips), len(validated_fqdns))

    return {
        "results": results,
        "errors": errors,
        "total_ips": len(ips),
        "resolved": resolved,
        "fqdns": all_fqdns,
        "validated_fqdns": validated_fqdns,
        "tool_results": [{"tool": "ip-fqdn-resolver", "duration": 0.0,
                          "skipped": False, "skip_reason": ""}],
    }
