"""
Run output directory layout.

Every AgentE run writes into a single timestamped directory:

    output/<domain>/<timestamp>/

Historically every stage dumped its files flat into that directory, which made
runs hard to navigate. This module defines a stable, numbered per-stage layout
so each tool's artefacts live in their own folder, all HTML reports collect
under ``reports/`` and logs collect under ``logs/``:

    output/<domain>/<timestamp>/
      logs/                 agente.log
      reports/              index.html + one HTML report per stage
      00-ip-resolve/        optional IP -> FQDN pre-step
      01-subdomains/        subfinder / subscraper / bbot
      02-validation/        dnsgen / puredns / httpx  (live_urls.txt)
      03-screenshots/       gowitness screenshots + nuclei results
      04-crawl/             gospider / katana / waymore
      05-assets/            downloaded JS/JSON/config (collected/)
      06-js-analysis/       semgrep raw output
      07-cloud/             cloud_enum / pycroburst
      08-email/             linkedin2username / phonebook
      09-exposure/          leakix / gitminer / google dorks
      config_snapshot.yaml
      summary.json

``build_layout`` returns a plain dict mapping short keys to ``Path`` objects;
callers hand each stage its own directory instead of the shared run root.
"""
from pathlib import Path

# Short key -> directory name (relative to the run root). Ordered by pipeline
# position so the numeric prefixes sort the same way the stages execute.
STAGE_DIRS: dict[str, str] = {
    "ip_resolve": "00-ip-resolve",
    "subdomains": "01-subdomains",
    "validation": "02-validation",
    "recon":      "03-screenshots",
    "crawl":      "04-crawl",
    "assets":     "05-assets",
    "jsanalysis": "06-js-analysis",
    "cloud":      "07-cloud",
    "email":      "08-email",
    "exposure":   "09-exposure",
}


def build_layout(run_dir: Path) -> dict[str, Path]:
    """
    Create the standard sub-directory layout under *run_dir* and return a dict
    of ``key -> Path``. Also includes ``root``, ``logs`` and ``reports``.
    All directories are created (``parents=True, exist_ok=True``).
    """
    run_dir = Path(run_dir)
    dirs: dict[str, Path] = {
        "root":    run_dir,
        "logs":    run_dir / "logs",
        "reports": run_dir / "reports",
    }
    for key, name in STAGE_DIRS.items():
        dirs[key] = run_dir / name

    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)

    return dirs
