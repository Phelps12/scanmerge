"""Command line entry point.

Exit codes: 0 report written, 1 no valid input file or the report could not
be written, 2 invalid arguments (argparse).
"""

import argparse
import sys

from . import __version__
from .excel import write_report
from .merge import MergedScan, merge
from .models import SEVERITIES
from .parsers import load_scans


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanmerge",
        description="Merge Nmap and OpenVAS/GVM results into an Excel non-conformity report "
        "and flag hosts that were not scanned for vulnerabilities.",
    )
    p.add_argument("--nmap", action="append", required=True, metavar="FILE",
                   help="Nmap XML output (nmap -oX); repeat for several files")
    p.add_argument("--openvas", required=True, metavar="FILE", help="OpenVAS/GVM report exported as XML")
    p.add_argument("--site", default="", help='network or site name for the report, e.g. "Store A"')
    p.add_argument("-o", "--output", required=True, metavar="FILE.xlsx", help="Excel file to write")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _print_summary(merged: MergedScan, site: str, output: str) -> None:
    counts = ", ".join(f"{sev} {sum(f.severity == sev for f in merged.findings)}" for sev in SEVERITIES)
    analysed = len(merged.analysed) if merged.analysed is not None else "n/a"
    gaps = len(merged.not_analysed) if merged.coverage_checked else "n/a"
    if site:
        print(f"Site: {site}")
    print(f"Hosts seen: {len(merged.hosts)} | analysed by OpenVAS: {analysed} | coverage gaps: {gaps}")
    print(f"Findings: {len(merged.findings)} ({counts})")
    for w in merged.warnings:
        print(f"WARNING: {w}")
    for h in merged.not_analysed:
        name = f" ({h.hostname})" if h.hostname else ""
        print(f"WARNING: {h.ip}{name} is up in Nmap but was not analysed by OpenVAS")
    for h in merged.not_in_nmap:
        print(f"WARNING: {h.ip} was analysed by OpenVAS but not seen by Nmap")
    if not merged.coverage_checked:
        print("WARNING: coverage check skipped: it needs at least one valid Nmap file and the OpenVAS report")
    print(f"Report written to {output}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    nmap, openvas, errors, warnings = load_scans(args.nmap, args.openvas)
    for _, message in errors:
        _error(message)
    skipped = [name for name, _ in errors]

    if nmap is None and openvas is None:
        _error("no valid input file, nothing to report")
        return 1

    merged = merge(nmap, openvas, warnings)
    try:
        write_report(args.output, merged, args.site, skipped)
    except OSError as e:
        _error(f"cannot write {args.output} ({e.strerror or e}); is it open in Excel?")
        return 1

    _print_summary(merged, args.site, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
