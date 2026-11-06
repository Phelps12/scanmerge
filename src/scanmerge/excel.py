"""Write the merged scan to an Excel workbook (findings, grouped issues, gaps, summary)."""

from datetime import date
from pathlib import Path

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Font, PatternFill
from openpyxl.worksheet.worksheet import Worksheet

from .merge import MergedScan, by_vulnerability
from .models import SEVERITIES

AUTO_COLUMNS = ["Network/Site", "Host", "Hostname", "Port", "Service", "Title", "CVE(s)", "CVSS",
                "Severity", "Source", "Solution"]
MANUAL_COLUMNS = ["Recommendation", "Cost", "Owner", "Deadline", "Status"]
VULN_COLUMNS = ["Severity", "CVSS", "Title", "CVE(s)", "Hosts", "Affected", "Solution"]
GAP_COLUMNS = ["Gap", "Host", "Hostname", "Open ports (Nmap)"]

# (fill, font colour) per severity
SEVERITY_STYLE = {
    "Critical": ("7B0000", "FFFFFF"),
    "High": ("E00000", "FFFFFF"),
    "Medium": ("FFA500", "000000"),
    "Low": ("4F81BD", "FFFFFF"),
    "Log": ("D9D9D9", "000000"),
}
HEADER_FILL = PatternFill("solid", fgColor="404040")
MANUAL_HEADER_FILL = PatternFill("solid", fgColor="2F5597")
EXCEL_CELL_LIMIT = 32767


def _safe(value):
    if isinstance(value, str):
        return ILLEGAL_CHARACTERS_RE.sub("", value)[:EXCEL_CELL_LIMIT]
    return value


def _append(ws: Worksheet, values: list) -> None:
    ws.append([_safe(v) for v in values])
    for cell in ws[ws.max_row]:
        if cell.data_type == "f":
            cell.data_type = "s"  # untrusted text starting with "=" must stay text, not a formula


def _header(ws: Worksheet, columns: list[str], widths: dict[str, int], manual: set[str] = frozenset()) -> None:
    ws.append(columns)
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = MANUAL_HEADER_FILL if cell.value in manual else HEADER_FILL
        ws.column_dimensions[cell.column_letter].width = widths.get(cell.value, 14)
    ws.freeze_panes = "A2"


def _colour_severity(ws: Worksheet, column: int, severity: str) -> None:
    fill, colour = SEVERITY_STYLE[severity]
    cell = ws.cell(ws.max_row, column)
    cell.fill = PatternFill("solid", fgColor=fill)
    cell.font = Font(bold=True, color=colour)


def service_label(merged: MergedScan, ip: str, port: str) -> str:
    s = merged.services.get((ip, port))
    if s is None:
        return ""
    return f"{s.service} ({s.version})" if s.version else s.service


def write_report(path: str | Path, merged: MergedScan, site: str = "", skipped: list[str] = ()) -> None:
    wb = Workbook()

    ws = wb.active
    ws.title = "Non-conformities"
    _header(ws, AUTO_COLUMNS + MANUAL_COLUMNS,
            {"Network/Site": 16, "Host": 16, "Hostname": 22, "Service": 22, "Title": 50, "CVE(s)": 28,
             "CVSS": 7, "Severity": 10, "Solution": 50, "Recommendation": 40},
            set(MANUAL_COLUMNS))
    for f in merged.findings:
        _append(ws, [site, f.ip, f.hostname, f.port, service_label(merged, f.ip, f.port), f.title,
                     ", ".join(f.cves), f.cvss, f.severity, f.source, f.solution] + [None] * len(MANUAL_COLUMNS))
        _colour_severity(ws, AUTO_COLUMNS.index("Severity") + 1, f.severity)
    ws.auto_filter.ref = ws.dimensions

    ws = wb.create_sheet("By vulnerability")
    _header(ws, VULN_COLUMNS + MANUAL_COLUMNS,
            {"Title": 50, "CVE(s)": 28, "CVSS": 7, "Severity": 10, "Hosts": 7, "Affected": 60, "Solution": 50,
             "Recommendation": 40},
            set(MANUAL_COLUMNS))
    for v in by_vulnerability(merged.findings):
        affected = ", ".join(f"{f.ip} {f.port}" for f in v.affected)
        _append(ws, [v.severity, v.cvss, v.title, ", ".join(v.cves), v.host_count, affected, v.solution]
                + [None] * len(MANUAL_COLUMNS))
        _colour_severity(ws, VULN_COLUMNS.index("Severity") + 1, v.severity)
    ws.auto_filter.ref = ws.dimensions

    ws = wb.create_sheet("Coverage gaps")
    _header(ws, GAP_COLUMNS, {"Gap": 28, "Host": 16, "Hostname": 22, "Open ports (Nmap)": 80})
    for label, hosts in (("Not analysed by OpenVAS", merged.not_analysed),
                         ("Not seen by Nmap", merged.not_in_nmap)):
        for h in hosts:
            ports = ", ".join(
                f"{s.port} {service_label(merged, s.ip, s.port)}".strip() for s in merged.open_ports(h.ip)
            )
            _append(ws, [label, h.ip, h.hostname, ports])
    ws.auto_filter.ref = ws.dimensions

    ws = wb.create_sheet("Summary")
    _header(ws, ["Metric", "Value"], {"Metric": 40, "Value": 40})
    checked = merged.coverage_checked
    rows = [
        ("Site", site),
        ("Generated", date.today().isoformat()),
        ("Hosts seen", len(merged.hosts)),
        ("Hosts analysed (OpenVAS)", len(merged.analysed) if merged.analysed is not None else "n/a"),
        ("Coverage gaps (up in Nmap, not analysed)", len(merged.not_analysed) if checked else "n/a"),
        ("Analysed by OpenVAS, not seen by Nmap", len(merged.not_in_nmap) if checked else "n/a"),
        ("Findings", len(merged.findings)),
        ("Distinct vulnerabilities", len(by_vulnerability(merged.findings))),
    ]
    rows += [(f"  {sev}", sum(f.severity == sev for f in merged.findings)) for sev in SEVERITIES]
    rows += [("Skipped input file", name) for name in skipped]
    rows += [("Warning", w) for w in merged.warnings]
    for row in rows:
        _append(ws, list(row))

    wb.save(path)
