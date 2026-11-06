from pathlib import Path

from openpyxl import load_workbook

from scanmerge.excel import AUTO_COLUMNS, MANUAL_COLUMNS, write_report
from scanmerge.merge import merge
from scanmerge.models import Finding, Host
from scanmerge.parsers import parse_nmap, parse_openvas

FIXTURES = Path(__file__).parent / "fixtures"


def _report(tmp_path, **kwargs):
    merged = merge(parse_nmap(FIXTURES / "nmap_store_tcp.xml"), parse_openvas(FIXTURES / "openvas_store.xml"))
    out = tmp_path / "report.xlsx"
    write_report(out, merged, site="Store A", **kwargs)
    return load_workbook(out)


def test_workbook_sheets(tmp_path):
    wb = _report(tmp_path)
    assert wb.sheetnames == ["Non-conformities", "By vulnerability", "Coverage gaps", "Summary"]


def test_non_conformities_sheet(tmp_path):
    ws = _report(tmp_path)["Non-conformities"]
    header = [c.value for c in ws[1]]
    assert header == AUTO_COLUMNS + MANUAL_COLUMNS
    assert ws.freeze_panes == "A2"
    assert ws.auto_filter.ref == "A1:P7"

    first = dict(zip(header, (c.value for c in ws[2])))
    assert first["Network/Site"] == "Store A"
    assert first["Host"] == "192.0.2.20"
    assert first["Service"] == "http (Apache httpd 2.4.49)"
    assert first["CVE(s)"] == "CVE-2021-41773, CVE-2021-42013"
    assert first["CVSS"] == 9.8
    assert first["Severity"] == "Critical"
    assert all(first[c] is None for c in MANUAL_COLUMNS)

    severity_cell = ws.cell(2, header.index("Severity") + 1)
    assert severity_cell.fill.fgColor.rgb.endswith("7B0000")


def test_coverage_gaps_sheet_lists_open_ports(tmp_path):
    ws = _report(tmp_path)["Coverage gaps"]
    rows = [[c.value for c in row] for row in ws.iter_rows(min_row=2)]
    assert rows == [
        ["Not analysed by OpenVAS", "192.0.2.30", "pos01.example.test", "3389/tcp ms-wbt-server"],
        ["Not seen by Nmap", "198.51.100.7", None, None],
    ]


def test_summary_sheet(tmp_path):
    ws = _report(tmp_path, skipped=["broken.xml"])["Summary"]
    summary = {row[0].value: row[1].value for row in ws.iter_rows(min_row=2)}
    assert summary["Site"] == "Store A"
    assert summary["Hosts seen"] == 5
    assert summary["Hosts analysed (OpenVAS)"] == 4
    assert summary["Coverage gaps (up in Nmap, not analysed)"] == 1
    assert summary["Analysed by OpenVAS, not seen by Nmap"] == 1
    assert summary["Findings"] == 6
    assert summary["  Critical"] == 1 and summary["  High"] == 2 and summary["  Log"] == 1
    assert summary["Skipped input file"] == "broken.xml"


def test_summary_without_openvas_marks_coverage_as_unknown(tmp_path):
    out = tmp_path / "report.xlsx"
    write_report(out, merge(parse_nmap(FIXTURES / "nmap_store_tcp.xml"), None))
    summary = {r[0].value: r[1].value for r in load_workbook(out)["Summary"].iter_rows(min_row=2)}
    assert summary["Coverage gaps (up in Nmap, not analysed)"] == "n/a"


def test_untrusted_text_is_not_written_as_formula(tmp_path):
    evil = Finding("192.0.2.10", "80/tcp", '=HYPERLINK("http://example.test","x")', 5.0, [],
                   "bad\x07char", "openvas")
    out = tmp_path / "report.xlsx"
    write_report(out, merge(None, ([Host("192.0.2.10", "", {"openvas"})], [evil])))

    ws = load_workbook(out)["Non-conformities"]
    title = ws.cell(2, AUTO_COLUMNS.index("Title") + 1)
    assert title.data_type == "s"
    assert title.value == '=HYPERLINK("http://example.test","x")'
    assert ws.cell(2, AUTO_COLUMNS.index("Solution") + 1).value == "badchar"


def test_by_vulnerability_sheet(tmp_path):
    wb = _report(tmp_path)
    ws = wb["By vulnerability"]
    header = [c.value for c in ws[1]]
    first = dict(zip(header, (c.value for c in ws[2])))
    assert first["Severity"] == "Critical"
    assert first["Hosts"] == 1
    assert first["Affected"] == "192.0.2.20 80/tcp"
    assert ws.max_row - 1 == 6  # one row per distinct NVT
    summary = {r[0].value: r[1].value for r in wb["Summary"].iter_rows(min_row=2)}
    assert summary["Distinct vulnerabilities"] == 6
