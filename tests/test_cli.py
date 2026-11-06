from pathlib import Path

import pytest
from openpyxl import load_workbook

from scanmerge.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
TCP = str(FIXTURES / "nmap_store_tcp.xml")
UDP = str(FIXTURES / "nmap_store_udp.xml")
OPENVAS = str(FIXTURES / "openvas_store.xml")
BAD = str(FIXTURES / "malformed.xml")
XXE = str(FIXTURES / "xxe.xml")


def test_writes_report_and_prints_summary(tmp_path, capsys):
    out = tmp_path / "report.xlsx"
    code = main(["--nmap", TCP, "--nmap", UDP, "--openvas", OPENVAS, "--site", "Store A", "-o", str(out)])

    assert code == 0
    assert load_workbook(out).sheetnames == ["Non-conformities", "Coverage gaps", "Summary"]
    stdout = capsys.readouterr().out
    assert "Hosts seen: 5 | analysed by OpenVAS: 4 | coverage gaps: 1" in stdout
    assert "Findings: 6 (Critical 1, High 2, Medium 1, Low 1, Log 1)" in stdout
    assert "192.0.2.30 (pos01.example.test) is up in Nmap but was not analysed by OpenVAS" in stdout
    assert "198.51.100.7 was analysed by OpenVAS but not seen by Nmap" in stdout


def test_invalid_file_is_skipped_with_clear_error(tmp_path, capsys):
    out = tmp_path / "report.xlsx"
    assert main(["--nmap", TCP, "--nmap", XXE, "--openvas", OPENVAS, "-o", str(out)]) == 0

    assert "rejected unsafe XML" in capsys.readouterr().err
    summary = {r[0].value: r[1].value for r in load_workbook(out)["Summary"].iter_rows(min_row=2)}
    assert summary["Skipped input file"] == XXE


def test_invalid_openvas_skips_coverage_check(tmp_path, capsys):
    out = tmp_path / "report.xlsx"
    assert main(["--nmap", TCP, "--openvas", BAD, "-o", str(out)]) == 0
    captured = capsys.readouterr()
    assert "malformed XML" in captured.err
    assert "coverage check skipped" in captured.out


def test_exits_non_zero_without_any_valid_file(tmp_path, capsys):
    out = tmp_path / "report.xlsx"
    assert main(["--nmap", BAD, "--nmap", XXE, "--openvas", str(tmp_path / "missing.xml"), "-o", str(out)]) == 1
    assert "no valid input file" in capsys.readouterr().err
    assert not out.exists()


def test_unwritable_output_returns_error(tmp_path, capsys):
    assert main(["--nmap", TCP, "--openvas", OPENVAS, "-o", str(tmp_path / "no-dir" / "r.xlsx")]) == 1
    assert "cannot write" in capsys.readouterr().err


def test_missing_required_arguments_exit_with_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["--nmap", TCP])
    assert exc.value.code == 2
