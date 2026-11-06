import base64
import http.client
import io
import json
import threading
from pathlib import Path

import pytest
from openpyxl import load_workbook

from scanmerge.web import analyse, make_server

FIXTURES = Path(__file__).parent / "fixtures"


def _file(name: str, upload_name: str | None = None) -> dict:
    data = (FIXTURES / name).read_bytes()
    return {"name": upload_name or name, "content": base64.b64encode(data).decode()}


def _payload(**overrides) -> dict:
    payload = {
        "site": "Store A",
        "nmap": [_file("nmap_store_tcp.xml"), _file("nmap_store_udp.xml")],
        "openvas": _file("openvas_store.xml"),
    }
    payload.update(overrides)
    return payload


def test_analyse_returns_summary_gaps_findings_and_excel():
    status, body = analyse(_payload())

    assert status == 200
    assert body["summary"] == {
        "hosts_seen": 5,
        "analysed": 4,
        "coverage_checked": True,
        "findings": 6,
        "by_severity": {"Critical": 1, "High": 2, "Medium": 1, "Low": 1, "Log": 1},
    }
    assert body["not_analysed"] == [{"ip": "192.0.2.30", "hostname": "pos01.example.test",
                                     "ports": ["3389/tcp ms-wbt-server"]}]
    assert [h["ip"] for h in body["not_in_nmap"]] == ["198.51.100.7"]
    assert body["findings"][0]["service"] == "http (Apache httpd 2.4.49)"
    assert body["filename"] == "scanmerge_Store_A.xlsx"

    wb = load_workbook(io.BytesIO(base64.b64decode(body["excel"])))
    assert wb.sheetnames == ["Non-conformities", "By vulnerability", "Coverage gaps", "Summary"]


def test_analyse_reports_skipped_files_by_upload_name():
    status, body = analyse(_payload(nmap=[_file("nmap_store_tcp.xml"), _file("xxe.xml", r"C:\scans\evil.xml")]))
    assert status == 200
    assert body["errors"] == ["evil.xml: rejected unsafe XML (EntitiesForbidden)"]


def test_analyse_without_valid_files_is_422():
    status, body = analyse(_payload(nmap=[_file("malformed.xml")], openvas=_file("xxe.xml")))
    assert status == 422
    assert body["error"] == "No valid input file, nothing to report."
    assert len(body["errors"]) == 2


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"nmap": [], "openvas": None},
        {"nmap": [{"name": "a.xml"}], "openvas": {"name": "b.xml", "content": ""}},
        {"nmap": [{"name": "a.xml", "content": "not base64!"}], "openvas": {"name": "b.xml", "content": ""}},
        {"site": 3, "nmap": [{"name": "a.xml", "content": ""}], "openvas": {"name": "b.xml", "content": ""}},
    ],
)
def test_analyse_rejects_malformed_requests(payload):
    status, body = analyse(payload)
    assert status == 400
    assert body["error"].startswith("Invalid request")


@pytest.fixture
def server():
    srv = make_server(0)  # any free port
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _request(port, method, path, body=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    return resp.status, resp.getheaders(), resp.read()


def test_server_serves_page_with_security_headers(server):
    status, headers, body = _request(server, "GET", "/")
    assert status == 200
    assert b"Merge your scans" in body
    headers = dict(headers)
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_server_analyses_upload(server):
    status, _, body = _request(server, "POST", "/api/analyse", json.dumps(_payload()))
    assert status == 200
    assert json.loads(body)["summary"]["findings"] == 6


def test_server_rejects_foreign_host_header(server):
    # A page on another domain resolving to 127.0.0.1 (DNS rebinding) sends its own Host.
    status, _, _ = _request(server, "GET", "/", host="attacker.example:80")
    assert status == 403


def test_server_rejects_bad_json_and_unknown_paths(server):
    assert _request(server, "POST", "/api/analyse", "{nope")[0] == 400
    assert _request(server, "GET", "/etc/passwd")[0] == 404


def test_analyse_returns_warnings():
    status, body = analyse(_payload())
    assert status == 200 and body["warnings"] == []


def test_analyse_groups_by_vulnerability():
    _, body = analyse(_payload())
    assert len(body["vulnerabilities"]) == 6
    first = body["vulnerabilities"][0]
    assert (first["severity"], first["hosts"], first["affected"][0]["port"]) == ("Critical", 1, "80/tcp")
