"""Local web interface: `scanmerge-ui` serves one page on 127.0.0.1.

Uploads are processed in memory with the same parsers, merge and Excel writer
as the CLI; nothing is written to disk and the server never listens on the
network.
"""

import argparse
import base64
import io
import json
import re
import sys
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files

from . import __version__
from .excel import service_label, write_report
from .merge import merge
from .models import SEVERITIES
from .parsers import load_scans

# shortcut: the whole request is held in memory; raise this if audit files grow past it.
MAX_BODY = 100 * 1024 * 1024
MAX_NAME = 200
DEFAULT_PORT = 8780
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
    "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class BadRequest(ValueError):
    pass


def _upload(item) -> io.BytesIO:
    if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("content"), str):
        raise BadRequest("each file needs a name and base64 content")
    try:
        buf = io.BytesIO(base64.b64decode(item["content"], validate=True))
    except ValueError as e:
        raise BadRequest(f"{item['name'][:MAX_NAME]}: content is not valid base64") from e
    buf.name = item["name"].replace("\\", "/").rsplit("/", 1)[-1][:MAX_NAME] or "upload.xml"
    return buf


def analyse(payload) -> tuple[int, dict]:
    """Handle one /api/analyse request body; returns (HTTP status, JSON body)."""
    try:
        if not isinstance(payload, dict) or not isinstance(payload.get("nmap"), list) or not payload["nmap"]:
            raise BadRequest("send at least one Nmap file and the OpenVAS report")
        site = payload.get("site", "")
        if not isinstance(site, str):
            raise BadRequest("site must be text")
        nmap_files = [_upload(i) for i in payload["nmap"]]
        openvas_file = _upload(payload.get("openvas"))
    except BadRequest as e:
        return 400, {"error": f"Invalid request: {e}."}

    nmap, openvas, errors = load_scans(nmap_files, openvas_file)
    messages = [message for _, message in errors]
    if nmap is None and openvas is None:
        return 422, {"error": "No valid input file, nothing to report.", "errors": messages}

    site = site.strip()[:MAX_NAME]
    merged = merge(nmap, openvas)
    excel = io.BytesIO()
    write_report(excel, merged, site, [name for name, _ in errors])

    def gap(h) -> dict:
        ports = [f"{s.port} {service_label(merged, s.ip, s.port)}".strip() for s in merged.open_ports(h.ip)]
        return {"ip": h.ip, "hostname": h.hostname, "ports": ports}

    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", site).strip("_")
    return 200, {
        "site": site,
        "errors": messages,
        "summary": {
            "hosts_seen": len(merged.hosts),
            "analysed": len(merged.analysed) if merged.analysed is not None else None,
            "coverage_checked": merged.coverage_checked,
            "findings": len(merged.findings),
            "by_severity": {sev: sum(f.severity == sev for f in merged.findings) for sev in SEVERITIES},
        },
        "not_analysed": [gap(h) for h in merged.not_analysed],
        "not_in_nmap": [gap(h) for h in merged.not_in_nmap],
        "findings": [
            {
                "ip": f.ip,
                "hostname": f.hostname,
                "port": f.port,
                "service": service_label(merged, f.ip, f.port),
                "title": f.title,
                "cves": f.cves,
                "cvss": f.cvss,
                "severity": f.severity,
                "solution": f.solution,
            }
            for f in merged.findings
        ],
        "filename": f"scanmerge_{slug}.xlsx" if slug else "scanmerge_report.xlsx",
        "excel": base64.b64encode(excel.getvalue()).decode("ascii"),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = f"scanmerge/{__version__}"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: dict) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json")

    def _local_host(self) -> bool:
        # Blocks DNS rebinding: only accept requests addressed to the loopback name we serve on.
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def do_GET(self) -> None:
        if not self._local_host():
            return self._send(403, b"Forbidden", "text/plain; charset=utf-8")
        if self.path in ("/", "/index.html"):
            page = files("scanmerge").joinpath("static/index.html").read_bytes()
            return self._send(200, page, "text/html; charset=utf-8")
        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        if not self._local_host():
            return self._json(403, {"error": "Forbidden"})
        if self.path != "/api/analyse":
            return self._json(404, {"error": "Not found"})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._json(411, {"error": "Content-Length required"})
        if not 0 < length <= MAX_BODY:
            return self._json(413, {"error": f"Upload too large (limit {MAX_BODY // (1024 * 1024)} MB)"})
        try:
            payload = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return self._json(400, {"error": "Invalid request: body is not JSON."})
        try:
            status, data = analyse(payload)
        except Exception:  # never leak a traceback to the page; it goes to the server terminal
            self.log_error("analysis failed:\n%s", traceback.format_exc())
            status, data = 500, {"error": "Unexpected error while analysing the files."}
        self._json(status, data)


def make_server(port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="scanmerge-ui", description="Open the scanmerge web interface (local only).")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port on 127.0.0.1 (default {DEFAULT_PORT})")
    p.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    args = p.parse_args(argv)

    try:
        server = make_server(args.port)
    except OSError as e:
        print(f"error: cannot listen on 127.0.0.1:{args.port} ({e.strerror or e}); try --port", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"scanmerge UI running at {url} (only reachable from this computer). Press Ctrl+C to stop.")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
