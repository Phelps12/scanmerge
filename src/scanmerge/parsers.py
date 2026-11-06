"""Parse Nmap and OpenVAS/GVM XML into the normalised model.

Input files are untrusted: everything goes through defusedxml, which rejects
entity declarations (XXE, billion laughs) and external references.
"""

from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, parse

from .models import Finding, Host, Service


class ScanParseError(ValueError):
    """An input file could not be used; the message is meant for the user."""


def _load(path: str | Path) -> Element:
    try:
        return parse(str(path)).getroot()
    except DefusedXmlException as e:
        raise ScanParseError(f"{path}: rejected unsafe XML ({type(e).__name__})") from e
    except ParseError as e:
        raise ScanParseError(f"{path}: malformed XML ({e})") from e
    except OSError as e:
        raise ScanParseError(f"{path}: cannot read file ({e.strerror or e})") from e


def parse_nmap(path: str | Path) -> tuple[list[Host], list[Service]]:
    """Return the hosts that are up and their open ports from an `nmap -oX` file."""
    root = _load(path)
    if root.tag != "nmaprun":
        raise ScanParseError(f"{path}: not an Nmap XML file (root element <{root.tag}>)")

    hosts: list[Host] = []
    services: list[Service] = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = next(
            (a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")),
            None,
        )
        if not ip:
            continue
        name = h.find("hostnames/hostname")
        hosts.append(Host(ip, name.get("name", "") if name is not None else "", {"nmap"}))

        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            attrs = svc.attrib if svc is not None else {}
            version = " ".join(v for v in (attrs.get("product"), attrs.get("version")) if v)
            port = f"{p.get('portid', '')}/{p.get('protocol', '')}"
            services.append(Service(ip, port, attrs.get("name", ""), version))
    return hosts, services


def _text(el: Element | None, path: str) -> str:
    found = el.find(path) if el is not None else None
    return (found.text or "").strip() if found is not None else ""


def _float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def _tag(tags: str, key: str) -> str:
    """Read one key from GVM's pipe-separated `<tags>` text (key=value|key=value)."""
    for part in tags.split("|"):
        name, _, value = part.partition("=")
        if name == key:
            return value.strip()
    return ""


def _cves(nvt: Element | None) -> list[str]:
    if nvt is None:
        return []
    cves = [r.get("id", "") for r in nvt.findall("refs/ref") if r.get("type", "").lower() == "cve"]
    if not cves:  # older GVM: comma-separated <cve> text, "NOCVE" when empty
        cves = [c.strip() for c in _text(nvt, "cve").split(",")]
    return sorted({c for c in cves if c and c.upper() != "NOCVE"})


def parse_openvas(path: str | Path) -> tuple[list[Host], list[Finding]]:
    """Return the analysed hosts and the results of an OpenVAS/GVM XML report.

    A host counts as analysed if the report lists it under <host>, even with no
    results; hosts that only appear in results are added too.
    """
    root = _load(path)
    if root.tag not in ("report", "get_reports_response"):
        raise ScanParseError(f"{path}: not an OpenVAS/GVM report (root element <{root.tag}>)")

    hosts: dict[str, Host] = {}
    for report in root.iter("report"):
        for h in report.findall("host"):
            ip = _text(h, "ip")
            if ip:
                hostname = _text(h, "detail[name='hostname']/value")
                hosts.setdefault(ip, Host(ip, hostname, {"openvas"}))

    findings: list[Finding] = []
    for r in root.iterfind(".//results/result"):
        host_el = r.find("host")
        ip = (host_el.text or "").strip() if host_el is not None else ""
        if not ip:
            continue
        nvt = r.find("nvt")
        tags = _text(nvt, "tags")
        severity = _float(_text(r, "severity"))
        if severity is None:
            severity = _float(_text(nvt, "cvss_base"))
        hostname = _text(host_el, "hostname")
        findings.append(
            Finding(
                ip=ip,
                port=_text(r, "port"),
                title=_text(nvt, "name") or _text(r, "name"),
                cvss=severity,
                cves=_cves(nvt),
                solution=_text(nvt, "solution") or _tag(tags, "solution"),
                source="openvas",
                nvt_oid=nvt.get("oid", "") if nvt is not None else "",
                hostname=hostname,
            )
        )
        host = hosts.setdefault(ip, Host(ip, hostname, {"openvas"}))
        host.hostname = host.hostname or hostname
    return list(hosts.values()), findings
