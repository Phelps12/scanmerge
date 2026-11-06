"""Parse Nmap and OpenVAS/GVM XML into the normalised model.

Input files are untrusted: everything goes through defusedxml, which rejects
entity declarations (XXE, billion laughs) and external references.
"""

from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, parse

from .models import Host, Service


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
