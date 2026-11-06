"""Join Nmap and OpenVAS data by IP, then port/protocol, and find coverage gaps."""

from dataclasses import dataclass
from ipaddress import ip_address

from .models import SEVERITIES, Finding, Host, Service


def ip_key(ip: str) -> tuple:
    """Numeric sort key; IPv4 before IPv6, unparsable values last."""
    try:
        addr = ip_address(ip)
        return (addr.version, int(addr), "")
    except ValueError:
        return (99, 0, ip)


def port_key(port: str) -> tuple:
    number, _, proto = port.partition("/")
    return (proto, int(number) if number.isdigit() else 1 << 17, number)


@dataclass
class MergedScan:
    hosts: list[Host]  # every host seen by any source, sorted by IP
    services: dict[tuple[str, str], Service]  # (ip, "443/tcp") -> service
    findings: list[Finding]  # deduplicated and sorted
    analysed: set[str] | None  # IPs OpenVAS analysed; None without OpenVAS input
    not_analysed: list[Host]  # up in Nmap, not analysed by OpenVAS
    not_in_nmap: list[Host]  # analysed by OpenVAS, not seen by Nmap

    def open_ports(self, ip: str) -> list[Service]:
        return sorted((s for (i, _), s in self.services.items() if i == ip), key=lambda s: port_key(s.port))


def merge(
    nmap: tuple[list[Host], list[Service]] | None,
    openvas: tuple[list[Host], list[Finding]] | None,
) -> MergedScan:
    """Merge parsed inputs; pass None for a side with no valid file.

    Coverage gaps are only computed when both sides are present, otherwise
    every host would look like a gap.
    """
    nmap_hosts, services = nmap or ([], [])
    openvas_hosts, findings = openvas or ([], [])

    hosts: dict[str, Host] = {}
    for h in [*nmap_hosts, *openvas_hosts]:
        cur = hosts.setdefault(h.ip, Host(h.ip))
        cur.hostname = cur.hostname or h.hostname
        cur.sources |= h.sources

    merged_services: dict[tuple[str, str], Service] = {}
    for s in services:
        key = (s.ip, s.port)
        if key not in merged_services or (s.version and not merged_services[key].version):
            merged_services[key] = s

    unique: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        unique.setdefault((f.ip, f.port, f.nvt_oid or f.title), f)
    for f in unique.values():
        if not f.hostname and f.ip in hosts:
            f.hostname = hosts[f.ip].hostname
    sorted_findings = sorted(
        unique.values(),
        key=lambda f: (SEVERITIES.index(f.severity), -(f.cvss or 0), ip_key(f.ip), port_key(f.port), f.title),
    )

    analysed = {h.ip for h in openvas_hosts} if openvas is not None else None
    seen_by_nmap = {h.ip for h in nmap_hosts}
    both = nmap is not None and openvas is not None

    def by_ip(ips) -> list[Host]:
        return sorted((hosts[ip] for ip in ips), key=lambda h: ip_key(h.ip))

    return MergedScan(
        hosts=by_ip(hosts),
        services=merged_services,
        findings=sorted_findings,
        analysed=analysed,
        not_analysed=by_ip(seen_by_nmap - analysed) if both else [],
        not_in_nmap=by_ip(analysed - seen_by_nmap) if both else [],
    )
