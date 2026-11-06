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
    coverage_checked: bool  # False when one side had no valid file
    warnings: list[str]  # notes for the reader: input warnings plus merge checks

    def open_ports(self, ip: str) -> list[Service]:
        return sorted((s for (i, _), s in self.services.items() if i == ip), key=lambda s: port_key(s.port))


def merge(
    nmap: tuple[list[Host], list[Service]] | None,
    openvas: tuple[list[Host], list[Finding]] | None,
    warnings: list[str] | None = None,
) -> MergedScan:
    """Merge parsed inputs; pass None for a side with no valid file.

    Coverage gaps are only computed when both sides are present, otherwise
    every host would look like a gap. `warnings` (e.g. from load_scans) are
    carried into the result.
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
    notes = list(warnings or [])
    if both and seen_by_nmap and analysed and not seen_by_nmap & analysed:
        notes.append(
            "Nmap and OpenVAS have no host in common: check that both scans target the same network "
            "(wrong OpenVAS target, or files from different sites?)"
        )

    def by_ip(ips) -> list[Host]:
        return sorted((hosts[ip] for ip in ips), key=lambda h: ip_key(h.ip))

    return MergedScan(
        hosts=by_ip(hosts),
        services=merged_services,
        findings=sorted_findings,
        analysed=analysed,
        not_analysed=by_ip(seen_by_nmap - analysed) if both else [],
        not_in_nmap=by_ip(analysed - seen_by_nmap) if both else [],
        coverage_checked=both,
        warnings=notes,
    )


@dataclass
class Vulnerability:
    """One issue (NVT) with every host/port it affects, for remediation planning."""

    title: str
    cvss: float | None
    severity: str
    cves: list[str]
    solution: str
    affected: list[Finding]

    @property
    def host_count(self) -> int:
        return len({f.ip for f in self.affected})


def by_vulnerability(findings: list[Finding]) -> list[Vulnerability]:
    """Group findings by NVT (title when the OID is missing), most severe and widespread first."""
    groups: dict[str, Vulnerability] = {}
    for f in findings:
        g = groups.get(f.nvt_oid or f.title)
        if g is None:
            groups[f.nvt_oid or f.title] = Vulnerability(f.title, f.cvss, f.severity, list(f.cves), f.solution, [f])
            continue
        g.affected.append(f)
        g.cves = sorted(set(g.cves) | set(f.cves))
        g.solution = g.solution or f.solution
        if (f.cvss or 0) > (g.cvss or 0):
            g.cvss, g.severity = f.cvss, f.severity
    return sorted(
        groups.values(),
        key=lambda g: (SEVERITIES.index(g.severity), -(g.cvss or 0), -g.host_count, g.title),
    )
