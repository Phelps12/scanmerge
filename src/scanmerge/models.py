"""Normalised records shared by the parsers, the merge step and the report."""

from dataclasses import dataclass, field

# Most severe first: this order drives sorting and the summary.
SEVERITIES = ("Critical", "High", "Medium", "Low", "Log")


def severity_from_cvss(cvss: float | None) -> str:
    """Map a CVSS score to a severity band (missing or <= 0 is Log)."""
    if cvss is None or cvss <= 0:
        return "Log"
    if cvss < 4.0:
        return "Low"
    if cvss < 7.0:
        return "Medium"
    if cvss < 9.0:
        return "High"
    return "Critical"


@dataclass
class Host:
    ip: str
    hostname: str = ""
    sources: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Service:
    ip: str
    port: str  # "443/tcp"
    service: str = ""
    version: str = ""


@dataclass
class Finding:
    ip: str
    port: str  # "443/tcp", or GVM pseudo-ports such as "general/tcp"
    title: str
    cvss: float | None
    cves: list[str]
    solution: str
    source: str
    nvt_oid: str = ""
    hostname: str = ""

    @property
    def severity(self) -> str:
        return severity_from_cvss(self.cvss)
