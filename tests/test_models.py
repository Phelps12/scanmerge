import pytest

from scanmerge.models import Finding, severity_from_cvss


@pytest.mark.parametrize(
    "cvss, expected",
    [
        (None, "Log"),
        (-1.0, "Log"),  # GVM uses negative scores for false positives and errors
        (0.0, "Log"),
        (0.1, "Low"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
        (10.0, "Critical"),
    ],
)
def test_severity_from_cvss(cvss, expected):
    assert severity_from_cvss(cvss) == expected


def test_finding_severity_follows_cvss():
    f = Finding("192.0.2.10", "443/tcp", "Heartbleed", 7.5, ["CVE-2014-0160"], "", "openvas")
    assert f.severity == "High"
