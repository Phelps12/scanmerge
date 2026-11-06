from pathlib import Path

import pytest

from scanmerge.models import Service
from scanmerge.parsers import ScanParseError, parse_nmap, parse_openvas

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_nmap_keeps_up_hosts_and_open_ports():
    hosts, services = parse_nmap(FIXTURES / "nmap_store_tcp.xml")

    assert [h.ip for h in hosts] == ["192.0.2.10", "192.0.2.20", "192.0.2.30", "198.51.100.5"]
    assert hosts[0].hostname == "fw.example.test"
    assert hosts[1].hostname == ""
    assert all(h.sources == {"nmap"} for h in hosts)

    assert Service("192.0.2.10", "22/tcp", "ssh", "OpenSSH 7.4") in services
    assert Service("192.0.2.20", "445/tcp", "microsoft-ds", "") in services
    assert not any(s.port == "8080/tcp" for s in services)  # closed
    assert not any(s.ip == "192.0.2.40" for s in services)  # down


def test_parse_nmap_udp_ignores_open_filtered():
    _, services = parse_nmap(FIXTURES / "nmap_store_udp.xml")
    assert services == [Service("192.0.2.20", "161/udp", "snmp", "net-snmp")]


def test_malformed_xml_is_rejected():
    with pytest.raises(ScanParseError, match="malformed XML"):
        parse_nmap(FIXTURES / "malformed.xml")


def test_external_entity_is_rejected():
    with pytest.raises(ScanParseError, match="rejected unsafe XML"):
        parse_nmap(FIXTURES / "xxe.xml")


def test_missing_file_is_reported(tmp_path):
    with pytest.raises(ScanParseError, match="cannot read file"):
        parse_nmap(tmp_path / "nope.xml")


def test_wrong_root_element_is_rejected(tmp_path):
    other = tmp_path / "other.xml"
    other.write_text("<report/>")
    with pytest.raises(ScanParseError, match="not an Nmap XML file"):
        parse_nmap(other)


def test_parse_openvas_counts_hosts_without_results_as_analysed():
    hosts, _ = parse_openvas(FIXTURES / "openvas_store.xml")
    by_ip = {h.ip: h for h in hosts}

    assert set(by_ip) == {"192.0.2.10", "192.0.2.20", "198.51.100.5", "198.51.100.7"}
    assert by_ip["192.0.2.10"].hostname == "fw.example.test"
    assert by_ip["198.51.100.5"].sources == {"openvas"}  # analysed, no results


def test_parse_openvas_results():
    _, findings = parse_openvas(FIXTURES / "openvas_store.xml")
    assert len(findings) == 7  # dedupe happens in the merge step

    apache = findings[0]
    assert apache.ip == "192.0.2.20"
    assert apache.port == "80/tcp"
    assert apache.cvss == 9.8
    assert apache.severity == "Critical"
    assert apache.cves == ["CVE-2021-41773", "CVE-2021-42013"]
    assert apache.solution == "Update to version 2.4.51 or later."
    assert apache.nvt_oid == "1.3.6.1.4.1.25623.1.0.900001"
    assert apache.source == "openvas"

    heartbleed = findings[1]
    assert heartbleed.solution == "Update OpenSSL to 1.0.1g or later."  # from <tags>
    assert heartbleed.hostname == "fw.example.test"


def test_parse_openvas_tolerates_missing_fields_and_old_cve_format(tmp_path):
    report = tmp_path / "old.xml"
    report.write_text(
        "<report><report><results><result>"
        "<host>192.0.2.99</host>"
        "<nvt><name>Old style</name><cvss_base>4.3</cvss_base><cve>CVE-2016-2183, NOCVE</cve></nvt>"
        "</result><result><port>80/tcp</port></result></results></report></report>"
    )
    hosts, findings = parse_openvas(report)

    assert [h.ip for h in hosts] == ["192.0.2.99"]
    assert len(findings) == 1  # the result without a host is skipped
    f = findings[0]
    assert (f.port, f.cvss, f.cves, f.solution, f.nvt_oid) == ("", 4.3, ["CVE-2016-2183"], "", "")


def test_openvas_rejects_external_entity():
    with pytest.raises(ScanParseError, match="rejected unsafe XML"):
        parse_openvas(FIXTURES / "xxe.xml")


def test_openvas_rejects_nmap_file():
    with pytest.raises(ScanParseError, match="not an OpenVAS/GVM report"):
        parse_openvas(FIXTURES / "nmap_store_tcp.xml")
