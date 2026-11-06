from pathlib import Path

import pytest

from scanmerge.models import Service
from scanmerge.parsers import ScanParseError, parse_nmap

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
