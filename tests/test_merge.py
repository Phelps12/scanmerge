from pathlib import Path

from scanmerge.merge import ip_key, merge
from scanmerge.models import Finding, Host, Service
from scanmerge.parsers import parse_nmap, parse_openvas

FIXTURES = Path(__file__).parent / "fixtures"


def _nmap():
    tcp_hosts, tcp_services = parse_nmap(FIXTURES / "nmap_store_tcp.xml")
    udp_hosts, udp_services = parse_nmap(FIXTURES / "nmap_store_udp.xml")
    return tcp_hosts + udp_hosts, tcp_services + udp_services


def test_merges_hosts_from_both_sources():
    result = merge(_nmap(), parse_openvas(FIXTURES / "openvas_store.xml"))
    by_ip = {h.ip: h for h in result.hosts}

    assert list(by_ip) == ["192.0.2.10", "192.0.2.20", "192.0.2.30", "198.51.100.5", "198.51.100.7"]
    assert by_ip["192.0.2.10"].sources == {"nmap", "openvas"}
    assert by_ip["192.0.2.30"].sources == {"nmap"}
    assert [s.port for s in result.open_ports("192.0.2.20")] == ["80/tcp", "445/tcp", "161/udp"]


def test_deduplicates_same_host_port_and_nvt():
    result = merge(_nmap(), parse_openvas(FIXTURES / "openvas_store.xml"))
    heartbleed = [f for f in result.findings if "CVE-2014-0160" in f.cves]
    assert len(heartbleed) == 1
    assert len(result.findings) == 6


def test_same_nvt_on_other_port_is_kept():
    findings = [
        Finding("192.0.2.10", "443/tcp", "TLS weak", 5.0, [], "", "openvas", "oid.1"),
        Finding("192.0.2.10", "8443/tcp", "TLS weak", 5.0, [], "", "openvas", "oid.1"),
        Finding("192.0.2.10", "443/tcp", "TLS weak", 5.0, [], "", "openvas", "oid.1"),
    ]
    result = merge(None, ([Host("192.0.2.10", "", {"openvas"})], findings))
    assert [f.port for f in result.findings] == ["443/tcp", "8443/tcp"]


def test_coverage_gaps_in_both_directions():
    result = merge(_nmap(), parse_openvas(FIXTURES / "openvas_store.xml"))

    # up in Nmap, never analysed by OpenVAS
    assert [h.ip for h in result.not_analysed] == ["192.0.2.30"]
    # analysed by OpenVAS but not seen by Nmap
    assert [h.ip for h in result.not_in_nmap] == ["198.51.100.7"]
    # 198.51.100.5 has no OpenVAS results but was analysed: not a gap
    assert "198.51.100.5" in result.analysed


def test_no_gaps_reported_when_one_side_is_missing():
    only_nmap = merge(_nmap(), None)
    assert only_nmap.analysed is None
    assert only_nmap.not_analysed == [] and only_nmap.not_in_nmap == []

    only_openvas = merge(None, parse_openvas(FIXTURES / "openvas_store.xml"))
    assert only_openvas.not_in_nmap == []


def test_sorted_by_severity_then_cvss_then_ip():
    result = merge(_nmap(), parse_openvas(FIXTURES / "openvas_store.xml"))
    assert [(f.severity, f.cvss, f.ip) for f in result.findings] == [
        ("Critical", 9.8, "192.0.2.20"),
        ("High", 8.1, "198.51.100.7"),
        ("High", 7.5, "192.0.2.10"),
        ("Medium", 5.0, "192.0.2.20"),
        ("Low", 2.6, "192.0.2.10"),
        ("Log", 0.0, "192.0.2.20"),
    ]


def test_ip_sort_is_numeric_and_handles_ipv6():
    ips = ["192.0.2.100", "2001:db8::1", "192.0.2.9", "not-an-ip"]
    assert sorted(ips, key=ip_key) == ["192.0.2.9", "192.0.2.100", "2001:db8::1", "not-an-ip"]


def test_service_with_version_wins_over_bare_duplicate():
    hosts = [Host("192.0.2.10", "", {"nmap"})]
    services = [Service("192.0.2.10", "22/tcp", "ssh", ""), Service("192.0.2.10", "22/tcp", "ssh", "OpenSSH 9.6")]
    result = merge((hosts, services), None)
    assert result.services[("192.0.2.10", "22/tcp")].version == "OpenSSH 9.6"


def test_finding_hostname_filled_from_nmap():
    result = merge(_nmap(), parse_openvas(FIXTURES / "openvas_store.xml"))
    ssh = next(f for f in result.findings if f.port == "22/tcp")
    assert ssh.hostname == "fw.example.test"


def test_warns_when_nmap_and_openvas_share_no_host():
    nmap = ([Host("192.0.2.10", "", {"nmap"})], [])
    openvas = ([Host("198.51.100.10", "", {"openvas"})], [])
    result = merge(nmap, openvas, ["input note"])
    assert result.warnings[0] == "input note"
    assert "no host in common" in result.warnings[1]


def test_no_overlap_warning_when_hosts_match():
    result = merge(_nmap(), parse_openvas(FIXTURES / "openvas_store.xml"))
    assert result.warnings == []
