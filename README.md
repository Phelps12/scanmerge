# scanmerge

[![tests](https://github.com/Phelps12/scanmerge/actions/workflows/tests.yml/badge.svg)](https://github.com/Phelps12/scanmerge/actions/workflows/tests.yml)

Merge Nmap and OpenVAS/GVM results into an Excel non-conformity report and flag coverage gaps.

## The problem

A network audit usually runs Nmap to discover hosts and OpenVAS/GVM to scan them for vulnerabilities, then someone merges both into a spreadsheet by hand. That is slow, and it hides a dangerous case: **a host that Nmap saw up but OpenVAS never analysed**. Nothing warns you, and the report looks clean for a machine nobody tested.

scanmerge does the merge and reports those blind spots:

- joins hosts by IP, then by port/protocol, across several Nmap files and one OpenVAS report;
- deduplicates findings (same host + port + NVT);
- flags hosts **up in Nmap but not analysed by OpenVAS**, and the reverse (analysed by OpenVAS but not seen by Nmap). A host counts as analysed when the report lists it under `<host>`, even if it has no results;
- sorts by severity, then CVSS, then IP;
- writes an Excel workbook ready for follow-up.

Input XML is treated as untrusted: it is parsed with [defusedxml](https://pypi.org/project/defusedxml/), so files with entity declarations (XXE, billion laughs) are rejected, and text from the scans is always written to Excel as text, never as a formula.

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/Phelps12/scanmerge.git
cd scanmerge
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[test]"
pytest
```

## Usage

Produce the inputs:

```bash
nmap -sV -oX scan_tcp.xml 192.0.2.0/24
nmap -sU --top-ports 50 -oX scan_udp.xml 192.0.2.0/24
```

In GSA, open the report and download it with the **XML** report format (or use `get_reports` over GMP).

Then merge them:

```bash
scanmerge --nmap scan_tcp.xml --nmap scan_udp.xml --openvas report.xml --site "Store A" -o reports/store_a.xlsx
```

| Option | |
|---|---|
| `--nmap FILE` | Nmap XML (`-oX`). Repeat for several files. Required. |
| `--openvas FILE` | OpenVAS/GVM report exported as XML. Required. |
| `--site NAME` | Network or site name, written to every row. |
| `-o FILE.xlsx` | Excel file to write. Required. |

An invalid input file (malformed, unsafe or unreadable) is skipped with an error on stderr and listed in the Summary sheet. If the OpenVAS report or all the Nmap files are invalid, the coverage check is skipped rather than flagging every host.

Exit codes: `0` report written, `1` no valid input file or the report could not be written, `2` invalid arguments.

### Web interface

For people who prefer not to use the terminal, the same merge runs behind a local web page:

```bash
scanmerge-ui
```

It opens `http://127.0.0.1:8780/` in the browser (`--port` to change it, `--no-browser` to skip opening). The page has three steps: add the Nmap files and the OpenVAS report, see the coverage gaps and the count per severity, then browse the findings by severity and download the Excel report, identical to the CLI one. Stop it with Ctrl+C.

The server only listens on 127.0.0.1, so other machines on the network cannot reach it. Uploads are processed in memory and never written to disk. It uses only the Python standard library, the page loads nothing from the internet, and requests sent with a foreign `Host` header are refused (DNS rebinding).

Scan results and reports contain sensitive network data: `.gitignore` excludes `*.xml`, `*.xlsx` and `reports/` (except the synthetic test fixtures).

## Example output

Using the synthetic fixtures in `tests/fixtures/` (documentation IP ranges, public CVEs):

```text
$ scanmerge --nmap tests/fixtures/nmap_store_tcp.xml --nmap tests/fixtures/nmap_store_udp.xml \
    --openvas tests/fixtures/openvas_store.xml --site "Store A" -o reports/demo.xlsx
Site: Store A
Hosts seen: 5 | analysed by OpenVAS: 4 | coverage gaps: 1
Findings: 6 (Critical 1, High 2, Medium 1, Low 1, Log 1)
WARNING: 192.0.2.30 (pos01.example.test) is up in Nmap but was not analysed by OpenVAS
WARNING: 198.51.100.7 was analysed by OpenVAS but not seen by Nmap
Report written to reports/demo.xlsx
```

The workbook has three sheets:

1. **Non-conformities**: one row per finding, with columns filled by the tool (Network/Site, Host, Hostname, Port, Service, Title, CVE(s), CVSS, Severity, Source, Solution) and empty columns to fill in by hand (Recommendation, Cost, Owner, Deadline, Status). Frozen header, filters, severity colours.

   | Host | Port | Service | Title | CVE(s) | CVSS | Severity |
   |---|---|---|---|---|---|---|
   | 192.0.2.20 | 80/tcp | http (Apache httpd 2.4.49) | Apache HTTP Server 2.4.49 Path Traversal and RCE | CVE-2021-41773, CVE-2021-42013 | 9.8 | Critical |
   | 198.51.100.7 | 445/tcp | | Microsoft SMBv1 Remote Code Execution (MS17-010) | CVE-2017-0144 | 8.1 | High |
   | 192.0.2.10 | 443/tcp | https (nginx 1.18.0) | OpenSSL TLS 'heartbeat' Extension Information Disclosure (Heartbleed) | CVE-2014-0160 | 7.5 | High |

2. **Coverage gaps**: hosts not analysed by OpenVAS, with the open ports Nmap saw, plus hosts analysed by OpenVAS but missing from Nmap.

   | Gap | Host | Hostname | Open ports (Nmap) |
   |---|---|---|---|
   | Not analysed by OpenVAS | 192.0.2.30 | pos01.example.test | 3389/tcp ms-wbt-server |
   | Not seen by Nmap | 198.51.100.7 | | |

3. **Summary**: counts by severity, hosts seen, hosts analysed and coverage gaps.

Severity follows the CVSS score: 0 = Log, 0.1–3.9 = Low, 4.0–6.9 = Medium, 7.0–8.9 = High, 9.0–10 = Critical.

## Development

```text
src/scanmerge/
  models.py    Host, Service, Finding and the CVSS → severity mapping
  parsers.py   Nmap and OpenVAS/GVM XML parsing (defusedxml)
  merge.py     join, deduplication, coverage gaps, sorting
  excel.py     the three-sheet workbook
  cli.py       command line
  web.py       local web interface (scanmerge-ui) and its /api/analyse endpoint
  static/      the single-page UI
tests/         pytest suite; fixtures are synthetic
```

## License

[MIT](LICENSE)
