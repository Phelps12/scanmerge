# Changelog

## 0.2.0 (2026-11-06)

- Local web interface: `scanmerge-ui` serves a page on 127.0.0.1 to import the files, see coverage gaps and severity counts, browse findings and download the Excel report.
- Findings grouped by vulnerability: new "By vulnerability" sheet, a distinct count in the Summary and a grouped view in the web UI.
- Warnings when the OpenVAS export was filtered (fewer results than the scan found) and when Nmap and OpenVAS share no host (wrong target or files from different sites).
- Parsers accept in-memory uploads; the CI runs the tests on Ubuntu and Windows with Python 3.11 to 3.14.

## 0.1.0 (2026-11-06)

- First release: CLI that merges Nmap and OpenVAS/GVM XML into an Excel report with Non-conformities, Coverage gaps and Summary sheets.
- Safe XML parsing with defusedxml (rejects XXE and other entity attacks).
- Deduplication by host + port + NVT, coverage gaps in both directions, sorting by severity, CVSS and IP.
