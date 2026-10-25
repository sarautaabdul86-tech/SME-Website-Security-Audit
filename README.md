# SME Website Security Audit

A defensive, beginner-friendly security-header audit tool for websites you own or have explicit permission to assess.

## Features
- Checks HTTP response status and common security headers.
- Scores six recommended headers (0–100).
- Notes server/version disclosure where available.
- Produces a terminal summary and a JSON report.
- Optional Nmap service discovery for a local lab target, when Nmap is installed.

## Safety and scope
Only test systems you own or are explicitly authorized to assess. Start with a local lab such as `http://127.0.0.1:8080`.
This tool performs basic checks; it is not a penetration test and does not prove that a site is secure.

## Requirements
- Python 3.10+
- `requests` is not required; the main tool uses Python's standard library.
- Optional: Nmap installed separately for local lab service discovery.

## Run
```bash
python audit.py http://127.0.0.1:8080
```
For an authorized HTTPS site:
```bash
python audit.py https://your-authorized-domain.example
```
Replace the example with a target you own or have permission to assess.

Reports are saved in `reports/`. Do not commit reports containing private information, tokens, internal IPs, or client data.

## Project contents
- `audit.py` — main audit tool
- `install.sh` — basic Termux/Linux setup helper
- `lab/` — safe local test server with example security headers
- `capstone/` — project summary and before/after evidence template
- `reports/` — generated JSON reports
