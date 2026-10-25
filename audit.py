#!/usr/bin/env python3
"""SME Website Security Audit — conservative security-header assessment."""
import argparse
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html import escape

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps browsers enforce HTTPS on HTTPS-ready sites.",
    "Content-Security-Policy": "Restricts the sources from which a page may load content.",
    "X-Frame-Options": "Helps prevent unauthorized framing/clickjacking.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing when set to nosniff.",
    "Referrer-Policy": "Controls referrer information sent by browsers.",
    "Permissions-Policy": "Restricts browser features the site does not need.",
}

def validate_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target must be a full http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("Do not place credentials in the target URL.")
    return parsed

def fetch_headers(url, timeout):
    request = urllib.request.Request(
        url, headers={"User-Agent": "SME-Website-Security-Audit/1.0"}, method="GET"
    )
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
        with response:
            return response.status, dict(response.headers.items()), response.geturl(), None
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()) if exc.headers else {}, exc.geturl(), f"HTTP error: {exc.code}"
    except Exception as exc:
        return None, {}, url, f"{type(exc).__name__}: {exc}"

def main():
    parser = argparse.ArgumentParser(description="Audit basic HTTP security headers on an authorized target.")
    parser.add_argument("url", help="Target URL you own or are authorized to assess")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--output-dir", default="reports", help="Directory for JSON reports")
    parser.add_argument("--nmap-local", action="store_true",
                        help="Run a small Nmap service check only when target hostname is localhost/loopback")
    args = parser.parse_args()

    try:
        parsed = validate_url(args.url)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    status, headers, final_url, error = fetch_headers(args.url, max(1, min(args.timeout, 30)))
    header_lookup = {k.lower(): v for k, v in headers.items()}
    results = []
    for name, purpose in SECURITY_HEADERS.items():
        value = header_lookup.get(name.lower())
        present = bool(value and value.strip())
        results.append({
            "header": name, "present": present,
            "value": value if present else None, "purpose": purpose,
            "recommendation": None if present else f"Review and configure {name} appropriately."
        })

    score = round(100 * sum(1 for item in results if item["present"]) / len(results))
    missing = [item["header"] for item in results if not item["present"]]
    server_header = header_lookup.get("server")
    risk = "LOW" if score >= 83 else "MODERATE" if score >= 50 else "HIGH"
    report = {
        "project": "SME Website Security Audit",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": args.url,
        "final_url": final_url,
        "http_status": status,
        "request_error": error,
        "security_header_score": score,
        "security_header_risk": risk,
        "headers_present": len(results) - len(missing),
        "headers_assessed": len(results),
        "missing_headers": missing,
        "server_header": server_header,
        "server_disclosure_note": "Review whether server/version details are unnecessarily exposed." if server_header else None,
        "headers": results,
        "limitations": [
            "This is a basic configuration check, not a full security assessment.",
            "A score does not guarantee that an application is secure.",
            "HSTS should only be enabled after HTTPS is correctly configured."
        ]
    }

    if args.nmap_local:
        host = (parsed.hostname or "").lower()
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            ip = ""
        if host not in ("localhost",) and not ip.startswith("127."):
            print("Skipping Nmap: --nmap-local is restricted to localhost/loopback targets.")
        elif subprocess.run(["sh", "-c", "command -v nmap >/dev/null 2>&1"]).returncode == 0:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            proc = subprocess.run(["nmap", "-sT", "-Pn", "-p", str(port), "127.0.0.1"],
                                  capture_output=True, text=True, timeout=20)
            report["local_nmap_output"] = (proc.stdout + proc.stderr)[-5000:]
        else:
            print("Nmap not installed; skipping optional local service check.")

    os.makedirs(args.output_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(args.output_dir, f"audit_{stamp}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n=== SME WEBSITE SECURITY AUDIT ===")
    print(f"Target: {args.url}")
    print(f"HTTP status: {status if status is not None else 'Unavailable'}")
    if error:
        print(f"Request note: {error}")
    print(f"Security header score: {score}/100")
    print(f"Header risk: {risk}")
    print(f"Headers present: {len(results)-len(missing)}/{len(results)}")
    if missing:
        print("Missing/review: " + ", ".join(missing))
    else:
        print("All six assessed headers were detected.")
    if server_header:
        print(f"Server header: {server_header} (review potential version disclosure)")
    print(f"JSON report saved: {report_path}")
    print("\nReminder: assess only systems you own or are authorized to test.")
    return 0 if status is not None else 1

if __name__ == "__main__":
    raise SystemExit(main())
