# SME Website Security Audit — Capstone Summary

## Objective
Demonstrate a defensive workflow for checking common HTTP security headers, recording results, recommending remediation, and validating changes in a controlled local lab.

## Method
1. Start a local test website.
2. Run the header audit against `http://127.0.0.1:8080`.
3. Review the score and missing-header recommendations.
4. Configure the lab server headers.
5. Run the audit again and compare results.

## Six headers assessed
- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Important note
Earlier project records described a successful local validation with all six headers detected and a 100/100 header score. This recovery bundle is a reconstructed version, so rerun it and capture fresh output before claiming its current results. Do not represent sample or historical results as a new test.

Only test systems you own or have written permission to assess.
