# Security Policy

## Supported Versions

Security updates are applied to the latest minor version release branch:

| Version | Supported          |
| ------- | ------------------ |
| 0.6.x   | :white_check_mark: |
| < 0.6.0 | :x:                |

---

## Security Model of iam-shrink

`iam-shrink` is designed with a defense-in-depth posture:
* **Local Loopback Telemetry Only:** The default CSM listener binds exclusively to `127.0.0.1` and never opens external or WAN network listeners.
* **Ephemeral Certificates:** When using the optional HTTP/HTTPS interception proxy (`--proxy`), CA root certificates and intermediate signing certificates are generated ephemerally in memory or temporary files, never persisted across reboots, and cleaned up upon process exit.
* **No Telemetry Phone-Home:** `iam-shrink` never sends captured AWS telemetry, account numbers, or IAM policies to any external server. All analysis and synthesis happens 100% locally on your machine.

---

## Reporting a Vulnerability

If you discover a potential security vulnerability in `iam-shrink`, please do **not** open a public issue.

Instead, please report it via one of the following channels:
1. **GitHub Private Security Advisory:** Submit a confidential report via the [Security tab](https://github.com/smford/iam-shrink/security/advisories/new).
2. **Direct Email:** Reach out directly to the maintainers with reproduction steps and proof-of-concept details.

We commit to acknowledging your report within 48 hours and providing a remediation timeline before any public disclosure.
