# Security Policy

## Supported Versions

Rudras is proprietary, closed-source software. Security updates are provided only for actively maintained versions under a valid license. Users on unsupported versions should upgrade immediately, as no patches — including for critical vulnerabilities — will be backported.

| Version | Supported          |
| ------- | ------------------ |
| 4.1.x   | :white_check_mark: |
| 4.0.x   | :white_check_mark: |
| 3.x.x   | :x:                |
| < 3.0   | :x:                |

## Reporting a Vulnerability

Rudras operates directly in the kernel packet path (WFP/WinDivert) with elevated privileges. **Do not open a public GitHub issue for security vulnerabilities.** As proprietary software, vulnerability details and any proof-of-concept material are confidential and must not be disclosed publicly, shared with third parties, or posted in any public forum at any time — before or after a fix ships.

### How to Report

- Email: **security@[project-domain]** (PGP key available on request — include "Rudras Vulnerability" in the subject line)
- Alternatively, use GitHub's [private vulnerability reporting](https://github.com/DeepakKrishna-DK/Rudras_/security/advisories/new) feature on this repository, restricted to authorized collaborators

Please include:

- A clear description of the vulnerability and its impact (e.g., privilege escalation, filter bypass, DoS, memory corruption)
- Steps to reproduce, including affected version, OS build, and configuration (`rudras.toml` excerpt if relevant)
- Proof-of-concept code or packet captures, if available
- Your assessment of severity (CVSS score preferred but not required)

### Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Initial acknowledgment | Within 48 hours |
| Preliminary triage & severity assessment | Within 5 business days |
| Status updates | At least every 7 days until resolved |
| Fix (Critical/High severity) | Target 30 days |
| Fix (Medium/Low severity) | Target 90 days |

### Disclosure Policy

- This is proprietary software with **no public disclosure**. Vulnerability reports, technical details, and proof-of-concept material remain confidential indefinitely and may only be shared with the project owner and individuals directly involved in remediation.
- Reporters must not disclose the vulnerability publicly, to any third party, or on any public platform (including social media, blogs, security mailing lists, or CVE databases) without prior written authorization from the project owner, regardless of whether a fix has been released.
- Internal security advisories or changelog entries (if issued) will describe the fix at a general level without reproducing exploit details, and are shared only with licensed users on a need-to-know basis.
- If a vulnerability is under active exploitation, notify the project owner immediately via the reporting channel above; response will be expedited accordingly.

### Scope

**In scope:**
- The core Rust firewall engine (packet interception, CyberImmune ML engine, rule evaluation, genetic algorithm rule persistence)
- The Next.js SOC Dashboard and its API layer
- Configuration parsing (`rudras.toml`) and IOC feed ingestion
- Privilege handling, WFP/WinDivert integration, and any component that could enable filter bypass, sandbox escape, or unauthorized process/network control

**Out of scope:**
- Vulnerabilities requiring physical access to an already-compromised host
- Denial of service via brute-force resource exhaustion without a novel bypass
- Issues in third-party dependencies without a demonstrated Rudras-specific exploit path (report upstream instead)
- Social engineering or attacks against infrastructure not part of this repository

### Accepted vs. Declined Reports

- **Accepted:** You'll receive a tracking reference and regular status updates until resolution. Given the proprietary nature of this project, public credit is not issued by default; any acknowledgment is at the sole discretion of the project owner and only with the reporter's explicit written consent.
- **Declined (not a vulnerability, out of scope, or already known):** You'll receive a written explanation of the decision. You're welcome to request reconsideration with additional evidence.

### Authorized Testing & Safe Harbor

Rudras is licensed, proprietary software. Security research is permitted **only** against instances you own, operate under a valid license, or have explicit written authorization to test. Testing against third-party deployments without permission is prohibited and may violate the License Agreement and applicable law (e.g., CFAA, CMA, Computer Misuse laws).

Within this authorized scope, we will not pursue legal action against researchers who:
- Test only against systems they own, license, or are explicitly authorized to test
- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption
- Report findings promptly through the private channel above and do not exploit the vulnerability beyond what's needed to demonstrate it
- Comply with the confidentiality and non-disclosure terms above
- Do not access, retain, or exfiltrate data belonging to other users or licensees

This safe harbor does not waive any provision of the Rudras License Agreement and applies solely to good-faith security research conducted within the terms above.
