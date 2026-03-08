# ⚠️  LEGAL NOTICE — TESTING

All tests described in this directory **require explicit written authorisation**
from the owner of every network, host, and system under test.

## Mandatory Prerequisites

Before executing **any** test from this suite:

1. **Written Authorisation** — Obtain a signed Rules of Engagement (RoE) document
   or equivalent written permission from the asset owner.
2. **Isolated Environment** — Conduct all tests in an isolated lab network unless
   the RoE explicitly covers a production environment.
3. **Logging & Audit Trail** — Ensure all test activity is logged for accountability.
4. **Data Protection** — Do not capture, store, or transmit real personally identifiable
   information (PII) without lawful basis (GDPR Art. 6, CCPA, etc.).
5. **Incident Response Plan** — Have an IRP in place before testing systems that,
   if inadvertently disrupted, could cause harm.

## Applicability

This notice applies to all tests including, but not limited to:

- Layer 2 / Layer 3 flood and reconnaissance tests (`01_`, `02_`)
- Web Application Firewall exploitation tests (`03_`)
- C2 / Malware / DNS / Data Exfiltration simulations (`04_`, `05_`)
- IPS, Zero Trust, and Threat Intelligence validation (`06_`)
- SIEM evasion and performance tests (`07_`)

## No Warranty

Test procedures are provided for **defensive validation only**. The authors accept
no liability for misuse, damage, or legal consequences arising from use of these
test scripts outside of an authorised, controlled environment.

## Contact

If you are unsure whether your planned use is authorised, stop and seek legal advice
before proceeding.
