# 4.5 Standards & Literature References

Rudras relies heavily on established consensus protocols, NIST cryptographic standards, and peer-reviewed computer science literature. The following is a consolidated list of references utilized throughout the architecture.

## 1. Federal and Cryptographic Standards

- **[NIST SP 800-207]** Zero Trust Architecture. Fundamentals of beyond-perimeter identity and continuous verification.
- **[NIST SP 800-162]** Guide to Attribute Based Access Control (ABAC). Enforced via the `Identity Policy Module` JWT claims logic.
- **[NIST SP 800-161r1]** Cybersecurity Supply Chain Risk Management Practices. Implemented via the `Supply Chain Verifier Module` runtime taint analysis.
- **[NIST SP 800-53r5]** Security and Privacy Controls for Information Systems. Automatic mapping generated via the `Compliance Engine Module`.
- **[FIPS 203, 204, & 205 (Drafts)]** Post-Quantum Cryptography Standardization. Rudras enables Kyber key-encapsulation (`Advanced Security Module`) ahead of the timeline deprecating classical ECC/RSA standards.
- **[RFC 8446]** The Transport Layer Security (TLS) Protocol Version 1.3. Enforced natively via `Secure Channel Module`.
- **[RFC 9000]** QUIC: A UDP-Based Multiplexed and Secure Transport. The basis for `Quic Inspector Module`.
- **[TCG TPM 2.0]** Trusted Platform Module Library. Used for device integrity seals in `Tpm Attestation Module`.

## 2. Peer-Reviewed Academic Literature

1. **Forrest, S., Perelson, A. S., Allen, L., & Cherukuri, R. (1994).** *Self-nonself discrimination in a computer.* IEEE Symposium on Research in Security and Privacy.
   - Basis for `Cyber Immune Module` and the Artificial Immune System theory.
2. **McMahan, B., Moore, E., Ramage, D., Hampson, S., & y Arcas, B. A. (2017).** *Communication-Efficient Learning of Deep Networks from Decentralized Data.* Artificial Intelligence and Statistics.
   - Foundation for the federated baseline crunching modeled inside `Advanced Ml Module`.
3. **Mnih, V., Kavukcuoglu, K., Silver, D., et al. (2013).** *Playing Atari with Deep Reinforcement Learning.* NIPS Deep Learning Workshop.
   - The DQN underpinning the Q-learning active response logic found in `Rl Policy Module`.
4. **AlEroud, A., & Karabatis, G. (2012).** *Bypassing intrusion detection systems using contextual anomaly detection.*
   - Context-aware threat hunting parameters seen in `Threat Hunt Module`.
5. **Yuan, L., Mai, J., Su, Z., Chen, H., Chuah, C. N., & Mohapatra, P. (2006).** *FIREMAN: A Toolkit for FIREwall Modeling and ANalysis.* IEEE Symposium on Security and Privacy.
   - Direct inspiration for the `Formal Verification Module` module checking ruleset consistency and shadows via Boolean SAT logic.

## 3. Threat Frameworks & Ontologies

- **[MITRE ATT&CK]** Adversarial Tactics, Techniques, and Common Knowledge. All alerts within `Ids Engine Module` attach TTK tags for SIEM dashboard mapping.
- **[MITRE ENGAGE]** Framework for adversary engagement, deception, and denial. Powers the persona dynamics of `Adaptive Honeypot Module`.
- **[OWASP Core Rule Set (CRS) v4]** Applied universally to `Gateway Mode Module` (L7 WAF) protecting internal web servers against SQLi, XSS, and broken access controls.
- **[SLSA Framework]** Supply-chain Levels for Software Artifacts. Implemented within `Supply Chain Verifier Module` to audit dependencies.

---

> _This reference list represents the theoretical and legal underpinning of Rudras v4.0.0. Internal partners auditing the platform should consult these references to validate specific cryptographic or detection heuristics._
