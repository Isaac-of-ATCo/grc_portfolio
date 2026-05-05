# Episource LLC Ransomware Attack (2025)

**Type:** GRC Case Study  
**Date:** June 2025  
**Analyst:** Isaac Kahiri — Healthcare GRC Analyst | Logotherapist | CC | CompTIA Security+  
**Frameworks:** NIST CSF 2.0 | HIPAA (45 CFR §164.400–414) | MITRE ATT&CK | HICP 2023

---

## Overview

Episource LLC — a medical coding, risk adjustment, and healthcare analytics company owned by UnitedHealth Group's Optum subsidiary — suffered a ransomware attack in January 2025 that exposed the protected health information of **5,418,866 individuals**. The breach is the second-largest healthcare data incident in the United States in 2025.

This case study applies NIST CSF 2.0, HIPAA regulatory requirements, MITRE ATT&CK, and HICP baseline practices to analyze the incident across governance, technical, regulatory, and vendor risk dimensions.

---

## Key Findings

- **Notification deadline missed.** HIPAA requires affected individuals to be notified within 60 days of breach discovery. Discovery was February 6, 2025; the deadline was April 7. Notification began April 23 — 16 or more days late on a rolling basis, with California's AG not notified until June 6 (120 days post-discovery).

- **Ten-day detection gap.** Attackers operated in Episource's AWS environment from January 27 to February 6 before detection — consistent with the absence of behavioral anomaly detection and cloud-native threat monitoring.

- **Repeat environment breach.** Episource's AWS environment was also breached in February 2023. Remediation was conducted and validated. The 2025 breach occurred in the same environment 22 months later — indicating that validated remediation was either insufficient or not sustained.

- **Vendor risk failure.** Sharp HealthCare was not notified until April 24, 2025 — 77 days after Episource detected the breach. Sharp's own EHR systems were never compromised; its patients' data was taken from a vendor system Sharp had no visibility into and may have had no contractual right to audit.

- **UHG acquisition pattern.** Change Healthcare (acquired 2022) was breached February 2024 with no MFA on a Citrix portal. Episource (acquired 2023) was breached January 2025. The Senate HELP Committee identified this as a pattern of post-acquisition cybersecurity governance failure and demanded answers from UHG's CEO.

- **Governance failure is the root cause.** The central finding is not technical. UHG has not demonstrated a systematic approach to assessing or enforcing minimum cybersecurity standards in newly acquired subsidiaries. The board, not the CISO, is the appropriate locus of accountability.

---

## Files

| File | Description |
|---|---|
| [episource-grc-analysis.md](episource-grc-analysis.md) | Full case study — ~3,500 words |
| [references.md](references.md) | All sources cited, with URLs |

---

## Framework Coverage

| NIST CSF 2.0 Function | Finding |
|---|---|
| Govern | No evidence of enterprise post-acquisition security standard (UHG pattern) |
| Identify | No data flow visibility — Sharp did not know what PHI lived in Episource's AWS environment |
| Protect | AWS environment breached twice despite 2023 validated remediation |
| Detect | 10-day dwell time — no behavioral anomaly detection |
| Respond | HIPAA notification deadline missed; covered entity notified 77 days after detection |
| Recover | Post-incident communications offered no specific commitments, milestones, or validation plan |
