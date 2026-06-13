# Purple Team Exercises

Structured purple team exercise reports documenting adversary emulation,
detection validation, and security gap analysis.

Each exercise follows this methodology:
1. Select threat actor based on industry relevance
2. Map TTPs to ATT&CK
3. Emulate techniques in controlled lab environment
4. Validate detections in Splunk
5. Document gaps and recommendations

## Exercise index

| File | Adversary | Scope | Status |
|------|-----------|-------|--------|
| APT29-purple-team-report.md | APT29 / Cozy Bear | 15 techniques, 4 tactics | Complete |

## Lab environment

- **Victim VM:** Windows 10 Enterprise + Sysmon (SwiftOnSecurity config)
- **Attacker VM:** Kali Linux + Atomic Red Team
- **SIEM:** Splunk Enterprise (developer license)
- **Emulation platform:** Atomic Red Team / CALDERA
