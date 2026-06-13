# APT29 — Adversary Profile & TTP Analysis

**Author:** Edna Katerne Ruiz Gutierrez
**Date:** June 2026  
**Framework:** MITRE ATT&CK Enterprise v15  
**Sources:** MITRE ATT&CK, CISA Advisory AA21-116A, Mandiant APT29 report

---

## Overview

APT29 (also known as Cozy Bear, Midnight Blizzard, or The Dukes) is a Russian
state-sponsored threat actor attributed to the Foreign Intelligence Service (SVR).
Active since at least 2008, APT29 is known for highly sophisticated, stealthy
operations targeting governments, think tanks, healthcare, and critical infrastructure
across Western nations — including Australia.

**Motivation:** Espionage — collection of political and strategic intelligence  
**Origin:** Russia (SVR)  
**Active since:** 2008  
**Notable campaigns:** SolarWinds (2020), Microsoft (2024), COVID-19 vaccine research

---

## ATT&CK Tactic Coverage

| Tactic | # Techniques used |
|--------|------------------|
| Initial Access | 3 |
| Execution | 4 |
| Persistence | 5 |
| Privilege Escalation | 3 |
| Defense Evasion | 8 |
| Credential Access | 4 |
| Discovery | 5 |
| Lateral Movement | 3 |
| Collection | 4 |
| Command & Control | 6 |
| Exfiltration | 2 |

---

## Key Techniques — Deep Dive

### Initial Access

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1566.001 | Spearphishing Attachment | Highly targeted emails with malicious attachments sent to specific individuals |
| T1566.002 | Spearphishing Link | Links to credential harvesting pages mimicking legitimate services |
| T1195.002 | Supply Chain Compromise | SolarWinds Orion platform compromise to reach downstream victims |

**Detection opportunity:** Monitor for Office processes spawning unusual child processes
(Word/Excel launching PowerShell, cmd). Log source: Sysmon Event ID 1.

---

### Execution

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1059.001 | PowerShell | Heavily obfuscated PowerShell for initial staging and persistence |
| T1059.003 | Windows Command Shell | cmd.exe for execution of batch scripts and living-off-the-land binaries |
| T1047 | WMI | Windows Management Instrumentation for remote execution |
| T1053.005 | Scheduled Tasks | Tasks created for persistence and delayed execution |

**Detection opportunity:** PowerShell with `-EncodedCommand`, `-NonInteractive`,
or `-WindowStyle Hidden` flags. Log source: Windows Event ID 4104 (Script Block Logging).

---

### Defense Evasion (most notable)

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1036.005 | Masquerading | Malicious binaries named to mimic legitimate Windows processes |
| T1070.001 | Clear Windows Event Logs | Wiping logs to remove evidence of activity |
| T1027 | Obfuscated Files | Heavy use of obfuscation in PowerShell and scripts |
| T1140 | Deobfuscate/Decode Files | Runtime decoding of payloads to evade static analysis |
| T1562.001 | Disable Security Tools | Disabling AV and EDR solutions before proceeding |

**Detection opportunity:** Event log clearing generates Windows Event ID 1102 (audit log cleared)
and 104 (system log cleared). These should always trigger high-priority alerts.

---

### Credential Access

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1003.001 | LSASS Memory | Dumping credentials from LSASS using tools like Mimikatz |
| T1110.003 | Password Spraying | Low-volume password attempts across many accounts to avoid lockout |
| T1606.002 | SAML Token Forgery | Golden SAML attack — forging authentication tokens for cloud access |

**Detection opportunity:** Sysmon Event ID 10 (process access) targeting lsass.exe.
SAML forgery requires monitoring of Azure AD/Entra ID sign-in logs for anomalous tokens.

---

## ATT&CK Navigator Layer

Coverage heatmap available in: `../04-navigator-layers/APT29-coverage.json`

High coverage tactics: Defense Evasion, Command & Control  
Low coverage tactics (gaps): Initial Access detection, SAML token abuse

---

## Detection Gaps Identified

| Gap | Risk | Recommended action |
|-----|------|--------------------|
| SAML token forgery (T1606.002) | Critical | Enable Azure AD sign-in anomaly alerts |
| Supply chain monitoring (T1195.002) | High | Implement software bill of materials (SBOM) review process |
| PowerShell obfuscation detection | Medium | Enable Script Block Logging (Event ID 4104) if not active |

---

## References

- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [CISA Advisory AA21-116A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a)
- [Microsoft Threat Intelligence — Midnight Blizzard](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance/)
