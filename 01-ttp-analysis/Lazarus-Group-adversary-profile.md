# Lazarus Group — Adversary Profile & TTP Analysis

**Author:** Edna Katerine Ruiz Gutierrez 
**Date:** June 2026  
**Framework:** MITRE ATT&CK Enterprise v15  
**Sources:** MITRE ATT&CK, CISA Advisory AA22-108A, US-CERT Alert TA18-149A

---

## Overview

Lazarus Group is a North Korean state-sponsored threat actor attributed to the
Reconnaissance General Bureau (RGB). One of the most prolific and financially
motivated APT groups globally, Lazarus combines espionage operations with
large-scale financial theft — making it unique among nation-state actors.

**Motivation:** Financial gain + espionage  
**Origin:** North Korea (RGB)  
**Active since:** 2009  
**Notable campaigns:** Sony Pictures (2014), Bangladesh Bank heist ($81M, 2016),
WannaCry ransomware (2017), Ronin Network crypto theft ($625M, 2022),
ongoing targeting of cryptocurrency exchanges and DeFi platforms

---

## Why Lazarus matters for Australian organisations

Australia's financial sector, cryptocurrency industry, and defence contractors
are consistent targets of Lazarus Group operations. ACSC has issued multiple
advisories on Lazarus activity targeting Australian entities.

---

## ATT&CK Tactic Coverage

| Tactic | # Techniques used |
|--------|------------------|
| Initial Access | 4 |
| Execution | 5 |
| Persistence | 6 |
| Privilege Escalation | 4 |
| Defense Evasion | 9 |
| Credential Access | 5 |
| Discovery | 6 |
| Lateral Movement | 4 |
| Collection | 5 |
| Command & Control | 7 |
| Exfiltration | 3 |
| Impact | 4 |

---

## Key Techniques — Deep Dive

### Initial Access

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1566.001 | Spearphishing Attachment | Malicious Word/Excel documents with macros, often job offer lures |
| T1566.002 | Spearphishing Link | Links to fake cryptocurrency platforms or job portals |
| T1195.001 | Compromise Software Dependencies | Trojanized open-source packages targeting developers |
| T1189 | Drive-by Compromise | Watering hole attacks on financial and crypto industry sites |

**Detection opportunity:** Office child process execution — Word or Excel spawning
PowerShell, cmd, or wscript. Sysmon Event ID 1 with parent image filtering.

---

### Execution & Persistence

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1059.001 | PowerShell | Custom PowerShell backdoors and downloaders |
| T1059.005 | Visual Basic | VBA macros in Office documents for initial execution |
| T1547.001 | Registry Run Keys | Persistence via HKCU/HKLM Run keys |
| T1543.003 | Windows Service | Malicious services installed for persistent access |
| T1053.005 | Scheduled Tasks | Tasks disguised as legitimate Windows maintenance jobs |

**Detection opportunity:** New services created outside of patch/update windows.
Windows Event ID 7045 (new service installed) combined with non-standard
binary paths or names mimicking system services.

---

### Defense Evasion (most notable)

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1036.005 | Masquerading | Malware named svchost.exe, lsm.exe, or other system process names |
| T1055.001 | DLL Injection | Injecting malicious DLLs into legitimate processes |
| T1070.004 | File Deletion | Cleaning up tools and artifacts after exfiltration |
| T1027.002 | Software Packing | Custom packers to evade AV static signatures |
| T1562.004 | Disable Firewall | Modifying firewall rules to enable C2 communications |

**Detection opportunity:** Processes running from unusual paths (AppData, Temp).
Sysmon Event ID 7 (image loaded) for DLL monitoring in sensitive processes.

---

### Financial Operations (unique to Lazarus)

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1657 | Financial Theft | Direct theft from financial systems and crypto wallets |
| T1486 | Data Encrypted for Impact | Ransomware deployment (WannaCry, HolyGhost) as secondary operation |
| T1496 | Resource Hijacking | Cryptomining on compromised infrastructure |

**Detection opportunity:** Unusual outbound connections to cryptocurrency-related
domains or Tor exit nodes. Monitor for large data staging before exfiltration.

---

### Command & Control

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1071.001 | Web Protocols | HTTP/HTTPS C2 traffic blending with legitimate web traffic |
| T1090.003 | Multi-hop Proxy | Chained proxies and VPNs to obscure C2 infrastructure |
| T1102 | Web Service | Using legitimate services (GitHub, Twitter, Dropbox) as C2 channels |
| T1573.001 | Symmetric Cryptography | Encrypted C2 communications to evade inspection |

**Detection opportunity:** Beaconing patterns — regular outbound connections at
consistent intervals. Network detection requires DNS query analysis and
JA3 TLS fingerprinting alongside Splunk.

---

## Comparison with APT29

| Attribute | APT29 | Lazarus Group |
|-----------|-------|---------------|
| Motivation | Espionage | Financial + Espionage |
| Stealth level | Extremely high | High |
| Persistence | Long-term (months/years) | Medium-term |
| Primary target | Government, think tanks | Finance, crypto, defence |
| Australia relevance | Medium | High |
| Most dangerous technique | SAML token forgery | Financial system access |

---

## Detection Gaps Identified

| Gap | Risk | Recommended action |
|-----|------|--------------------|
| Crypto wallet monitoring | Critical | Alert on processes accessing wallet.dat or keystore files |
| Beaconing detection | High | Implement JA3 fingerprinting + connection frequency analysis |
| Trojanized packages (T1195.001) | High | Software composition analysis (SCA) in CI/CD pipeline |
| Living-off-the-land binaries | Medium | Baseline legitimate LOLBin usage, alert on deviations |

---

## References

- [MITRE ATT&CK — Lazarus Group](https://attack.mitre.org/groups/G0032/)
- [CISA Advisory AA22-108A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a)
- [US-CERT Alert TA18-149A](https://www.cisa.gov/news-events/alerts/2018/05/29/hidden-cobra-lazarus-group-and-bluenoroff)
- [ACSC — North Korean Cyber Activity](https://www.cyber.gov.au/)
