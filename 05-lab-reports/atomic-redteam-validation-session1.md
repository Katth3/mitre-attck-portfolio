# Lab Report — Atomic Red Team Validation Session 1

**Author:** Edna Katerine Ruiz Gutierrez
**Date:** June 2026  
**Objective:** Execute multiple MITRE ATT&CK techniques using Atomic Red Team
and validate detection coverage in Splunk across Execution, Defense Evasion,
Credential Access, Persistence, and Discovery tactics.

---

## Environment

| Component | Details |
|-----------|---------|
| Victim VM | Windows 11 Enterprise Evaluation |
| Endpoint telemetry | Sysmon v15 + SwiftOnSecurity config (modified) |
| SIEM | Splunk Enterprise 9.x |
| Emulation framework | Atomic Red Team (Invoke-AtomicRedTeam) |
| Ingestion method | Scheduled task CSV export (60s interval) |

---

## Pre-execution setup

Windows Defender Real-Time Protection and Tamper Protection were disabled
for this lab session to allow atomic tests to execute without interference.
This is standard practice for isolated, host-only adversary emulation labs
and would not be done on production systems.

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```

---

## Test Results

### Test 1 — T1059.001 PowerShell Encoded Command
**Tactic:** Execution  
**Command:** `Invoke-AtomicTest T1059.001 -TestNumbers 1`  
**Sysmon EventID generated:** 1 (Process Create)  
**Splunk query:** `index=main sourcetype="csv" Message="*EncodedCommand*"`  
**Result:** ✅ Detected

---

### Test 2 — T1070.004 File Deletion
**Tactic:** Defense Evasion  
**Command:** `Invoke-AtomicTest T1070.004 -TestNumbers 1`  
**Sysmon EventID generated:** 1 (Process Create), 22 (DNS Query)  
**Result:** ✅ Detected — additional DNS telemetry observed alongside
file deletion activity, providing extra investigative context.

---

### Test 3 — T1003.001 LSASS Memory Dump via comsvcs.dll
**Tactic:** Credential Access  
**Command:** `Invoke-AtomicTest T1003.001 -TestNumbers 2`

**Initial result:** ❌ Blocked — Windows Defender Tamper Protection
prevented execution ("Access Denied"). This is a preventive control
working as intended.

**After disabling Tamper Protection:** Technique executed successfully.
Sysmon EventID 1 captured `rundll32.exe` + `comsvcs.dll` execution, but
**EventID 10 (Process Access) was not generated** — critical gap identified.

**Root cause:** SwiftOnSecurity Sysmon config ships with `ProcessAccess`
set to `onmatch="include"` with no rules — by design, to avoid noise.
This means EventID 10 is globally disabled by default.

**Remediation applied:**
```xml
<ProcessAccess onmatch="include">
    <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
```

**Re-test result:** ✅ Detected — EventID 10 generated successfully,
capturing SourceProcessId, TargetImage=lsass.exe, and GrantedAccess.

**Full cycle demonstrated:** identify → analyze → remediate → verify.

---

### Test 4 — T1547.001 Registry Run Key Persistence
**Tactic:** Persistence  
**Command:** `Invoke-AtomicTest T1547.001 -TestNumbers 1`  
**Sysmon EventID generated:** 1 (Process Create), 13 (Registry value set)  
**Splunk query:** `index=main sourcetype="csv" Message="*CurrentVersion\\Run*"`  
**Result:** ✅ Detected

**Notable finding:** The Sysmon event was tagged with `RuleName: T1060,RunKey`
— the SwiftOnSecurity configuration includes legacy ATT&CK technique IDs
(T1060 was the pre-2020 ID for what is now T1547.001) directly in rule
names, demonstrating ATT&CK-aware detection engineering at the
configuration level.

---

### Test 5 — T1082 System Information Discovery
**Tactic:** Discovery  
**Command:** `Invoke-AtomicTest T1082 -TestNumbers 1`  
**Sysmon EventID generated:** 1 (Process Create), 13 (Registry value set)  
**Result:** ✅ Detected — `systeminfo.exe` execution captured along with
registry queries for OS inventory information (product name, build number).

---

## Summary

| # | Technique | Tactic | Detected | Notes |
|---|-----------|--------|----------|-------|
| 1 | T1059.001 | Execution | ✅ | Clean detection |
| 2 | T1070.004 | Defense Evasion | ✅ | Bonus DNS telemetry |
| 3 | T1003.001 | Credential Access | ✅ | Gap found + remediated live |
| 4 | T1547.001 | Persistence | ✅ | ATT&CK-tagged Sysmon rule |
| 5 | T1082 | Discovery | ✅ | Registry-based recon visible |

**Overall detection rate: 5/5 (100%) — including one technique that
required live remediation to achieve detection.**

---

## Key Takeaways

1. **Preventive and detective controls operate independently.** Tamper
   Protection blocked T1003.001 on the first attempt — a successful
   preventive control. Detective controls must be validated separately,
   as this exercise demonstrated.

2. **Default Sysmon configurations make tradeoffs.** SwiftOnSecurity
   disables EventID 10 by design to reduce noise. Detection engineers
   must understand these tradeoffs and tune configurations based on
   their organisation's risk profile — full EID 10 logging may be
   appropriate for high-value targets (domain controllers, jump hosts)
   even if too noisy for general endpoints.

3. **Registry telemetry (EID 13) provides discovery context.** Both
   persistence (T1547.001) and discovery (T1082) techniques generated
   registry events, showing that EID 13 has value beyond persistence
   detection alone.

4. **ATT&CK-aware tooling exists at the configuration level.** Finding
   `RuleName: T1060,RunKey` in Sysmon output shows that mapping to ATT&CK
   isn't just a documentation exercise — it's embedded in detection
   configurations used industry-wide.

---

## References

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK](https://attack.mitre.org)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
