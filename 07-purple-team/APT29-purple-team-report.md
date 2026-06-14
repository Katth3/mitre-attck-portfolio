# Purple Team Exercise Report — APT29 (Cozy Bear)

**Author:** Edna Katerine Ruiz Gutierrez
**Date:** June 2026  
**Classification:** Portfolio — Public  
**Threat Actor:** APT29 / Cozy Bear / Midnight Blizzard  
**Framework:** MITRE ATT&CK Enterprise v15  

---

## Executive Summary

This purple team exercise emulated APT29 TTPs across 15 techniques covering
4 MITRE ATT&CK tactics: Execution, Persistence, Defense Evasion, and
Credential Access.

**Key findings:**

| Metric | Result |
|--------|--------|
| Techniques emulated | 15 |
| Detections triggered | 9 |
| Detection rate | 60% |
| Critical gaps identified | 3 |
| High gaps identified | 4 |

**Bottom line:** The lab environment detected the majority of execution and
persistence techniques but showed significant gaps in defense evasion and
cloud credential abuse (SAML token forgery). Immediate improvements recommended
in PowerShell Script Block Logging and Azure AD monitoring.

---

## Objectives

1. Validate existing Splunk detections against real APT29 TTPs
2. Identify gaps in detection coverage
3. Prioritize remediation based on risk
4. Produce actionable recommendations for security improvement

---

## Scope

**In scope:**
- Windows endpoint detection (Sysmon + Splunk)
- ATT&CK tactics: Execution, Persistence, Defense Evasion, Credential Access

**Out of scope:**
- Network-level detections
- Cloud environment (Azure AD / M365)
- Initial Access simulation

---

## Environment

| Component | Details |
|-----------|---------|
| Victim | Windows 10 Enterprise VM, Sysmon v15, SwiftOnSecurity config |
| Attacker | Kali Linux VM, Atomic Red Team v4 |
| SIEM | Splunk Enterprise 9.x, developer license |
| Network | Isolated VirtualBox host-only network |
| Duration | 4 hours active emulation |

---

## Emulation Results

### Tactic: Execution

| Technique | ID | Tool used | Detected | Alert level |
|-----------|-----|-----------|----------|-------------|
| PowerShell encoded command | T1059.001 | Atomic T1059.001-1 | ✅ Yes | Medium |
| PowerShell hidden window | T1059.001 | Atomic T1059.001-4 | ✅ Yes | Medium |
| WMI command execution | T1047 | Atomic T1047-1 | ❌ No | — |
| Scheduled task execution | T1053.005 | Atomic T1053.005-1 | ✅ Yes | High |

**Execution detection rate: 3/4 (75%)**

---

### Tactic: Persistence

| Technique | ID | Tool used | Detected | Alert level |
|-----------|-----|-----------|----------|-------------|
| Registry Run Key | T1547.001 | Atomic T1547.001-1 | ✅ Yes | Medium |
| Scheduled task creation | T1053.005 | Atomic T1053.005-4 | ✅ Yes | High |
| New local admin account | T1136.001 | Atomic T1136.001-1 | ❌ No | — |

**Persistence detection rate: 2/3 (67%)**

---

### Tactic: Defense Evasion

| Technique | ID | Tool used | Detected | Alert level |
|-----------|-----|-----------|----------|-------------|
| Event log clearing | T1070.001 | Atomic T1070.001-1 | ✅ Yes | High |
| Masquerading — rename binary | T1036.005 | Atomic T1036.005-1 | ❌ No | — |
| Timestomping | T1070.006 | Atomic T1070.006-1 | ❌ No | — |
| Disable Windows Defender | T1562.001 | Atomic T1562.001-1 | ✅ Yes | High |

**Defense Evasion detection rate: 2/4 (50%)**

---

### Tactic: Credential Access

| Technique | ID | Tool used | Detected | Alert level |
|-----------|-----|-----------|----------|-------------|
| LSASS memory access | T1003.001 | Atomic T1003.001-1 | ✅ Yes | High |
| SAM database dump | T1003.002 | Atomic T1003.002-1 | ❌ No | — |
| Password spraying | T1110.003 | Atomic T1110.003-1 | ✅ Yes | Medium |

**Credential Access detection rate: 2/3 (67%)**

---

## Gap Analysis

### Critical gaps

| Gap | Technique | Risk | Business impact |
|-----|-----------|------|-----------------|
| WMI execution not detected | T1047 | Critical | Attacker can execute code silently without triggering any alert |
| SAM database dump not detected | T1003.002 | Critical | Full local credential theft goes undetected |
| Masquerading not detected | T1036.005 | Critical | Malware running as legitimate process name evades all detections |

### High gaps

| Gap | Technique | Risk | Recommended fix |
|-----|-----------|------|-----------------|
| New local account creation | T1136.001 | High | Alert on Event ID 4720 (user account created) |
| Timestomping | T1070.006 | High | Enable Sysmon EID 2 (file creation time changed) |
| Script Block Logging disabled | T1059.001 | High | Enable via GPO: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell |
| No cloud monitoring | T1606.002 | High | Implement Azure AD sign-in anomaly detection |

---

## Recommendations

### Immediate (0–30 days)

1. **Enable PowerShell Script Block Logging** via Group Policy
   - Path: `Computer Configuration → Administrative Templates → Windows Components → PowerShell`
   - Enables Event ID 4104 — captures full PowerShell script content

2. **Add Sigma rule for WMI execution**
   - Monitor `wmiprvse.exe` spawning unusual child processes
   - Sysmon EID 1 with ParentImage filter

3. **Alert on Event ID 4720** — new local account creation
   - Zero false positives in most environments
   - Any new local account outside change window = investigate

### Short term (30–90 days)

4. **Enable Sysmon EID 2** (file creation time changed) for timestomping detection
5. **Deploy SAM dump detection** — monitor `reg.exe` accessing SAM hive
6. **Implement masquerading detection** — alert on known system binary names
   running from non-system paths

### Long term (90+ days)

7. **Extend coverage to Azure AD / Microsoft Sentinel**
   - SAML token forgery (T1606.002) requires cloud-native monitoring
   - Out of scope for this exercise but critical for full APT29 coverage

---

## Coverage Heatmap

ATT&CK Navigator layer: `../04-navigator-layers/APT29-coverage.json`

| Tactic | Techniques tested | Detected | Rate |
|--------|------------------|----------|------|
| Execution | 4 | 3 | 75% |
| Persistence | 3 | 2 | 67% |
| Defense Evasion | 4 | 2 | 50% |
| Credential Access | 3 | 2 | 67% |
| **Total** | **14** | **9** | **64%** |

---

## Additional Finding — T1003.001 LSASS Memory Access (Live Test)

**Date tested:** June 2026  
**Method:** Atomic Red Team T1003.001-2 (rundll32 + comsvcs.dll MiniDump)

### Observations

1. **Tamper Protection blocked initial execution** — Windows Defender
   Tamper Protection prevented `rundll32.exe` from accessing `lsass.exe`
   memory on first attempt ("Access Denied"). This is a working
   preventive control against T1003.001.

2. **After disabling Tamper Protection**, the technique executed
   successfully. Sysmon EventID 1 (Process Create) captured the
   `rundll32.exe comsvcs.dll` execution.

3. **Critical gap identified:** Sysmon EventID 10 (Process Access) —
   the event type specifically designed to detect LSASS memory access —
   was NOT generated. This means the current SwiftOnSecurity configuration
   does not capture process access to LSASS, leaving a detection gap
   for the most direct indicator of T1003.001.

### Risk

Without EventID 10 coverage, T1003.001 is only detectable via EventID 1
(the parent process executing comsvcs.dll) — a weaker signal that can be
evaded by using different LOLBins or direct syscalls (as in Atomic test
T1003.001-3, which uses direct system calls and API unhooking to avoid
this exact detection point).

### Recommendation

Modify Sysmon configuration to explicitly include EventID 10 for
`lsass.exe` as TargetImage:

```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
```

Re-test after configuration change to confirm EID 10 generation.

**Updated detection rate including this live test: 9/15 (60%) — gap
explicitly identified with remediation provided.**

---

## Lessons Learned

1. **Sysmon is essential** — without it, half these detections would not exist.
   Baseline Sysmon deployment should be a priority for any organisation.

2. **Defense evasion is the hardest tactic to detect** — attackers blend into
   legitimate activity. Detection requires behavioral baselines, not just signatures.

3. **Cloud is the biggest gap** — APT29's most sophisticated techniques
   (SAML forgery, Azure AD abuse) require Microsoft Sentinel or equivalent.
   Endpoint-only detection is insufficient for this threat actor.

4. **Purple teaming reveals what vulnerability scanning cannot** — a patched
   system can still be fully compromised if detections are missing.

5. **Preventive controls and detective controls must be tested separately** —
   Tamper Protection successfully blocked LSASS access on first attempt,
   demonstrating defense-in-depth. However, once a preventive control is
   bypassed or disabled, detective controls (Sysmon EID 10) must independently
   catch the activity. This exercise found a gap in that second layer —
   exactly the kind of finding purple teaming is designed to surface.

---

## References

- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [CISA AA21-116A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a)****
