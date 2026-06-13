# Lab Report — Sysmon + Splunk Detection Lab Setup

**Author:** Edna Katerine Ruiz Gutierrez
**Date:** June 2026  
**Objective:** Configure a Windows endpoint detection lab with Sysmon and
Splunk to support MITRE ATT&CK detection engineering exercises.

---

## Environment

| Component | Details |
|-----------|---------|
| Host OS | Windows 10 / 11 |
| Virtualisation | VirtualBox 7.x |
| Victim VM | Windows 10 Enterprise Evaluation |
| SIEM | Splunk Enterprise 9.x (developer license) |
| Endpoint telemetry | Sysmon v15 + SwiftOnSecurity config |

---

## Step 1 — Install Sysmon

Download Sysmon from Microsoft Sysinternals and the SwiftOnSecurity
configuration file:

- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Config: https://github.com/SwiftOnSecurity/sysmon-config

Install via PowerShell (run as Administrator):

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Verify Sysmon is running:

```powershell
Get-Service Sysmon64
```

Expected output:
```
Status   Name               DisplayName
------   ----               -----------
Running  Sysmon64           Sysmon64
```

---

## Step 2 — Verify Sysmon events in Event Viewer

Open Event Viewer → Applications and Services Logs →
Microsoft → Windows → Sysmon → Operational.

Key Event IDs to confirm are populating:

| Event ID | Description |
|----------|-------------|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image loaded (DLL) |
| 10 | Process access |
| 11 | File created |
| 13 | Registry value set |

---

## Step 3 — Install Splunk Enterprise

Download from splunk.com (developer license — free, 500MB/day).

Run the installer and set:
- Admin username: `admin`
- Password: strong password, save it
- Default port: `8000`

Access Splunk at: `http://localhost:8000`

---

## Step 4 — Connect Sysmon logs to Splunk

In Splunk: **Settings** → **Add Data** → **Monitor** → **Local Event Log Collections**.

Add these log sources:

```
Microsoft-Windows-Sysmon/Operational
Security
System
Application
```

Verify data is flowing — open Search and run:

```splunk
index=main | stats count by sourcetype
```

Expected output includes:
```
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
WinEventLog:Security
WinEventLog:System
```

---

## Step 5 — Validate with a test query

Run this SPL to confirm Sysmon process creation events are visible:

```splunk
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1
| table _time, ComputerName, Image, CommandLine, ParentImage
| head 20
```

If results appear — lab is fully operational.

---

## Observations

- Sysmon with SwiftOnSecurity config generates approximately 200–400 MB
  of log data per day on a lightly used Windows VM — within the 500MB
  Splunk developer license limit.
- Without Sysmon, Windows Security logs alone are insufficient to detect
  the majority of ATT&CK techniques in the Execution and Defense Evasion
  tactics.
- Splunk search performance on a single VM is acceptable for lab purposes
  with a 7-day retention window.

---

## Conclusion

Lab environment is operational and ready for ATT&CK detection engineering
exercises. Sysmon telemetry confirmed across all critical Event IDs.
Splunk ingestion verified across 4 log sources.

**Next exercise:** Atomic Red Team T1059.001 — PowerShell execution validation.
