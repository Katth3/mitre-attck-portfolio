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
| Victim VM | Windows 11 Enterprise Evaluation |
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
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
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

Key Event IDs confirmed populating:

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
- Password: strong password
- Default port: `8000`

Access Splunk at: `http://localhost:8000`

---

## Step 4 — Connect Sysmon logs to Splunk

Due to Windows 11 permission restrictions on the Sysmon event channel,
a scheduled task was configured to export Sysmon events to CSV every minute,
which Splunk monitors as a file input.

Create export folder:

```powershell
New-Item -ItemType Directory -Path C:\SysmonLogs -Force
```

Create scheduled task:

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument '-Command "Get-WinEvent -LogName \"Microsoft-Windows-Sysmon/Operational\" -MaxEvents 200 | Select-Object TimeCreated, Id, Message | Export-Csv C:\SysmonLogs\sysmon.csv -Append -NoTypeInformation"'

$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 1) -Once -At (Get-Date)

Register-ScheduledTask -TaskName "SysmonExport" -Action $action -Trigger $trigger -RunLevel Highest -Force

Start-ScheduledTask -TaskName "SysmonExport"
```

In Splunk: **Settings → Add Data → Monitor → Files & Directories**
- Path: `C:\SysmonLogs\sysmon.csv`
- Sourcetype: `csv`
- Index: `main`

---

## Step 5 — Verify data flow

Run in Splunk Search:

```splunk
index=main sourcetype="csv" | head 20
```

Confirmed events visible including EventID 1 (Process Create)
and EventID 13 (Registry value set).

---

## Observations

- Sysmon with SwiftOnSecurity config generates rich telemetry across
  all critical event types.
- Windows 11 restricts direct event log access for Splunk services —
  workaround via scheduled CSV export resolved the issue.
- Splunk search confirmed events arriving within 60 seconds of activity.
- EventID 13 (Registry) captured automatically alongside process events,
  providing additional detection context beyond what was expected.

---

## Conclusion

Lab environment is fully operational. Sysmon telemetry confirmed across
EventID 1, 11, and 13. Splunk ingestion verified via CSV file monitor.
Detection queries validated against real attacker techniques.

**Next exercise:** Atomic Red Team T1059.001 — automated PowerShell
execution validation.

---

## Validation Results — Live Detection Evidence

The following ATT&CK techniques were executed manually in the lab
and confirmed detected in Splunk within 60 seconds of execution.

| Technique | ID | Command used | Detected | Sysmon EventID |
|-----------|-----|-------------|----------|----------------|
| PowerShell suspicious flags | T1059.001 | `powershell.exe -NonInteractive -WindowStyle Hidden -Command "whoami"` | ✅ Yes | 1 |
| Event log clearing | T1070.001 | `wevtutil cl System` | ✅ Yes | 1 |
| Process discovery | T1057 | `tasklist.exe /fo csv > C:\Windows\Temp\proclist.txt` | ✅ Yes | 1 + 13 |

**Detection rate: 3/3 (100%)**

### Splunk queries used for validation

```splunk
index=main sourcetype="csv" Message="*NonInteractive*"
index=main sourcetype="csv" Message="*wevtutil*"
index=main sourcetype="csv" Message="*tasklist*"
```

### Key finding

EventID 13 (Registry value set) was captured alongside the tasklist.exe
execution, demonstrating that Sysmon telemetry provides broader context
than process creation alone — registry activity associated with process
execution is visible without additional configuration.
