# Detection Queries — Splunk SPL

Splunk SPL queries for threat hunting and detection, mapped to MITRE ATT&CK.
Each query includes: technique ID, data sources required, logic explanation,
and tuning notes.

## Requirements

- Splunk Enterprise (free developer license — 500MB/day)
- Sysmon installed with SwiftOnSecurity config
- Windows Event Logs: Security, System, Sysmon/Operational

## Query index

| File | Technique | Tactic | Data source |
|------|-----------|--------|-------------|
| T1059.001-powershell-hunting.md | T1059.001 | Execution | Sysmon EID 1 |
| T1070.001-eventlog-cleared.md | T1070.001 | Defense Evasion | Windows Security |
| T1003.001-lsass-access.md | T1003.001 | Credential Access | Sysmon EID 10 |
| T1053.005-scheduled-tasks.md | T1053.005 | Persistence | Windows Security |
| T1547.001-registry-run-keys.md | T1547.001 | Persistence | Sysmon EID 13 |

## How to use

1. Copy the SPL query into Splunk Search bar
2. Adjust `index=` and `sourcetype=` to match your environment
3. Set time range to last 24h for initial testing
4. Review false positives section before deploying as alert
