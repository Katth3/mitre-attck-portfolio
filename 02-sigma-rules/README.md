# Detection Rules

Sigma rules mapped to MITRE ATT&CK techniques.
Each rule includes: technique ID, log source, detection logic, and test notes.

## Rule index

| File | Technique | Tactic | Log source |
|------|-----------|--------|------------|
| T1059.001-powershell-encoded.yml | T1059.001 | Execution | Windows — Sysmon |
| T1059.001-powershell-suspicious-flags.yml | T1059.001 | Execution | Windows — Sysmon |
| T1053.005-scheduled-task-created.yml | T1053.005 | Persistence | Windows Security |
| T1547.001-registry-run-key.yml | T1547.001 | Persistence | Windows — Sysmon |
| T1070.001-event-log-cleared.yml | T1070.001 | Defense Evasion | Windows Security |
| T1003.001-lsass-access.yml | T1003.001 | Credential Access | Windows — Sysmon |

## How to convert to Splunk SPL 

```bash
sigma convert -t splunk -p sysmon rule.yml
```

## Coverage

ATT&CK Navigator layer: `../04-navigator-layers/detection-rules-coverage.json`
