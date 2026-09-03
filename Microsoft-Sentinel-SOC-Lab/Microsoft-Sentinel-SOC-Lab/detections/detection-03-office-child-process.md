# Detection 03 — Suspicious Office Child Process Creation

**Event:** 4688  
**MITRE:** T1059 / T1059.003

## KQL

```kql
SecurityEvent
| where EventID == 4688
| where tostring(NewProcessName) matches regex @"(?i)\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)\.exe$"
| where tostring(ParentProcessName) matches regex @"(?i)\\(winword|excel|outlook|acrord32|mshta|wscript|cscript)\.exe$"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

## Controlled validation

Excel VBA launched `cmd.exe /c echo Sentinel Detection Test`.

## Investigation result

Process chain: `explorer.exe → EXCEL.EXE → cmd.exe → echo Sentinel Detection Test`.

The command was an authorized lab test, so no remediation was required.
