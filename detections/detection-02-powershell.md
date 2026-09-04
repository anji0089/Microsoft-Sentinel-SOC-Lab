# Detection 02 — Suspicious PowerShell Command Execution

**Event:** 4688  
**MITRE:** T1059.001 — PowerShell

## KQL

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where Account !endswith "$"
| where CommandLine matches regex @"(?i)(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|IEX\s*\(|Invoke-WebRequest\s+https?://|DownloadString\s*\(|FromBase64String\s*\()"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

## Validation

Controlled PowerShell process-creation tests using `IEX()` and a remote web request pattern were observed in Sentinel.

## False-positive analysis

Azure Arc and Acer software generated legitimate PowerShell activity. Testing showed why command-line context and account type matter when tuning a detection.

## Investigation Result

The detection successfully identified controlled PowerShell process-creation events generated during lab validation.

The investigation also identified legitimate PowerShell activity from Azure Arc and Acer software. These events demonstrated that PowerShell command-line context and account type are important when distinguishing suspicious execution from legitimate administrative or software activity.

The controlled PowerShell tests did not contain a malicious payload.

## Analyst Lesson

PowerShell execution alone does not establish malicious activity. An analyst should review the command line, account context, parent process, execution pattern, and surrounding events before determining whether the activity is suspicious.

In this lab, the detection worked as intended while the investigation demonstrated the importance of false-positive analysis.
