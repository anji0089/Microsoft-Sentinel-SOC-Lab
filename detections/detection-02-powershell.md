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
