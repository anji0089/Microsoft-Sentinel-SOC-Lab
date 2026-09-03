# Detection 04 — Suspicious Certutil Activity

**Event:** 4688  
**MITRE:** T1027 — Obfuscated/Compressed Files and Information

## KQL

```kql
SecurityEvent
| where EventID == 4688
| where tostring(NewProcessName) endswith @"\certutil.exe"
| where tostring(CommandLine) matches regex @"(?i)(-urlcache|-decode|-decodehex|-encode|-verifyctl|-split)"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

## Controlled validation

A test file was encoded with `certutil.exe -encode` from PowerShell.

## Investigation result

The test produced the expected process-creation telemetry and matched the detection. A separate Acer service invocation of certutil was identified as likely legitimate software activity and was not treated as malicious.

**Important:** never publish screenshots containing passwords or other secrets from real command lines.
