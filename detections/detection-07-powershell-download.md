# Detection 07 — Suspicious PowerShell Download Activity

**Event:** 4688  
**MITRE:** T1105 — Ingress Tool Transfer

## KQL

    SecurityEvent
    | where EventID == 4688
    | where tostring(NewProcessName) endswith @"\powershell.exe"
        or tostring(NewProcessName) endswith @"\pwsh.exe"
    | where tostring(CommandLine) matches regex @"(?i)(Invoke-WebRequest|Invoke-RestMethod|WebClient|DownloadString|DownloadFile|Start-BitsTransfer)"
    | project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
    | order by TimeGenerated desc

## Validation

A new Windows PowerShell process was launched with:

`Invoke-WebRequest https://example.com -UseBasicParsing | Out-Null`

The process-creation event was observed in Sentinel and matched the rule.

## Analyst Lesson

The detection must evaluate the actual process command line. A command containing a suspicious word as plain text is not necessarily execution of that command.

Controlled testing also demonstrated the importance of reviewing the account, parent process, and command-line context before determining whether PowerShell activity is suspicious.

## Verdict

**Benign authorized lab test. No remediation was required.**
