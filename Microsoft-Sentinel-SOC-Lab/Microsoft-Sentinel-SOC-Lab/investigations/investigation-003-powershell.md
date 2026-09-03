# Investigation 003 — PowerShell

## Tested behaviors

1. `Invoke-WebRequest` to `https://example.com`
2. `IEX()` with a harmless `Write-Output` command
3. A second controlled `IEX()` test

## Assessment

The events were generated intentionally to validate PowerShell detections. No malicious payload was used.

## Response

No containment required. The exercise also identified legitimate Azure Arc and Acer PowerShell activity that should not be mistaken for malicious execution.
