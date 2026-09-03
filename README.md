# Microsoft Sentinel SOC Lab

A hands-on SOC L1 detection and investigation lab built with Microsoft Sentinel, Azure Log Analytics, and Windows SecurityEvent telemetry.

## Objective

Build and validate practical SOC detections, investigate the resulting telemetry, map activity to MITRE ATT&CK, and document analyst decisions.

## Lab Architecture

```text
Windows 11 Pro (ACER)
        |
        | Azure Connected Machine Agent / Azure Arc
        v
Azure Monitor / Log Analytics Workspace
        |
        v
Microsoft Sentinel
        |
        +--> Analytics Rules
        +--> Security Alerts
        +--> Investigations
```

## Telemetry

Primary data source: Windows `SecurityEvent` table.

Key Event IDs used:

- 4625 — Failed logon
- 4688 — Process creation
- 4720 — User account created
- 4732 — Member added to local security-enabled group

## Detections

| # | Detection | Event | MITRE |
|---|---|---:|---|
| 1 | Multiple Failed Windows Logons | 4625 | Credential Access |
| 2 | Suspicious PowerShell Command Execution | 4688 | T1059.001 |
| 3 | Suspicious Office Child Process Creation | 4688 | T1059 / T1059.003 |
| 4 | Suspicious Certutil Activity | 4688 | T1027 |
| 5 | Local Administrator Group Modification | 4732 | T1098 |
| 6 | New Windows User Account Created | 4720 | T1136 |
| 7 | Suspicious PowerShell Download Activity | 4688 | T1105 |

## Investigations

- Investigation 001 — Excel → CMD
- Investigation 002 — Certutil
- Investigation 003 — PowerShell
- Investigation 004 — Multiple Failed Logons

## Analyst Approach

Each alert is treated as a starting point, not proof of compromise. The investigation checks process context, account, source, parent process, command line, timing, and whether the activity was an authorized lab test.

## Current Result

All four documented investigations were assessed as benign/authorized or system-generated activity. The lab demonstrates both detection validation and false-positive analysis.

> Note: screenshots containing subscription IDs, tenant identifiers, resource IDs, credentials, or other sensitive values should be redacted before publishing.
