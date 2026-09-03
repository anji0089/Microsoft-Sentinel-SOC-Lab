# Microsoft Sentinel SOC Lab

## Overview

This project is a hands-on Security Operations Center (SOC) laboratory built using Microsoft Sentinel, Azure Log Analytics, Azure Arc, Azure Monitor Agent, Kusto Query Language (KQL), and Windows Security Event Logs.

The lab demonstrates the complete SOC L1 workflow:

Telemetry Collection → Detection Engineering → Alert Generation → Investigation → MITRE ATT&CK Mapping → Analyst Verdict

The objective was to build realistic security detections, generate controlled test activity, investigate the resulting telemetry, identify false positives, and document the investigation process.

## Project Objectives

- Build a practical Microsoft Sentinel SOC monitoring environment.
- Collect Windows security telemetry from a Windows endpoint.
- Develop custom KQL-based analytics rules.
- Generate controlled security events for detection validation.
- Investigate alerts using raw Windows event data.
- Analyze process relationships and command-line activity.
- Identify legitimate activity and false positives.
- Map detected behaviors to MITRE ATT&CK.
- Document SOC analyst investigation decisions.

## Lab Architecture

Windows 11 Endpoint
        |
        v
Azure Arc Connected Machine Agent
        |
        v
Azure Monitor Agent (AMA)
        |
        v
Data Collection Rule (DCR)
        |
        v
Azure Log Analytics Workspace
        |
        v
Microsoft Sentinel
        |
        v
Analytics Rules
        |
        v
Security Alerts
        |
        v
SOC Investigation
        |
        v
MITRE ATT&CK Mapping
        |
        v
Analyst Verdict

## Technologies Used

| Technology | Purpose |
|---|---|
| Microsoft Sentinel | SIEM and security monitoring |
| Azure Log Analytics | Centralized log storage and querying |
| Azure Arc | Connected the Windows endpoint to Azure |
| Azure Monitor Agent (AMA) | Telemetry collection |
| Data Collection Rules (DCR) | Controlled Windows event ingestion |
| Kusto Query Language (KQL) | Detection and investigation queries |
| Windows Security Event Logs | Endpoint security telemetry |
| MITRE ATT&CK | Adversary behavior mapping |

## Detection Engineering

Seven custom Microsoft Sentinel analytics rules were created and validated using Windows security telemetry.

| # | Detection | Windows Event | MITRE ATT&CK |
|---|---|---:|---|
| 1 | Multiple Failed Windows Logons | 4625 | Credential Access |
| 2 | Suspicious PowerShell Command Execution | 4688 | T1059.001 |
| 3 | Suspicious Office Child Process Creation | 4688 | T1059 |
| 4 | Suspicious Certutil Activity | 4688 | T1027 |
| 5 | Local Administrator Group Modification | 4732 | T1098 |
| 6 | New Windows User Account Created | 4720 | T1136 |
| 7 | Suspicious PowerShell Download Activity | 4688 | T1105 |

Detailed KQL queries and detection logic are documented in the detections directory.

## Investigation Cases

### Investigation 001 — Excel to CMD

A controlled Excel test was used to validate detection of command interpreter execution from an Office application.

Process Chain:

explorer.exe
    |
    v
EXCEL.EXE
    |
    v
cmd.exe

The command executed was a controlled test command and did not perform malicious activity.

Analyst Verdict: Benign authorized security test.

View Investigation: investigations/investigation-001-excel-cmd.md

### Investigation 002 — Certutil Activity

A controlled certutil.exe -encode operation was generated to validate the certutil detection.

The investigation also identified legitimate Acer software using certutil.exe, demonstrating why command-line context and parent-process analysis are important.

Analyst Verdict: Benign authorized test activity and legitimate system activity.

View Investigation: investigations/investigation-002-certutil.md

### Investigation 003 — PowerShell Activity

Controlled PowerShell activity was generated to validate detections for suspicious PowerShell commands and web-request behavior.

The investigation included:

- PowerShell command execution
- IEX usage in a controlled test
- Invoke-WebRequest in a controlled test
- Parent-process analysis
- False-positive analysis

Analyst Verdict: Benign authorized security tests.

View Investigation: investigations/investigation-003-powershell.md

### Investigation 004 — Multiple Failed Windows Logons

Multiple Windows Event ID 4625 events triggered the failed-logon detection.

The raw events were investigated to determine whether the activity represented brute-force behavior.

Observations:

- Authentication failures occurred locally.
- 127.0.0.1 appeared as a source address for some events.
- No identifiable target username was present in the investigated events.
- Windows system processes such as svchost.exe and CloudExperienceHostBroker.exe were associated with the events.
- No external source IP or confirmed attacker-controlled account was identified.

Analyst Verdict: Benign/system-generated authentication failures.

Conclusion: Brute-force activity was not confirmed.

View Investigation: investigations/investigation-004-failed-logons.md

## SOC L1 Investigation Methodology

The investigations followed a repeatable SOC analyst workflow:

1. Validate the alert and detection logic.
2. Identify the affected host and account.
3. Examine the underlying Windows event.
4. Review process, command-line, parent-process, and source information.
5. Establish the process or authentication context.
6. Compare activity against expected or authorized behavior.
7. Map relevant behavior to MITRE ATT&CK.
8. Determine the final analyst verdict.
9. Document false positives and potential tuning opportunities.

The objective was not simply to generate alerts, but to determine whether the detected activity represented a genuine security concern.

## MITRE ATT&CK Coverage

The project demonstrates detection and investigation of behaviors associated with:

- T1059 — Command and Scripting Interpreter
- T1059.001 — PowerShell
- T1027 — Obfuscated/Compressed Files and Information
- T1098 — Account Manipulation
- T1136 — Create Account
- T1105 — Ingress Tool Transfer

Detailed mappings are available in the mitre-mapping directory.

## Key SOC Findings

This project demonstrated several important SOC investigation concepts.

### Alerts require investigation

A triggered alert does not automatically mean malicious activity occurred.

### Process context matters

Parent-child process relationships can help distinguish legitimate activity from suspicious execution.

### Command-line analysis is important

The process name alone may not provide enough information to determine intent.

### False positives are expected

Legitimate applications and system components can perform behaviors that resemble attacker techniques.

### Detection logic requires tuning

Broad keyword-based detections can produce false positives and should be refined using context.

### Raw event analysis provides valuable evidence

Investigating the underlying Windows event can reveal information that is not immediately visible in an alert.

## Evidence

Investigation evidence screenshots are stored in the screenshots directory.

Current investigation evidence includes:

- Excel to CMD investigation
- Certutil investigation
- PowerShell investigation
- Multiple failed-logon investigation

Screenshots should be reviewed for sensitive information before being shared publicly.

## Repository Structure

<pre>
Microsoft-Sentinel-SOC-Lab/
├── architecture/
│   └── README.md
├── detections/
│   ├── detection-01-failed-logons.md
│   ├── detection-02-powershell.md
│   ├── detection-03-office-child-process.md
│   ├── detection-04-certutil.md
│   ├── detection-05-admin-group-modification.md
│   ├── detection-06-user-account-created.md
│   └── detection-07-powershell-download.md
├── investigations/
│   ├── investigation-001-excel-cmd.md
│   ├── investigation-002-certutil.md
│   ├── investigation-003-powershell.md
│   └── investigation-004-failed-logons.md
├── incident-response/
│   └── README.md
├── mitre-mapping/
│   └── README.md
├── screenshots/
│   ├── investigation-001-excel-cmd-evidence.png
│   ├── investigation-002-certutil-evidence.png
│   ├── investigation-003-powershell-download.png
│   ├── investigation-003-powershell-iex-test.png
│   └── investigation-004-failed-logons-evidence.png
└── README.md
</pre>

## Skills Demonstrated

- Microsoft Sentinel
- SIEM Monitoring
- KQL
- Windows Event Log Analysis
- Security Alert Investigation
- Detection Engineering
- False Positive Analysis
- Process Tree Analysis
- PowerShell Investigation
- Windows Authentication Analysis
- MITRE ATT&CK
- SOC L1 Investigation Methodology
- Security Monitoring
- Incident Analysis
- Technical Documentation

## Project Outcome

The lab demonstrates a practical SOC L1 workflow from endpoint telemetry collection through detection, investigation, contextual analysis, MITRE ATT&CK mapping, and final analyst verdict.

Rather than treating every alert as malicious, the project focuses on evidence-based investigation and accurate classification of security events.

## Disclaimer

This project was created in a controlled personal laboratory environment for cybersecurity learning and portfolio purposes.

Security events and suspicious behaviors were intentionally generated to validate detection logic. No unauthorized systems were targeted.
