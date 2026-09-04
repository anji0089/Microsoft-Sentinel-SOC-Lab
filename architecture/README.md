# Architecture

This document describes the architecture and telemetry flow used in the Microsoft Sentinel SOC Lab.

The lab uses a Windows 11 endpoint connected to Azure through Azure Arc. Windows security telemetry is collected and sent to Log Analytics, where Microsoft Sentinel analytics rules evaluate the events and generate security alerts for investigation.

---

## Architecture Components

1. **Windows 11 Endpoint**
   - Lab endpoint: `ACER`
   - Generates Windows Security Events.
   - Used to perform controlled security tests.

2. **Azure Connected Machine Agent / Azure Arc**
   - Connects the Windows endpoint to Azure.
   - Enables Azure-based management and telemetry collection.

3. **Azure Monitor Agent**
   - Collects configured Windows event logs from the endpoint.
   - Sends the collected telemetry to the configured Log Analytics workspace.

4. **Log Analytics Workspace**
   - Stores and provides access to the collected Windows security telemetry.
   - Windows security events are queried from the `SecurityEvent` table.

5. **Microsoft Sentinel**
   - Uses analytics rules to detect suspicious behavior.
   - Generates security alerts when detection conditions are met.
   - Provides the investigation environment for SOC analysis.

6. **SOC Investigation**
   - Analysts validate alerts against the underlying telemetry.
   - Related events, processes, accounts, command lines, and authentication details are investigated.
   - The analyst assigns a final verdict based on evidence.

---

## High-Level Architecture

<pre>
Windows 11 Endpoint (ACER)
          |
          | Windows Security Events
          v
Azure Connected Machine Agent / Azure Arc
          |
          | Telemetry Collection
          v
Azure Monitor Agent
          |
          | Event Logs
          v
Log Analytics Workspace
          |
          | SecurityEvent Table
          v
Microsoft Sentinel
          |
          | Analytics Rules
          v
Security Alerts
          |
          v
SOC L1 Investigation
          |
          | Evidence Analysis
          v
Analyst Verdict
          |
          +----------------------+
          |          |           |
          v          v           v
       Benign    Suspicious   Malicious
          |          |           |
          v          v           v
      Document    Escalate    Contain /
      & Close     & Continue  Remediate
                  Analysis
</pre>

---

## Detailed Telemetry Flow

The complete telemetry pipeline used in this project is:

**Windows Activity → Windows Security Event → Azure Arc / Connected Machine Agent → Azure Monitor Agent → Log Analytics → SecurityEvent → Sentinel Analytics Rule → Security Alert → SOC Investigation**

The analyst then follows:

**Security Alert → Initial Triage → Alert Validation → Investigation → Evidence Analysis → Analyst Verdict → Response → Documentation → Closure**

---

## Detection Pipeline

The detections in this project primarily use Windows Security Event telemetry.

### Process Creation Detection

**User/Application Activity → Event ID 4688 → SecurityEvent → Sentinel Analytics Rule → Security Alert → Process Investigation**

Examples investigated:

- PowerShell execution
- Office spawning command shell
- Certutil execution
- PowerShell download activity

---

### Authentication Detection

**Authentication Failure → Event ID 4625 → SecurityEvent → Sentinel Analytics Rule → Security Alert → Authentication Investigation**

The analyst reviews:

- Account
- Source IP
- Logon type
- Authentication package
- Failure information
- Process context
- Related authentication events

---

### Account Activity Detection

**Account Change → Windows Security Event → SecurityEvent → Sentinel Analytics Rule → Security Alert → Account Investigation**

Examples include:

- Event ID `4720` — New user account created
- Event ID `4732` — Member added to local security-enabled group

These events can be correlated to understand account creation and privilege changes.

---

## Core Windows Events Used

| Event ID | Activity | Purpose in Lab |
|---:|---|---|
| 4688 | Process Creation | PowerShell, Office child process, and certutil detections |
| 4625 | Failed Logon | Multiple failed Windows logon detection |
| 4720 | User Account Created | New Windows user account detection |
| 4732 | Member Added to Local Group | Local Administrator group modification detection |
| 4624 | Successful Logon | Authentication context and correlation |
| 4672 | Special Privileges Assigned | Privileged activity context |
| 4798 | Local Group Membership Enumeration | Supporting investigation context |
| 5379 | Credential Manager Activity | Supporting investigation context |

Not every observed Windows event became a detection. Some events were reviewed during investigation but were considered too noisy or insufficiently specific for standalone detections.

---

## Sentinel Detection Architecture

The Sentinel detection process is:

**SecurityEvent → KQL Query → Analytics Rule → Detection Condition → Security Alert → Analyst Investigation**

Each analytics rule evaluates incoming telemetry using KQL.

When the defined conditions are satisfied, Sentinel generates an alert that can be investigated by the SOC analyst.

---

## Example: PowerShell Detection Flow

**User Executes PowerShell**

↓

**Windows Generates Event ID 4688**

↓

**Event Is Collected by Azure Monitor Agent**

↓

**Event Is Stored in Log Analytics**

↓

**SecurityEvent Is Evaluated by Sentinel**

↓

**PowerShell Analytics Rule Matches**

↓

**Security Alert Generated**

↓

**SOC Analyst Reviews Command Line and Parent Process**

↓

**Related Events Are Correlated**

↓

**Analyst Determines Verdict**

---

## Example: Office Child Process Detection Flow

**Excel Opens**

↓

**Excel VBA Launches cmd.exe**

↓

**Windows Generates Event ID 4688**

↓

**Event Is Ingested into Log Analytics**

↓

**Sentinel Analytics Rule Detects Office → Command Shell Relationship**

↓

**Security Alert Generated**

↓

**SOC Analyst Investigates Parent-Child Process Relationship**

↓

**Process Chain Reviewed**

**explorer.exe → EXCEL.EXE → cmd.exe**

↓

**Controlled Test Confirmed**

↓

**Benign / Authorized Security Test**

---

## Example: Account Change Detection Flow

**Controlled User Account Creation**

↓

**Event ID 4720 Generated**

↓

**Event Collected in SecurityEvent**

↓

**Sentinel Detects New Account**

↓

**Security Alert Generated**

↓

**SOC Analyst Investigates Account**

↓

**Related Event ID 4732 Identified**

↓

**Account Added to Administrators**

↓

**Activity Confirmed as Authorized Lab Test**

↓

**Benign / Authorized Security Test**

---

## Security Investigation Architecture

The architecture supports a complete SOC L1 investigation process:

**Detection**

↓

**Alert Validation**

↓

**Host and Account Identification**

↓

**Event Analysis**

↓

**Process / Authentication Analysis**

↓

**Command-Line Analysis**

↓

**Related Event Correlation**

↓

**Evidence Assessment**

↓

**Analyst Verdict**

↓

**Response**

↓

**Documentation**

↓

**Closure**

---

## Project Architecture Summary

The project demonstrates a complete security monitoring pipeline:

**Endpoint → Telemetry Collection → Log Analytics → Microsoft Sentinel → Detection → Alert → Investigation → Verdict → Response**

This architecture provides the foundation for the seven Sentinel detections and four documented investigations included in this project.

---

## Lab Environment

| Component | Configuration |
|---|---|
| Endpoint | Windows 11 Pro |
| Host | `ACER` |
| Azure Connectivity | Azure Arc |
| Telemetry Agent | Azure Monitor Agent |
| Log Platform | Azure Log Analytics |
| SIEM | Microsoft Sentinel |
| Primary Table | `SecurityEvent` |
| Detection Language | KQL |
| Detection Type | Sentinel Analytics Rules |
| Investigation | SOC L1 Evidence-Based Analysis |

---

## Architecture Principle

The project follows an evidence-based security monitoring model:

**Collect → Detect → Validate → Investigate → Correlate → Decide → Respond → Document**

The presence of an alert does not automatically indicate malicious activity.

The analyst must validate the underlying telemetry and investigate the surrounding context before assigning a final verdict.
