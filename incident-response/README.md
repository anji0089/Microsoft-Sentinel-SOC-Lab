# Incident Response

This section documents the incident response workflow used in the Microsoft Sentinel SOC Lab.

The purpose is to demonstrate how a SOC L1 analyst handles a security alert from initial triage through investigation, evidence analysis, verdict, response, documentation, and closure.

---

## Incident Response Workflow

**Security Alert → Initial Triage → Alert Validation → Investigation → Evidence Analysis → Analyst Verdict → Response → Documentation → Closure**

The response process is based on evidence rather than assuming that every triggered alert represents malicious activity.

---

## SOC L1 Investigation Flow

**Alert → Validate → Identify Host/User → Examine Event → Analyze Command Line → Check Parent Process → Correlate Related Events → Determine Verdict → Respond → Document**

The analyst follows this process to determine whether the detected activity represents legitimate, suspicious, or malicious behavior.

---

## 1. Initial Triage

When a Microsoft Sentinel alert is generated, the analyst first reviews the available alert information.

The following information is examined:

- Alert name
- Severity
- Time generated
- Affected host
- User or account
- Source IP address
- Windows Event ID
- Command line or activity
- MITRE ATT&CK technique
- Related alerts or events

The goal of initial triage is to understand what triggered the alert and determine whether further investigation is required.

---

## 2. Alert Validation

The analyst validates the alert against the underlying telemetry.

Validation includes:

- Confirming that the triggering event exists in Log Analytics.
- Confirming that the event matches the analytics rule logic.
- Identifying the affected host and account.
- Reviewing the event timestamp.
- Checking the command line or activity that triggered the detection.
- Determining whether the activity could be legitimate or authorized.

A detection threshold by itself does not prove malicious activity.

### Alert Validation Flow

**Sentinel Alert → Locate Underlying Event → Compare With Detection Logic → Review Host/User → Review Activity → Validate Detection**

---

## 3. Investigation

After validating the alert, the analyst investigates related telemetry to establish context.

Depending on the detection, the investigation may include:

- Windows SecurityEvent analysis
- Process creation analysis
- Parent-child process relationships
- Command-line analysis
- User and account activity
- Source IP analysis
- Authentication details
- Related events before and after the alert
- Legitimate software or administrative activity

The investigation focuses on answering:

**What happened?**

**Who or what performed the activity?**

**Which system was involved?**

**Was the activity expected or suspicious?**

**Is there enough evidence to confirm malicious activity?**

### Investigation Flow

**Alert → Event Details → Host/User → Process or Authentication Context → Related Events → Evidence Correlation → Analyst Assessment**

---

## 4. Evidence Analysis

Evidence is collected from the underlying security telemetry.

Important evidence can include:

- Timestamp
- Computer name
- Account
- Process name
- Command line
- Parent process
- Event ID
- Source IP address
- Authentication information
- Related events
- Sentinel alert details
- Investigation screenshots

The evidence is evaluated together rather than relying on a single field.

Sensitive information such as passwords, tokens, secrets, subscription identifiers, or other credentials should not be published in screenshots or documentation.

### Evidence Analysis Flow

**Event Data → Process/User Context → Command Line → Parent Process → Related Events → Correlation → Evidence-Based Conclusion**

---

## 5. Analyst Verdict

After investigation, the analyst assigns a final verdict based on the available evidence.

### Benign / Authorized Activity

The activity is determined to be legitimate, expected, system-generated, administrative, or intentionally generated as part of a security test.

**Verdict:** Benign / Authorized Security Test

**Reason:** The activity was intentionally generated to validate the Microsoft Sentinel detection. The process, account, command line, and surrounding activity were reviewed and no malicious behavior was identified.

### Suspicious Activity

The activity contains indicators associated with potentially malicious behavior, but there is not enough evidence to confirm compromise.

**Verdict:** Suspicious

**Action:** Continue investigation and escalate when appropriate.

### Malicious Activity

The available evidence supports that the activity was unauthorized or malicious.

**Verdict:** Malicious

**Action:** Follow the appropriate containment, eradication, recovery, and escalation procedures.

### Verdict Flow

**Evidence Collected → Context Reviewed → Activity Classified**

**Benign → Document and Close**

**Suspicious → Continue Investigation / Escalate**

**Malicious → Contain / Escalate / Remediate**

---

## 6. Response Actions

Response actions depend on the investigation result.

### Benign Activity

For confirmed benign activity:

- Document the investigation.
- Record the reason for the classification.
- Close the alert when appropriate.
- Consider detection tuning if the activity repeatedly causes false positives.

### Suspicious Activity

For suspicious activity:

- Continue investigation.
- Correlate additional telemetry.
- Identify affected systems and accounts.
- Escalate to the appropriate security team.
- Recommend containment when supported by the evidence.

### Confirmed Malicious Activity

For confirmed malicious activity, possible response actions include:

- Isolate the affected endpoint when authorized.
- Disable or secure compromised accounts.
- Block malicious indicators when appropriate.
- Remove malicious processes or persistence mechanisms.
- Preserve relevant evidence.
- Escalate to the incident response team.
- Continue monitoring for related activity.
- Document all response actions.

No containment action is assumed unless the investigation provides sufficient evidence and the action is authorized.

### Response Flow

**Verdict → Response Decision → Containment if Required → Eradication/Remediation → Recovery → Monitoring → Documentation → Closure**

---

## 7. Detection Tuning

Investigation results can identify opportunities to improve detection quality.

During this project, several detections demonstrated why context is important.

Examples include:

- Legitimate software generating command-line activity.
- Windows system processes generating authentication failures.
- PowerShell commands containing suspicious keywords without actually performing malicious actions.
- Legitimate applications executing utilities that can also be abused by attackers.

Possible tuning approaches include:

- Adding account context.
- Adding parent-process conditions.
- Filtering known legitimate system activity.
- Requiring stronger command-line patterns.
- Adjusting thresholds.
- Adding additional event correlation.

Detection tuning should reduce false positives without removing meaningful attacker behavior.

### Detection Tuning Flow

**Detection → Investigation → False Positive Identified → Identify Missing Context → Improve Detection Logic → Test Again → Validate Detection Quality**

---

## 8. Case Documentation

Each investigation should document:

- What triggered the alert
- When the activity occurred
- Which host was involved
- Which account was involved
- What activity was observed
- What evidence was collected
- What related events were identified
- What the analyst concluded
- What response was performed
- Why the case was closed

Good documentation allows another analyst to understand the investigation without repeating the entire analysis.

### Case Documentation Flow

**Alert → Investigation Notes → Evidence → Analyst Verdict → Response → Closure Reason**

---

# Lab Investigation Results

The following investigations were performed in the Microsoft Sentinel SOC Lab using controlled security tests and observed Windows telemetry.

---

## Investigation 001 — Excel to CMD

A controlled Excel VBA test launched `cmd.exe` to validate the Office child-process detection.

### Observed Process Chain

**explorer.exe → EXCEL.EXE → cmd.exe → echo Sentinel Detection Test**

The command executed was a controlled test command and did not perform malicious activity.

### Investigation

- Parent process: `EXCEL.EXE`
- Child process: `cmd.exe`
- Account: `ACER\anji0`
- Host: `ACER`
- Event ID: `4688`
- Activity: Controlled command execution
- Purpose: Detection validation

### Analyst Verdict

**Benign / Authorized Security Test**

### Response

No containment was required. The activity was documented as controlled detection validation.

---

## Investigation 002 — Certutil Activity

A controlled `certutil.exe -encode` operation was executed to validate the certutil detection.

### Observed Process Chain

**pwsh.exe → certutil.exe → -encode → Controlled Test File**

The operation was performed against a controlled test file created specifically for detection validation.

### Investigation

- Parent process: `pwsh.exe`
- Child process: `certutil.exe`
- Account: `ACER\anji0`
- Host: `ACER`
- Event ID: `4688`
- Activity: Controlled certutil encoding
- MITRE ATT&CK: T1027
- Purpose: Detection validation

### Analyst Verdict

**Benign / Authorized Security Test**

### Response

No containment was required. The activity was documented as a controlled detection test.

---

## Investigation 003 — PowerShell Activity

Controlled PowerShell commands were executed to validate PowerShell-based detections.

The tests included controlled `IEX` and `Invoke-WebRequest` activity.

### PowerShell Investigation Chain

**pwsh.exe → powershell.exe → Controlled PowerShell Command → Sentinel Detection → Evidence Analysis → Analyst Verdict**

For the web-request test:

**pwsh.exe → powershell.exe → Invoke-WebRequest → Sentinel Alert → Investigation → Benign Verdict**

For the IEX test:

**PowerShell → IEX('Write-Output TEST') → Sentinel Alert → Command-Line Analysis → Benign Verdict**

### Investigation

The analyst reviewed:

- PowerShell executable
- Account
- Command line
- Parent process
- Event ID
- Timestamp
- Detection rule
- Related telemetry

The investigation also identified examples where legitimate or test commands contained suspicious keywords without representing malicious behavior.

### Analyst Verdict

**Benign / Authorized Security Test**

### Response

No containment was required. The activity was documented as controlled detection validation.

---

## Investigation 004 — Failed Windows Logons

Multiple Windows authentication failures were investigated after the failed-logon detection generated an alert.

### Authentication Investigation Flow

**Event ID 4625 → Failed Authentication → Account/Target Analysis → Source IP Analysis → Logon Type → Authentication Details → Process Context → Related Events → Analyst Verdict**

### Observed Evidence

The investigated events included:

- Event ID: `4625`
- Host: `ACER`
- Source IP: `127.0.0.1` or unavailable
- Logon Type: `2`
- Authentication Package: `Negotiate`
- Failure information associated with Windows authentication
- Processes including Windows system components

The events did not provide evidence of an external source attempting to authenticate against the system.

The target account fields were also not sufficient to establish a specific brute-force target.

### Analyst Assessment

The observed activity was consistent with system-generated or local authentication failures rather than confirmed external brute-force activity.

### Analyst Verdict

**Benign / System-Generated Authentication Activity**

### Response

No containment was required.

The investigation was documented and the detection behavior was reviewed for potential future tuning.

---

# Process Investigation Methodology

Process-based detections require more than looking at the executable name.

The analyst should examine:

1. Process name
2. Command line
3. Parent process
4. Account
5. Host
6. Timestamp
7. Related processes
8. Related events
9. Expected application behavior
10. Evidence of malicious intent

### Process Investigation Chain

**Process Created → Identify Parent → Examine Command Line → Identify User → Check Host → Correlate Events → Determine Intent → Verdict**

For example:

**explorer.exe → EXCEL.EXE → cmd.exe → Controlled Command**

The process chain alone is suspicious enough to investigate, but the final verdict requires additional context.

---

# PowerShell Investigation Methodology

PowerShell is commonly monitored because attackers can use it for execution, downloading content, scripting, and post-compromise activity.

However, PowerShell activity is not automatically malicious.

The analyst should investigate:

- Executing account
- PowerShell executable
- Parent process
- Command line
- Encoded commands
- Download-related commands
- Script execution
- Network activity
- Related process creation
- User intent
- Whether the activity was authorized

### PowerShell Investigation Chain

**PowerShell Event → Command-Line Analysis → Parent Process → Account → Related Activity → Detection Context → Verdict**

A suspicious keyword should therefore be treated as an investigation starting point rather than proof of compromise.

---

# Authentication Investigation Methodology

Authentication alerts require analysis of the authentication context.

The analyst should examine:

- Event ID
- Account
- Target username
- Source IP
- Logon type
- Authentication package
- Failure reason
- Status and substatus
- Process involved
- Related successful or failed logons
- Host activity

### Authentication Investigation Chain

**Authentication Failure → Identify Account → Identify Source → Analyze Logon Type → Review Authentication Details → Correlate Events → Determine Whether Activity Is Expected**

This helps distinguish normal system-generated authentication failures from suspicious credential attacks.

---

# SOC L1 Investigation Principles

The following principles were applied throughout the project:

### 1. Alert Does Not Equal Incident

A detection rule identifies activity that requires investigation.

It does not automatically prove compromise.

### 2. Context Matters

The same command can be legitimate in one situation and malicious in another.

### 3. Process Relationships Matter

Parent-child relationships can provide important context about how a process was launched.

### 4. Command Lines Matter

Command-line arguments can reveal the actual behavior behind a process execution event.

### 5. Correlation Matters

A single event may be ambiguous. Related events can provide the additional context needed for a confident verdict.

### 6. Evidence-Based Verdicts

The analyst should classify activity based on collected evidence rather than assumptions.

### 7. Document Everything

Investigation notes should allow another analyst to understand what happened, what was checked, and why the final verdict was reached.

---

# MITRE ATT&CK Investigation Coverage

The investigations and detections in this project cover multiple MITRE ATT&CK techniques and tactics.

Examples include:

- T1059 — Command and Scripting Interpreter
- T1059.001 — PowerShell
- T1027 — Obfuscated/Compressed Files and Information
- T1098 — Account Manipulation
- T1136 — Create Account
- T1105 — Ingress Tool Transfer

The MITRE mappings provide additional context for understanding the attacker behaviors represented by the detections.

---

# Overall Incident Response Flow

**Security Alert**

↓

**Initial Triage**

↓

**Alert Validation**

↓

**Investigation**

↓

**Evidence Analysis**

↓

**Analyst Verdict**

↓

**Benign / Suspicious / Malicious**

↓

**Response**

↓

**Documentation**

↓

**Closure**

---

# Project Outcome

This incident response workflow demonstrates a practical SOC L1 approach to handling security alerts in Microsoft Sentinel.

The lab demonstrates the complete analytical process:

**Detection → Validation → Investigation → Evidence Correlation → Verdict → Response → Documentation**

The project also demonstrates that effective SOC analysis requires understanding the context surrounding an alert rather than treating every detection as confirmed malicious activity.

All investigations in this lab were performed in a controlled environment for detection validation and learning purposes.

No real-world malicious activity was intentionally performed.
