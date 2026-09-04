# MITRE ATT&CK Mapping

This section maps the Microsoft Sentinel detections developed in this SOC Lab to relevant MITRE ATT&CK techniques.

The mappings are based on the behavior the detections are designed to identify and the Windows telemetry investigated during the lab.

---

## Detection-to-MITRE Mapping

| Detection | Event ID | MITRE Tactic | MITRE Technique | Investigation Evidence |
|---|---:|---|---|---|
| Suspicious PowerShell Command Execution | 4688 | Execution | T1059.001 — PowerShell | `powershell.exe` process creation and suspicious command-line patterns |
| Suspicious Office Child Process Creation | 4688 | Execution | T1059.003 — Windows Command Shell | Office application spawning `cmd.exe` |
| Suspicious Certutil Activity | 4688 | Defense Evasion | T1027 — Obfuscated/Compressed Files and Information | `certutil.exe` executing encoding-related activity |
| Local Administrator Group Modification | 4732 | Persistence / Privilege Escalation | T1098 — Account Manipulation | Account added to the local Administrators group |
| New Windows User Account Created | 4720 | Persistence | T1136 — Create Account | New local account creation |
| Suspicious PowerShell Download Activity | 4688 | Command and Control | T1105 — Ingress Tool Transfer | PowerShell executing `Invoke-WebRequest` or other download-related commands |
| Multiple Failed Windows Logons | 4625 | Credential Access | Credential Access context | Repeated authentication failures investigated for possible credential attack behavior |

---

# 1. T1059.001 — PowerShell

### Detection

**Suspicious PowerShell Command Execution**

### Windows Event

`4688 — Process Creation`

### Observed Behavior

The detection identifies PowerShell processes containing suspicious command-line patterns.

Examples include:

- Encoded PowerShell commands
- `IEX`
- `Invoke-WebRequest`
- `DownloadString`
- `FromBase64String`

### Investigation Flow

**Event 4688 → powershell.exe → Command-Line Analysis → Parent Process → Account → Related Events → Analyst Verdict**

### Lab Evidence

Controlled PowerShell activity was generated to validate the detection.

Examples included:

**pwsh.exe → powershell.exe → IEX('Write-Output TEST')**

and:

**pwsh.exe → powershell.exe → Invoke-WebRequest → Sentinel Detection**

The activity was intentionally generated for detection testing.

### Analyst Assessment

The commands were reviewed in context and determined to be authorized security tests rather than malicious execution.

### Verdict

**Benign / Authorized Security Test**

---

# 2. T1059.003 — Windows Command Shell

### Detection

**Suspicious Office Child Process Creation**

### Windows Event

`4688 — Process Creation`

### Observed Behavior

The detection identifies command interpreters launched by Office or other application processes.

The controlled lab test involved Excel launching `cmd.exe`.

### Process Chain

**explorer.exe → EXCEL.EXE → cmd.exe → echo Sentinel Detection Test**

### Investigation Flow

**Event 4688 → Identify Parent Process → Identify Child Process → Analyze Command Line → Identify User → Determine Intent**

### Lab Evidence

A controlled Excel VBA test launched:

`cmd.exe /c echo Sentinel Detection Test`

The command was intentionally generated to validate the detection.

### Analyst Assessment

The parent-child relationship was suspicious enough to trigger investigation, but the command itself was harmless and intentionally executed as part of the lab.

### Verdict

**Benign / Authorized Security Test**

---

# 3. T1027 — Obfuscated/Compressed Files and Information

### Detection

**Suspicious Certutil Activity**

### Windows Event

`4688 — Process Creation`

### Observed Behavior

The detection monitors `certutil.exe` for command-line options associated with encoding, decoding, or other potentially suspicious usage.

Examples monitored include:

- `-encode`
- `-decode`
- `-decodehex`
- `-urlcache`
- `-verifyctl`
- `-split`

### Process Chain

**pwsh.exe → certutil.exe → -encode → Controlled Test File**

### Investigation Flow

**Event 4688 → certutil.exe → Command-Line Analysis → Parent Process → Account → File Context → Analyst Verdict**

### Lab Evidence

A controlled test file was created and encoded using `certutil.exe -encode`.

The operation was performed specifically to validate the Sentinel detection.

### Analyst Assessment

The use of `certutil.exe` was identified and investigated because the utility can be abused by attackers.

In this lab, the activity was authorized and performed against a controlled test file.

### Verdict

**Benign / Authorized Security Test**

---

# 4. T1098 — Account Manipulation

### Detection

**Local Administrator Group Modification**

### Windows Event

`4732 — Member Added to Security-Enabled Local Group`

### Observed Behavior

The detection monitors changes to the local `Administrators` group.

### Investigation Flow

**Event 4732 → Identify Target Group → Identify Member → Identify Account Performing Change → Correlate Account Creation → Determine Authorization**

### Lab Evidence

A temporary test account named `SentinelTest` was created and added to the local Administrators group to validate the detection.

The related account creation generated Event ID `4720`.

### Correlated Activity

**4720 — Account Created**

↓

**4732 — Account Added to Administrators**

This correlation provided additional context for the investigation.

### Analyst Assessment

The account and privilege change were intentionally generated as part of the Sentinel detection test.

### Verdict

**Benign / Authorized Security Test**

---

# 5. T1136 — Create Account

### Detection

**New Windows User Account Created**

### Windows Event

`4720 — A User Account Was Created`

### Observed Behavior

The detection identifies newly created Windows user accounts.

### Investigation Flow

**Event 4720 → Identify New Account → Identify Creating Account → Review Host → Correlate Group Membership → Determine Authorization**

### Lab Evidence

The controlled test created the temporary account:

`SentinelTest`

The account was created by:

`ACER\anji0`

The activity was performed specifically to validate the Sentinel detection.

### Related Event

The account creation was correlated with Event ID `4732`, which showed the account being added to the local Administrators group.

### Analyst Assessment

The account creation was authorized and part of the security testing performed in the lab.

### Verdict

**Benign / Authorized Security Test**

---

# 6. T1105 — Ingress Tool Transfer

### Detection

**Suspicious PowerShell Download Activity**

### Windows Event

`4688 — Process Creation`

### Observed Behavior

The detection looks for PowerShell commands associated with downloading content.

Examples include:

- `Invoke-WebRequest`
- `Invoke-RestMethod`
- `WebClient`
- `DownloadString`
- `DownloadFile`
- `Start-BitsTransfer`

### PowerShell Investigation Chain

**pwsh.exe → powershell.exe → Invoke-WebRequest → Sentinel Alert → Evidence Analysis → Analyst Verdict**

### Lab Evidence

A controlled PowerShell process executed:

`Invoke-WebRequest https://example.com -UseBasicParsing`

The command was used to validate the detection.

### Analyst Assessment

The activity contained a download-related PowerShell command and therefore triggered investigation.

The destination and command context were reviewed, and the activity was determined to be a controlled security test.

### Verdict

**Benign / Authorized Security Test**

---

# 7. Failed Windows Logons — Credential Access Context

### Detection

**Multiple Failed Windows Logons**

### Windows Event

`4625 — An Account Failed to Log On`

### Observed Behavior

The detection identifies multiple failed Windows authentication attempts within a defined time window.

### Investigation Flow

**Event 4625 → Account Analysis → Source IP Analysis → Logon Type → Authentication Package → Process Context → Related Events → Analyst Verdict**

### Lab Evidence

The investigated events included:

- Event ID: `4625`
- Host: `ACER`
- Source: `127.0.0.1` or unavailable
- Logon Type: `2`
- Authentication Package: `Negotiate`
- Processes including `svchost.exe` and `CloudExperienceHostBroker.exe`
- Target username/domain fields that did not identify a meaningful external account

### Analyst Assessment

The evidence was consistent with local or system-generated authentication failures.

There was not enough evidence to confirm an external brute-force attack.

### Verdict

**Benign / System-Generated Activity**

### Detection Engineering Note

The investigation identified that some events did not contain meaningful account or target values.

This can create noisy alerts and weak grouping context.

Future tuning could improve account correlation and reduce false positives without removing meaningful authentication attack detection.

---

# MITRE Coverage Summary

The project demonstrates detection and investigation coverage across several ATT&CK areas:

**Execution**

- T1059.001 — PowerShell
- T1059.003 — Windows Command Shell

**Defense Evasion**

- T1027 — Obfuscated/Compressed Files and Information

**Persistence / Privilege Escalation**

- T1098 — Account Manipulation
- T1136 — Create Account

**Command and Control**

- T1105 — Ingress Tool Transfer

**Credential Access**

- Multiple Failed Windows Logons — behavioral credential-access detection context

---

# Detection-to-Investigation Relationship

The project follows the relationship:

**MITRE Technique → Detection Logic → Windows Event → Sentinel Alert → Investigation → Evidence → Analyst Verdict**

For example:

**T1059.001**

↓

**PowerShell Detection**

↓

**Event 4688**

↓

**powershell.exe**

↓

**Command-Line Analysis**

↓

**Parent Process Analysis**

↓

**Related Telemetry**

↓

**Benign / Suspicious / Malicious Verdict**

This demonstrates how MITRE ATT&CK techniques can be used to provide behavioral context for SIEM detections.

---

# Important Analyst Principle

A MITRE ATT&CK mapping does not mean that the observed activity is automatically malicious.

The technique describes the behavior that could be associated with an attacker.

The analyst must still investigate:

- Who performed the activity?
- What process executed?
- What command was used?
- What was the parent process?
- Which host was involved?
- Was the activity authorized?
- What related events occurred?
- Is there sufficient evidence of malicious intent?

Therefore:

**MITRE Technique ≠ Confirmed Attack**

The final classification must be based on evidence and context.

---

# Project Outcome

The MITRE ATT&CK mapping connects the Sentinel detections to recognizable attacker behaviors and provides a structured framework for investigation.

The completed workflow demonstrates:

**Detection → MITRE Mapping → Telemetry Analysis → Investigation → Evidence Correlation → Analyst Verdict**

This approach reflects a practical SOC L1 workflow where detections are investigated using both technical telemetry and behavioral context.
