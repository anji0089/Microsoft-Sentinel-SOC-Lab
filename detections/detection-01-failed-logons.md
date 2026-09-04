# Detection 01 — Multiple Failed Windows Logons

**Event:** 4625  
**Purpose:** Identify repeated failed Windows authentication attempts within a five-minute window.

## KQL

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count()
    by Account, Computer, IpAddress, TimeWindow = bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
```

## MITRE

**T1110 — Brute Force**

The detection identifies repeated authentication failures that may indicate brute-force behavior.

In this lab, the investigated events were assessed as benign/system-generated activity, so no brute-force attack was confirmed.

## Validation

A Sentinel alert was generated successfully. The underlying events were then reviewed individually.

## Investigation result

The observed events had no identifiable target username, used local/system processes such as `svchost.exe` and `CloudExperienceHostBroker.exe`, and included `127.0.0.1` as a source for some events. The activity was assessed as benign/system-generated rather than confirmed brute-force activity.

## Analyst lesson

A failed-logon threshold alone does not establish malicious activity. Source, target, process context, timing, and authentication details must be investigated.
