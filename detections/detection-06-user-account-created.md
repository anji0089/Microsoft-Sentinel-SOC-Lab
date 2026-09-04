# Detection 06 — New Windows User Account Created

**Event:** 4720  
**MITRE:** T1136 — Create Account

## KQL

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, Account, Activity, TargetUserName, SubjectUserName
| order by TimeGenerated desc
```

## Controlled validation

A temporary `SentinelTest` account was created for the lab. Event 4720 identified the account creation and the user responsible for the action.

## Verdict

Benign authorized test. The temporary account was removed after testing.

## Analyst Lesson

New Windows account creation should be investigated because attackers may create accounts to maintain access to a compromised system.

An analyst should review the new account name, account type, initiating user, timing, group membership, and related authentication or privilege events.

In this lab, the account was intentionally created for detection validation and was removed after testing.


