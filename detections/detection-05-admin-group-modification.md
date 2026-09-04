# Detection 05 — Local Administrator Group Modification

**Event:** 4732  
**MITRE:** T1098 — Account Manipulation

## KQL

```kql
SecurityEvent
| where EventID == 4732
| where TargetUserName =~ "Administrators"
| project TimeGenerated, Computer, Account, Activity, TargetUserName, MemberName, SubjectUserName
| order by TimeGenerated desc
```

## Controlled validation

A temporary lab account was created and added to the local Administrators group. Event 4732 confirmed the group modification.

## Analyst action

The temporary test account was removed after validation. No permanent privilege change was intended.

## Investigation Result

The 4732 event confirmed that a user account was added to the local Administrators group.

The activity was intentionally generated during lab validation. The temporary account was removed after testing, so no unauthorized privilege change remained.

## Analyst Lesson

Membership changes to privileged groups should be investigated because they can provide an account with elevated permissions.

An analyst should review the target group, member account, initiating user, timing, and related account-creation or authentication events before determining whether the change is authorized.

In this lab, the modification was an authorized controlled test and was assessed as benign.
