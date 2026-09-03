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
