# Incident Response

## L1 Investigation Workflow

1. Validate the alert and timestamp.
2. Identify the affected host and account.
3. Inspect the raw events.
4. Review process and parent-process context.
5. Check source IP and authentication context where applicable.
6. Determine whether the activity is authorized, benign, suspicious, or confirmed malicious.
7. Document the verdict and evidence.
8. Escalate or contain only when evidence supports it.

## Lab Principle

Detection does not equal compromise. Every alert should be investigated before taking response action.
