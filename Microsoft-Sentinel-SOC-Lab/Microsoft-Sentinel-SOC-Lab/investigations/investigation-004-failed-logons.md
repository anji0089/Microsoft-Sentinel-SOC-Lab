# Investigation 004 — Multiple Failed Windows Logons

## Trigger

Repeated Windows 4625 events caused the failed-logon detection to fire.

## Evidence reviewed

- Target username: `-`
- Target domain: `-`
- Source: `127.0.0.1` or unavailable
- Logon type: `2`
- Authentication package: `Negotiate`
- Processes: `svchost.exe` and `CloudExperienceHostBroker.exe`
- Failure status: `0xc000006d` / `0xc0000003`

## Assessment

The evidence is consistent with local/system-generated authentication failures rather than a confirmed external brute-force attempt.

## Verdict

**Benign / system-generated activity.**

## Response

No containment or remediation required.

## Detection-engineering note

The current aggregation should be reviewed because several events do not contain a meaningful account/target value. This can create noisy alerts and weak grouping context.
