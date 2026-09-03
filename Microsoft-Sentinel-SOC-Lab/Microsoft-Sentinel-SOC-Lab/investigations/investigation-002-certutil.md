# Investigation 002 — Certutil

## Alert behavior

`certutil.exe` performed an encoding operation.

## Process chain

`pwsh.exe → certutil.exe -encode`

## Assessment

The event was generated intentionally using a test file to validate the detection. Benign/authorized.

A separate Acer service invocation was reviewed as legitimate software activity.

## Response

No containment required.
