# Coverage Model

## Why coverage is separate from findings

A scanner that finds zero endpoints has not proven that zero endpoints exist. Coverage records what the auditor was capable of inspecting and prevents false `complete` results.

## Required coverage data

Every audit records:

- detected languages;
- detected frameworks;
- detected HTTP/integration clients;
- detector executions and versions;
- files scanned;
- files excluded and exclusion rules;
- unsupported surfaces/patterns;
- inventory completeness.

## Detector statuses

- `supported`: detector supports the relevant detected patterns and completed successfully.
- `partial`: detector ran but known relevant patterns are not fully covered.
- `unsupported`: no reliable detector exists for the detected pattern.
- `failed`: detector should have run but failed.

Only `supported` detectors can contribute to a `complete` audit.

## Integration surface statuses

- `confirmed`: surface exists and is sufficiently classified.
- `probable`: evidence suggests existence but is incomplete.
- `unverified`: existence/details cannot be confirmed.
- `unsupported`: surface exists but cannot currently be audited adequately.

## Audit status decision

`complete` requires:

```text
inventory_complete
AND no detector in partial/unsupported/failed
AND unsupported_surfaces = []
AND primary outputs valid
```

`partial` is required when useful findings exist but coverage is incomplete.

`failed` is required when the audit cannot produce trustworthy derived knowledge for the source snapshot.

## Unknown vs absent

- `confirmed_absent`: positive evidence supports absence in the covered scope.
- `not_detected`: scanner found no instance; this is not proof of absence.
- `unknown`: insufficient evidence.
- `unsupported`: auditor cannot inspect the relevant surface reliably.
