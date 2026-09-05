# SecurityDiag Pack Validation Report

**Pack:** Konnaxion SecurityDiag  
**Version:** 1.1.0  
**Validation date:** 2026-09-05

## v1.1 security integration

SecurityDiag v1.1 is Capsule Manager / Konnaxion Agent aware while remaining independent and read-only.

Validated design properties:

- Capsule Manager policy declarations are inspected locally at S03.
- S08 rejects privileged containers, host network, host PID/IPC and dangerous host mounts.
- S09 can read the canonical Capsule Security Gate evidence through SSH.
- S09 requires the Agent to be loopback-only and checks service identity/token/audit permissions.
- `UNKNOWN`, `FAIL_BLOCKING`, and required `SKIPPED` Capsule checks do not satisfy the release gate.
- S14 requires Capsule Security Gate evidence when `capsule_manager.require_for_release=true`.
- SecurityDiag does not obtain Docker control or invoke arbitrary Agent operations.

## Framework validation

Validation commands:

```text
python -m compileall -q .
python -m unittest discover -s tests -v
python securitydiag.py doctor
```

Expected/validated targeted result for this pack:

```text
compileall: PASS
unit tests: 14 passed
doctor: PASS
```

## Konnaxion snapshot baseline

The earlier repository smoke against `Code_snapshot_Konnaxion(7).zip` established:

```text
S00 PASS
S01 WARN   exported snapshot has no live .git metadata
S02 PASS
S03 WARN   exported snapshot omitted live lockfiles / local mailpit uses latest
S04 PASS
```

No broad application rerun is required by the v1.1 bridge itself.

## Live-host evidence intentionally not fabricated

S05-S14 remain dependent on a real fresh VPS, real public hostname, privileged read evidence where required, Capsule Manager instance evidence, backup metadata and recovery attestations.

Missing live evidence is expected to become `BLOCKED`/non-passing, not an assumed PASS.
