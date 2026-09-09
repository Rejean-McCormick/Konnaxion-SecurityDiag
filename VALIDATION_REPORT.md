# SecurityDiag Pack Validation Report

**Pack:** Konnaxion SecurityDiag  
**Version:** 1.1.0  
**Original validation date:** 2026-09-05  
**Security hardening revision:** 2026-09-08 (S02 coverage refinement)

## v1.1 security integration

SecurityDiag v1.1 is Capsule Manager / Konnaxion Agent aware while remaining independent and read-only.

Validated design properties after the 2026-09-08 hardening revision:

- Capsule Manager policy declarations are inspected locally at S03.
- S08 rejects privileged containers, host network, host PID/IPC and dangerous host mounts.
- S08 strict allowlists cannot report PASS when their configured image/project allowlists are empty.
- S09 reads the canonical Capsule Security Gate evidence through SSH.
- S09 requires the Agent to be loopback-only and checks service identity/token/audit permissions.
- Configurable S09 remote paths are validated and shell-quoted before the fixed privileged read-only probe is executed.
- Aggregate Capsule PASS/WARN without the complete required check set is rejected.
- `UNKNOWN`, `FAIL_BLOCKING`, missing required checks, and required `SKIPPED` Capsule checks do not satisfy the release gate.
- `capsule_manager.required_gate_checks` cannot remove the canonical required baseline.
- S14 verifies presence and acceptability of all required prior levels in the `release` campaign.
- S14 requires Capsule Security Gate evidence whenever `capsule_manager.require_for_release=true`, including when Capsule integration was accidentally disabled.
- S02 reports bounded-scan coverage loss as `PARTIAL`/`WARN` instead of silently treating skipped content as complete evidence.
- S02 samples content before applying the text-size bound, so large obvious binary assets (media, archives, JARs) do not create false `PARTIAL` coverage failures. Oversized text-like files remain incomplete evidence.
- S03 declared audits are restricted to read-only package vulnerability audit commands.
- Persisted `effective_config.json` is recursively redacted as defense in depth.
- SecurityDiag does not obtain Docker control or invoke arbitrary Agent operations.

## Targeted patch validation

Validation performed against the supplied hardening patch archive:

```text
python -m compileall -q .
PYTHONPATH=. python -m unittest discover -s tests -v
```

Result:

```text
compileall: PASS
targeted tests: 17 passed
```

The supplied patch archive contains only the files being updated, so the full-project `doctor`, complete original test suite, live-host S05-S14 campaign and public external probes are not fabricated here. After merging these files into the complete SecurityDiag tree, run:

```text
python -m compileall -q .
python -m unittest discover -s tests -v
python securitydiag.py doctor
```

## Konnaxion snapshot baseline

The earlier repository smoke against `Code_snapshot_Konnaxion(7).zip` established before the coverage hardening:

```text
S00 PASS
S01 WARN   exported snapshot has no live .git metadata
S02 PASS
S03 WARN   exported snapshot omitted live lockfiles / local mailpit uses latest
S04 PASS
```

The S02 behavior is intentionally stricter after this revision: when Git tracked-file inventory is unavailable, S02 reports incomplete coverage (`PARTIAL`) instead of claiming complete tracked-secret evidence.

## Live-host evidence intentionally not fabricated

S05-S14 remain dependent on a real fresh VPS, real public hostname, privileged read evidence where required, Capsule Manager instance evidence, backup metadata and recovery attestations.

Missing live evidence is expected to become `BLOCKED`/non-passing, not an assumed PASS.
