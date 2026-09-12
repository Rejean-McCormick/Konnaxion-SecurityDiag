# Konnaxion Recovery Drill Assistant

Operational companion for SecurityDiag S13/S14. It is deliberately **not** part of the read-only diagnostic runner.

## Workflow

1. **Preflight** validates SSH/sudo, the configured backup root, required production env files and the running compose project.
2. **Backup + off-server copy** creates a PostgreSQL dump and media archive on the VPS, downloads them to the operator-selected destination, and verifies SHA-256 hashes.
3. **Isolated restore drill** uses the verified off-server copy, uploads it to temporary staging, and restores it into temporary PostgreSQL/Redis/Django containers attached only to a Docker `--internal` network. No production port is published and no production database/volume is restored into.
4. On successful restore, the tool writes the non-secret attestation required by S13 to the configured `recovery.restore_attestation_file` (default: `securitydiag/attestations/restore-drill.local.json` under the Konnaxion target repo).
5. **Human release attestations** remain explicit. The tool presents the six S14 incident-recovery statements but does not infer or pre-approve them.
6. **Run SecurityDiag Release** executes the normal release campaign after evidence is ready.

## Backup data sensitivity

The off-server PostgreSQL dump and media archive contain production data. Store them outside both Git repositories in a protected local/network/encrypted destination. The assistant rejects a destination inside either the Konnaxion target repo or the SecurityDiag repo.

## Isolation model

The restore drill creates temporary names prefixed `kxrd_` and uses:

- an internal-only Docker network;
- temporary PostgreSQL and Redis containers based on the exact running production image IDs;
- a temporary Django container based on the exact running production image ID;
- a temporary media volume;
- no published host ports;
- cleanup via shell `trap` even when the drill fails.

The Django probe calls `/accounts/login/` from inside the temporary app container and performs an ORM query through the restored database.

## Evidence generated

- latest backup state: `<target>/.securitydiag/recovery-assistant/latest-backup.json`
- drill evidence: `<target>/.securitydiag/recovery-assistant/drill-*.json`
- S13 attestation: configured `recovery.restore_attestation_file`
- local off-server manifest beside the downloaded backup files

No secret environment values are written to these evidence files.
