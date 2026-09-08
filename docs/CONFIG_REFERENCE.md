# SecurityDiag configuration reference

SecurityDiag loads `securitydiag.config.json` and overlays `securitydiag.config.local.json` when present.

## Important sections

### `execution`

- `allow_network`: permits declared SSH/external probes.
- `allow_declared_audits`: permits only explicitly configured **read-only package vulnerability audits**.

Declared audit commands are constrained to reviewed audit forms such as `pnpm audit`, `npm audit`, `yarn audit`, and `pip-audit` (including `python -m pip_audit`). Mutating/output options such as audit `fix`/`--fix` or `--output` are rejected with `CONFIG_ERROR`.

### `scan`

- `max_files`: maximum repository files traversed by bounded scanners.
- `max_file_bytes`: maximum size for text-content scanning.

S02 records coverage metadata. Hitting `max_files`, losing Git tracked-file inventory, read errors, or skipping oversized **tracked** files produces `PARTIAL` rather than an implicit PASS. Oversized untracked files produce a warning when untracked scanning is enabled. Binary files are counted separately.

### `remote`

- `enabled`: enables remote VPS evidence.
- `host`, `port`: SSH target.
- `user`: recommended human audit/ops account; default is `ops`.
- `identity_file`: local private-key path; never embed key material.
- `sudo_mode`: `disabled` or `noninteractive`. Noninteractive means `sudo -n`.
- `allowed_sudo_users`: expected human sudo identities.
- `allowed_ssh_key_fingerprints`: expected authorized-key fingerprints.
- `docker.strict_container_allowlist`: fail unknown runtime containers/images when evidence is available.

When `docker.strict_container_allowlist=true`, both `allowed_image_prefixes` and `allowed_compose_projects` must be non-empty. An empty strict allowlist is a configuration error, never PASS.

### `capsule_manager`

- `enabled`: enables Capsule-aware policy/evidence correlation.
- `repo_root`: explicit path or `auto` for sibling `Konnaxion_Capsule_Manager`.
- `instance_id`: required for remote Capsule evidence.
- `agent_port`: expected local Agent port, default `8765`.
- `require_for_release`: S14 requires Capsule evidence even if the integration was accidentally left disabled.
- `unknown_is_blocking`: controls UNKNOWN handling only when Capsule evidence is not required for release; release qualification always treats required UNKNOWN evidence as blocking.
- `require_local_agent_bind`: controls non-release diagnostics; when Capsule evidence is required for release, S09 always requires the Agent listener to be loopback-only.
- `required_gate_checks`: complete canonical set of Capsule checks required as release evidence. Local overrides may add checks but must not omit canonical required checks.
- `security_gate_remote_path_template`: canonical non-secret gate evidence path.
- `agent_token_path`: checked by metadata only; value is never read.
- `audit_path`: Agent audit JSONL metadata path.
- `agent_service_name`: default `kx-agent`.
- `expected_agent_user`: default `kx-agent`.
- `policy_files`: local Capsule Manager policy/code declarations inspected by S03.

S09 validates the Agent service name, port and configured remote paths before generating its fixed read-only probe. Paths are shell-quoted before the probe is sent to the privileged `bash -s` audit channel.

For release, an aggregate Capsule `PASS`/`WARN` is accepted only when the complete required check set is present. A missing required check, required `SKIPPED`, blocking `UNKNOWN`, or `FAIL_BLOCKING` makes the evidence non-passing.

### `external`

Defines hostname, TLS/HTTP endpoints and forbidden public ports. External probing requires `execution.allow_network=true`.

### `release.attestations`

Human recovery assertions required by S14, including fresh VPS, no old-disk clone, secret rotation, clean Git source, cloud-firewall verification and old-VPS retirement/isolation.

S14 independently verifies that all required levels from the `release` campaign are present and have release-acceptable verdicts before issuing its final PASS.

## Local config must not contain

- SSH private keys;
- passwords;
- `DJANGO_SECRET_KEY`;
- database URLs;
- API tokens;
- Agent bearer token values;
- signing private keys.

Only paths, identities, hostnames, fingerprints and non-secret policy metadata belong in SecurityDiag config.

As a defensive second layer, the persisted `.securitydiag/runs/<run-id>/effective_config.json` is recursively redacted before writing. This does not make secret-bearing SecurityDiag configuration supported; it only reduces accidental evidence leakage.
