# SecurityDiag configuration reference

SecurityDiag loads `securitydiag.config.json` and overlays `securitydiag.config.local.json` when present.

## Important sections

### `execution`

- `allow_network`: permits declared SSH/external probes.
- `allow_declared_audits`: permits only explicitly configured package-manager vulnerability audits.

### `remote`

- `enabled`: enables remote VPS evidence.
- `host`, `port`: SSH target.
- `user`: recommended human audit/ops account; default is `ops`.
- `identity_file`: local private-key path; never embed key material.
- `sudo_mode`: `disabled` or `noninteractive`. Noninteractive means `sudo -n`.
- `allowed_sudo_users`: expected human sudo identities.
- `allowed_ssh_key_fingerprints`: expected authorized-key fingerprints.
- `docker.strict_container_allowlist`: fail unknown runtime containers/images when evidence is available.

### `capsule_manager`

- `enabled`: enables Capsule-aware policy/evidence correlation.
- `repo_root`: explicit path or `auto` for sibling `Konnaxion_Capsule_Manager`.
- `instance_id`: required for remote Capsule evidence.
- `agent_port`: expected local Agent port, default `8765`.
- `require_for_release`: S14 requires Capsule evidence.
- `unknown_is_blocking`: recommended `true`.
- `require_local_agent_bind`: recommended `true`.
- `security_gate_remote_path_template`: canonical non-secret gate evidence path.
- `agent_token_path`: checked by metadata only; value is never read.
- `audit_path`: Agent audit JSONL metadata path.
- `agent_service_name`: default `kx-agent`.
- `expected_agent_user`: default `kx-agent`.
- `policy_files`: local Capsule Manager policy/code declarations inspected by S03.

### `external`

Defines hostname, TLS/HTTP endpoints and forbidden public ports. External probing requires `execution.allow_network=true`.

### `release.attestations`

Human recovery assertions required by S14, including fresh VPS, no old-disk clone, secret rotation, clean Git source, cloud-firewall verification and old-VPS retirement/isolation.

## Local config must not contain

- SSH private keys;
- passwords;
- `DJANGO_SECRET_KEY`;
- database URLs;
- API tokens;
- Agent bearer token values;
- signing private keys.

Only paths, identities, hostnames, fingerprints and non-secret policy metadata belong in SecurityDiag config.
