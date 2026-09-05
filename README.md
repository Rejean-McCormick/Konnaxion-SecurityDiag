# Konnaxion SecurityDiag

**Version:** 1.1.0  
**Mode:** copy-in, read-only security qualification frame  
**Runtime:** Python 3.10+ standard library only  
**Primary target:** Konnaxion repository + fresh Linux production VPS  
**Integration:** Capsule Manager / Konnaxion Agent evidence-aware

SecurityDiag applies the LevelUpDiag operating model to deployment security. It produces structured, repeatable evidence across the repository, application production configuration, Capsule Manager policies, remote VPS, Docker runtime, Konnaxion Agent boundary, incident-recovery indicators, public TLS/ports, backups and final release readiness.

SecurityDiag is deliberately a **diagnostic and qualification layer**. It does not replace Capsule Manager and it never becomes an alternate privileged orchestrator.

```text
SecurityDiag        = independent qualification + correlation
Capsule Manager     = orchestration + operator workflow
Konnaxion Agent     = narrow privileged enforcement boundary
security-gate.json  = non-secret evidence contract between them
```

SecurityDiag does not rewrite SSH configuration, enable UFW, delete containers, rotate secrets, remove malware, restore databases, start arbitrary containers, or modify production state.

## Why this pack exists

The Konnaxion incident-recovery record describes a previous compromise that reached the deployment account, involved malicious Docker containers and cron persistence, attempted privileged persistence, created `/tmp/sshd`, and exposed credentials.

Therefore the release model assumes:

```text
old compromised VPS != trusted production baseline
```

The intended path is a **fresh VPS**, clean Git deployment, rotated secrets, verified DB/media restoration, locked ingress and repeatable S00-S14 qualification.

## Install

Recommended repository layout:

```text
Konnaxion/
├── backend/
├── frontend/
├── ...
└── securitydiag/
```

Capsule Manager may remain a sibling repository:

```text
C:\mycode\Konnaxion\
├── Konnaxion\
│   └── securitydiag\
└── Konnaxion_Capsule_Manager\
```

Add the entries from `INSTALL_GITIGNORE.txt` to the repository `.gitignore`.

## Quick start — local repository only

```powershell
cd C:\mycode\Konnaxion\Konnaxion

python .\securitydiag\securitydiag.py doctor
python .\securitydiag\securitydiag.py list
python .\securitydiag\securitydiag.py run repo
```

Evidence is written under:

```text
.securitydiag/
├── runs/<run-id>/
└── latest/
```

## Capsule Manager integration

Copy:

```text
securitydiag/securitydiag.config.local.example.json
→ securitydiag/securitydiag.config.local.json
```

Enable the bridge only when Capsule Manager is present:

```json
{
  "capsule_manager": {
    "enabled": true,
    "repo_root": "auto",
    "instance_id": "konnaxion-production",
    "require_for_release": true,
    "unknown_is_blocking": true
  }
}
```

`repo_root: "auto"` looks for the sibling `Konnaxion_Capsule_Manager` repository.

SecurityDiag validates the declared Capsule Manager/Agent policy locally and, on the host, reads the canonical evidence file:

```text
/opt/konnaxion/instances/<INSTANCE_ID>/state/security-gate.json
```

It also independently checks the Agent listener, service user, token/audit permissions, Docker exposure and network profile. SecurityDiag does **not** call arbitrary Agent operations and does not receive Docker or firewall privileges.

### Evidence rule

For release:

```text
PASS       = usable evidence
WARN       = review/disposition required
FAIL_BLOCKING = release blocked
UNKNOWN    = release blocked
SKIPPED    = release blocked for required checks
```

A missing `security-gate.json` is not silently converted to PASS.

## Fresh VPS connection

Set only non-secret metadata:

```json
{
  "remote": {
    "enabled": true,
    "host": "NEW_SERVER_IP_OR_DNS",
    "user": "ops",
    "identity_file": "C:/Users/YOU/.ssh/konnaxion-new-vps-2026",
    "sudo_mode": "noninteractive"
  }
}
```

`ops` is the recommended human administrative identity. Normal human users should not be added to the Docker group merely for SecurityDiag.

Network execution remains opt-in:

```json
"execution": {
  "allow_network": true
}
```

SSH host-key checking defaults to strict verification. `sudo_mode: "noninteractive"` uses `sudo -n`; it never asks SecurityDiag to collect or store a sudo password.

## Campaigns

| Campaign | Purpose |
|---|---|
| `repo` | repository secrets, supply chain, Capsule policy and production config |
| `predeploy` | repo + clean VPS baseline before Konnaxion exposure |
| `host` | SSH, firewall, Docker, Agent, runtime, permissions and IOC |
| `incident` | focused compromise/persistence evidence |
| `external` | DNS, TLS, redirects, headers and public port exposure |
| `release` | complete S00-S14 qualification |

Recommended order:

```text
repo
→ predeploy
→ Capsule Manager / Agent deployment
→ host
→ external
→ backup + isolated restore drill
→ release
```

## S00-S14

| ID | Level |
|---|---|
| S00 | Diagnostic Integrity |
| S01 | Target & Security Context |
| S02 | Repository Secrets & Artifact Hygiene |
| S03 | Supply Chain, Capsule Integrity & Automation |
| S04 | Application Production Security |
| S05 | Clean Host & OS Baseline |
| S06 | SSH Hardening |
| S07 | Firewall & Listening Ports |
| S08 | Docker & Capsule Runtime Policy |
| S09 | Runtime Isolation, Agent & Security Gate |
| S10 | Secrets & Filesystem Permissions |
| S11 | Persistence & Incident IOC Scan |
| S12 | External TLS & Attack Surface |
| S13 | Backup & Recovery Evidence |
| S14 | Security Release Gate |

See `docs/S00_S14_MATRIX.md`.

## Capsule/Agent release invariants

SecurityDiag v1.1 expects the optimized Capsule Manager path to enforce or evidence:

- cryptographic capsule signature verification against a trusted public key;
- capsule checksum verification;
- signed-manifest image allowlist;
- Agent loopback-only bind;
- bearer-token authentication;
- Agent service identity `kx-agent`;
- no arbitrary shell / Docker / firewall primitive;
- no privileged containers;
- no host network, host PID or host IPC;
- no Docker socket mount inside application containers;
- no unsafe host bind mount;
- explicit network profile;
- expiration for `public_temporary`;
- non-secret append-only audit/evidence;
- `UNKNOWN` on a blocking Security Gate check blocks release.

## Incident indicators shipped by default

```text
negoroo/amco
amco_
supportxmr
xmrig
/tmp/sshd
pakchoi
```

IOC absence does **not** make an old compromised VPS trustworthy.

## Backup/restore release evidence

Copy:

```text
securitydiag/attestations/restore-drill.example.json
→ securitydiag/attestations/restore-drill.local.json
```

Do not mark it successful until a real isolated restore has been performed and Konnaxion has booted against the restored database.

S13 checks backup metadata only; it never opens database dumps.

## Safety properties

- no remediation;
- no secret values in normal evidence;
- bounded/redacted stdout/stderr;
- no shell invocation for local commands;
- fixed read-oriented remote probes;
- no direct Docker control;
- no direct Agent mutation API;
- strict SSH host-key checking by default;
- external probes limited to configured ports/URLs;
- target Git tracked state checked before/after campaigns;
- Capsule Manager evidence is corroborating evidence, not blind trust.

## Useful commands

```powershell
python .\securitydiag\securitydiag.py show-config
python .\securitydiag\securitydiag.py run S03
python .\securitydiag\securitydiag.py run S09
python .\securitydiag\securitydiag.py run incident
python .\securitydiag\securitydiag.py run release
python .\securitydiag\securitydiag.py verify-run .\.securitydiag\runs\<RUN>\summary.json
python -m unittest discover .\securitydiag\tests -v
```

## Release policy

For the public Konnaxion deployment:

```text
SecurityDiag S00-S14
        +
Capsule Manager Security Gate
        +
external attack-surface evidence
        +
backup/restore evidence
        +
incident-recovery attestations
        =
SECURITY QUALIFIED FOR RELEASE
```

`FAIL`, `BLOCKED`, required `SKIPPED`, or blocking `UNKNOWN` means **no release**.
#   K o n n a x i o n - S e c u r i t y D i a g  
 