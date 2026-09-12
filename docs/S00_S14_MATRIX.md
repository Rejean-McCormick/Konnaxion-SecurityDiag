# SecurityDiag S00-S14 matrix

| ID | Gate | Main evidence |
|---|---|---|
| S00 | Diagnostic Integrity | Python, modules, schemas, read-only contract |
| S01 | Target & Security Context | repo, Git state, phase, network policy |
| S02 | Repository Secrets & Artifact Hygiene | tracked/untracked secret patterns, keys, env files, archives |
| S03 | Supply Chain, Capsule Integrity & Automation | lockfiles, CI pinning, image pinning, Capsule Manager security-policy alignment, declared audits |
| S04 | Application Production Security + common-auth contract | Django production settings, compose exposure, optional `check --deploy` |
| S05 | Clean Host & OS Baseline | host identity, OS/kernel, NTP, pending updates, Fail2Ban/unattended-upgrades |
| S06 | SSH Hardening | root/password/KBI/public-key/forwarding policy |
| S07 | Firewall & Listening Ports | cloud/UFW posture, default deny, public bind detection |
| S08 | Docker & Capsule Runtime Policy | human Docker-group membership, socket, privileged/host namespaces, unsafe mounts, ports, signed-manifest image policy |
| S09 | Runtime Isolation, Agent & Security Gate | Agent loopback bind/user/token/audit, network profile, Capsule Security Gate evidence, runtime IOC |
| S10 | Secrets & Filesystem Permissions | SSH keys, authorized-key fingerprints, production secret modes, sudo/sudoers review |
| S11 | Persistence & Incident IOC Scan | users, cron, systemd, `/tmp`, `/dev/shm`, known IOC |
| S12 | External TLS & Attack Surface | DNS, TLS, HTTP→HTTPS, headers, forbidden public ports |
| S13 | Backup & Recovery Evidence | backup freshness, offsite evidence, isolated restore attestation |
| S14 | Security Release Gate | S00-S13 correlation + Capsule Security Gate + recovery attestations |

## Cross-layer rule

SecurityDiag and Capsule Manager do not duplicate authority:

```text
SecurityDiag    -> observe, diagnose, correlate, qualify
Capsule Manager -> orchestrate approved lifecycle operations
Konnaxion Agent -> perform narrow privileged operations
```

The Agent exports a non-secret `security-gate.json`; SecurityDiag reads it and independently corroborates host/runtime exposure.

For required Capsule checks, `UNKNOWN`, `FAIL_BLOCKING`, and `SKIPPED` are release-blocking.
