# SecurityDiag release runbook

## 1. Local repository

```powershell
python .\securitydiag\securitydiag.py run repo
```

Resolve repository/application blockers before provisioning.

## 2. Fresh host baseline

Configure SSH metadata and run:

```powershell
python .\securitydiag\securitydiag.py run predeploy
```

Do not deploy onto an old compromised disk/snapshot.

## 3. Capsule Manager / Agent

Install the optimized Agent boundary:

- Agent service bound to loopback;
- dedicated `kx-agent` service identity;
- trusted capsule public key provisioned separately;
- bearer token provisioned separately;
- human users not casually added to Docker group;
- runtime/security policies present.

Deploy through Capsule Manager, not through ad-hoc arbitrary Docker commands.

## 4. Host qualification

Once the intended instance exists:

```powershell
python .\securitydiag\securitydiag.py run host
```

S09 must observe a usable `security-gate.json` and independently validate the Agent/runtime boundary.

## 5. External surface

```powershell
python .\securitydiag\securitydiag.py run external
```

Only intended public HTTP/HTTPS exposure may remain.

## 6. Backup/restore

Perform a real isolated restore and record the attestation. Do not infer restore success from the existence of backup files.

## 7. Final gate

```powershell
python .\securitydiag\securitydiag.py run release
```

Preserve the resulting `.securitydiag/runs/<RUN>` with the Git tag it qualifies.

No release when a required technical level is `FAIL`/`BLOCKED`, when required Capsule evidence is `UNKNOWN`/`SKIPPED`/`FAIL_BLOCKING`, or when recovery attestations are incomplete.
