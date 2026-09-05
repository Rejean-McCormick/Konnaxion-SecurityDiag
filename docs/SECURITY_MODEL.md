# SecurityDiag security model

## Separation of authority

```text
SecurityDiag
  read-only observation / qualification
        |
        | reads non-secret evidence + independently probes
        v
Capsule Manager
  orchestration / operator intent
        |
        v
Konnaxion Agent
  narrow local privileged enforcement
        |
        +-- Docker
        +-- firewall/network
        +-- host lifecycle operations
```

SecurityDiag is intentionally **not** given Docker-group membership, a Docker socket, arbitrary Agent commands or firewall mutation authority.

## Evidence contract

The Agent writes:

```text
/opt/konnaxion/instances/<INSTANCE_ID>/state/security-gate.json
```

The file contains status/check evidence and redacted runtime evidence only. Missing/invalid evidence is not success.

SecurityDiag corroborates that evidence by checking the host independently:

- Agent listener is loopback-only;
- Agent runs under the expected service account;
- token/audit files have restrictive modes;
- runtime network profile is explicit;
- `public_temporary` has expiration;
- Docker/container exposure complies with policy;
- public ports match the intended external surface.

## Trust rules

- Capsule signature verification must be cryptographic.
- Capsule checksums must match.
- Signed manifest image references are the runtime allowlist.
- Canonical service names do not authorize arbitrary images.
- Blocking `UNKNOWN` is equivalent to no proof and blocks release.
- An old compromised VPS is never promoted back to trusted baseline solely because current IOC scans are clean.
