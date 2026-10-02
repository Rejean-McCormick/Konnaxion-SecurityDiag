# SecurityDiag 1.3.0 — Web Trust hardening

- S04 now checks Konnaxion web authorization and untrusted-content boundaries.
- Adds correlated ClickFix-delivery and stored-active-content chain detection.
- Requires fail-closed production registration, DRF throttling, reviewed external URLs, upload containment, CSP, WebSocket Origin checks and fixed internal proxy origins.
- S14 treats required-level WARN as release-blocking.
- Incident-recovery attestations can no longer be disabled to obtain a release PASS.
