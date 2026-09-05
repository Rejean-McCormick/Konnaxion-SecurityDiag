# SecurityDiag level contract

Each level is a focused, read-only security diagnostic declared in `securitydiag_manifest.json` and implemented as:

```python
def run(cfg, report):
    ...
```

A level must not remediate the target. It may read repository files, execute bounded local inspection commands, use configured SSH to collect read-only VPS evidence, or perform configured external network probes.

Verdicts:

| Verdict | Meaning |
|---|---|
| PASS | Required condition was checked and satisfied. |
| WARN | Risk or manual-review item exists but evidence is usable. |
| FAIL | A security requirement was checked and failed. |
| SKIP | Intentionally not executed. |
| BLOCKED | A prerequisite or permission prevented required evidence. |
| PARTIAL | Evidence is incomplete. |
| ERROR | SecurityDiag implementation failed. |
| INFRA_ERROR | Worker, timeout, SSH, or execution infrastructure failed. |
| CONFIG_ERROR | Configuration is invalid. |

Rules:

- never copy secret values into findings;
- never make a required `SKIP` look green;
- never convert an SSH/timeout failure into `PASS`;
- known compromise indicators are release blockers;
- public internal-service ports are release blockers;
- human recovery attestations are explicit rather than guessed.
