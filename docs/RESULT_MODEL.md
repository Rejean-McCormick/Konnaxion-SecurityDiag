# Result model

Evidence is written under:

```text
<repo>/.securitydiag/runs/<run-id>/
  effective_config.json
  summary.json
  summary.txt
  summary.md
  levels/S00/result.json
  ...
  levels/S14/result.json
```

`<repo>/.securitydiag/latest/` contains convenience copies of the most recent executed campaign.

Exit codes:

| Code | Meaning |
|---:|---|
| 0 | `PASS` or `WARN` |
| 10 | security requirement `FAIL` |
| 20 | required evidence `BLOCKED` / incomplete |
| 30 | configuration, infrastructure, or SecurityDiag error |
| 64 | CLI usage error |

A `WARN` exit code is intentionally zero so CI can preserve non-blocking evidence, but release owners must disposition warnings before public launch.
