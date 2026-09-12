# SecurityDiag release profiles

SecurityDiag distinguishes normal production validation from incident-recovery validation.

## `standard_release` (default)

Used when validating a normal production release. S14 gates on the required technical SecurityDiag levels, Capsule Manager release evidence, external surface, and backup/restore evidence. The six historical incident-recovery attestations remain visible but do not block release.

No configuration change is required. If `release.profile` is absent, SecurityDiag uses `standard_release`.

## `incident_recovery`

Use this profile after a suspected or confirmed compromise when the historical rebuild conditions must also be proven. Add this to `securitydiag.config.local.json`:

```json
{
  "release": {
    "profile": "incident_recovery"
  }
}
```

When `release.require_attestations` is true, the existing six human attestations are blocking only under this profile.

An unknown profile fails closed with `CONFIG_ERROR`.
