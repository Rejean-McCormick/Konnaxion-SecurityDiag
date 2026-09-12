SecurityDiag SSH Hardening Assistant - overlay-only
===================================================

Target root:
  C:\mycode\Konnaxion\SecurityDiag

Install:
  Extract this ZIP directly into the SecurityDiag root.
  Existing SecurityDiag files are not replaced by this overlay.

Run:
  Double-click RUN_SSH_HARDENING_ASSISTANT.bat

Recommended sequence in the GUI:
  1. Preflight only
  2. Apply safe hardening
  3. Run SecurityDiag Host

Default admin account:
  kx-admin

Expected verified key fingerprint:
  SHA256:1atsJGWjV8lYPXNsWNQBYXbDuKCEl95E02xPJjQk91g

The helper backs up securitydiag.config.local.json before updating SSH identity/allowlists.
It also creates a remote SSH config backup and arms an automatic rollback before disabling root/password SSH.
