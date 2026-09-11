# SecurityDiag 1.1.1 — server transport hotfix

- Fixed Windows -> SSH script transport: remote shell scripts are sent as UTF-8 bytes with LF-only newlines, preventing PowerShell/Windows CRLF translation from breaking `bash -s`.
- Added `ssh -T` for non-interactive diagnostics.
- Privileged diagnostics now run directly with `bash -s` when the configured remote user is `root`; `sudo -n` is only required for non-root users.
- Added regression tests for LF-only transport, root privileged execution, and no-TTY SSH.
- No remediation behavior was added; SecurityDiag remains read-only.
