# SecurityDiag SSH Hardening Assistant

`RUN_SSH_HARDENING_ASSISTANT.bat` launches a Windows/Tkinter helper for the S06/S10 remediation sequence.

## Safety model

The helper deliberately does **not** disable root login first. It performs these stages:

1. Reads `securitydiag.config.local.json` and uses the existing OpenSSH host, port and private-key path.
2. Verifies the local SHA256 public-key fingerprint against the expected fingerprint shown in the UI.
3. Proves the current SSH path works.
4. Creates or validates `kx-admin`, installs the same public key and creates a reviewed NOPASSWD sudo policy. This is required because current SecurityDiag privileged probes use `sudo -n bash -s`.
5. Proves a fresh `kx-admin` login and `sudo -n` **before** changing sshd policy.
6. Backs up any existing `99-konnaxion-hardening.conf` on the VPS.
7. Arms a remote automatic rollback process.
8. Installs the hardening drop-in, runs `sshd -t`, and reloads SSH.
9. Opens a fresh `kx-admin` connection and checks the effective sshd policy.
10. Cancels the rollback only after the fresh connection succeeds.
11. Updates only these local SecurityDiag fields, while backing up the JSON first:
    - `remote.user = "kx-admin"`
    - `remote.sudo_mode = "noninteractive"`
    - `remote.allowed_sudo_users = ["kx-admin"]`
    - `remote.allowed_ssh_key_fingerprints = [verified fingerprint]`

If the post-reload connection fails, the rollback remains armed and the helper attempts to verify that the previous root SSH path becomes reachable again.

## Expected fingerprint for this Konnaxion VPS

At packaging time the operator independently verified:

`SHA256:1atsJGWjV8lYPXNsWNQBYXbDuKCEl95E02xPJjQk91g`

The assistant pre-fills that value but still recomputes the fingerprint from the configured local key before making changes.

## Files and secrets

The private key is never read into SecurityDiag configuration and is never copied to the VPS. Only the public key is added to the new account. The helper writes timestamped backups of the local JSON and the prior remote sshd drop-in.

## After success

Use the **Run SecurityDiag Host** button. S06 should then see root/password/keyboard-interactive login disabled, public-key login enabled, `AllowUsers` restricted to the configured account, X11/TCP forwarding disabled, and `MaxAuthTries 3`. S10 should validate the configured fingerprint allowlist.
