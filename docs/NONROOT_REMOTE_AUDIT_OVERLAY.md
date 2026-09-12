# SecurityDiag Non-Root Remote Audit Overlay v1.0.0

This overlay corrects remote host evidence collection after moving SecurityDiag from direct `root` SSH access to a hardened non-root administrative account such as `kx-admin`.

## Changes

- **S06 SSH Hardening**: effective `sshd -T` collection runs through the existing reviewed privileged path (`sudo -n bash -s`) when the configured remote user is non-root.
- **S07 Firewall & Listening Ports**: remote collection runs privileged and discovers UFW using `/usr/sbin/ufw`, `/sbin/ufw`, or `PATH`; it no longer assumes UFW is absent merely because `/usr/sbin` is not in a non-root PATH.
- **S10 Secrets & Filesystem Permissions**:
  - SSH home/key evidence stays non-privileged so `$HOME` is the configured SSH user's home.
  - Production `secret_paths` are checked separately through the privileged path.
  - Only file metadata (`stat`) is collected; secret contents are never read.

No Konnaxion source or VPS configuration is modified by this overlay.
