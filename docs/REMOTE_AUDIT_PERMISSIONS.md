# Remote audit permissions

Most S05-S11 checks use ordinary read access. Docker inspection, root cron and some firewall evidence may require privilege.

SecurityDiag does **not** prompt for sudo passwords over SSH.

Options:

1. Run the pack locally on the VPS from an administrative shell.
2. Use a dedicated `ops` account with a carefully reviewed audit privilege model. The example local config uses `ops` for SecurityDiag while application files may remain owned by a non-sudo `deploy` account.
3. Set `remote.sudo_mode` to `noninteractive` only when `sudo -n` is intentionally available.

Do not solve audit convenience by putting the routine `deploy` account in the Docker group. Docker documents that this grants root-level privileges.

If privileged evidence is unavailable, SecurityDiag returns `BLOCKED`; it does not invent a pass.
