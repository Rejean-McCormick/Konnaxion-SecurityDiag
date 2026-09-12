from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]+={0,2}$")
DEFAULT_ADMIN_USER = "kx-admin"
DEFAULT_EXPECTED_FINGERPRINT = "SHA256:1atsJGWjV8lYPXNsWNQBYXbDuKCEl95E02xPJjQk91g"
DROPIN_PATH = "/etc/ssh/sshd_config.d/99-konnaxion-hardening.conf"
ROLLBACK_DELAY_SECONDS = 90


class HardeningError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemoteSpec:
    host: str
    user: str
    port: int
    identity_file: Path
    strict_host_key_checking: str = "yes"
    known_hosts_file: str | None = None
    connect_timeout_seconds: int = 10


@dataclass(frozen=True)
class CommandResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HardeningError(f"Config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise HardeningError(f"Invalid JSON in {path}: {exc}") from exc


def save_json_with_backup(path: Path, data: dict) -> Path:
    backup = path.with_name(f"{path.name}.bak-{utc_stamp()}")
    if path.exists():
        shutil.copy2(path, backup)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return backup


def repo_root_from_script(script_path: Path) -> Path:
    # tools/ssh_hardening_core.py -> SecurityDiag root
    return script_path.resolve().parent.parent


def remote_spec_from_config(cfg: dict) -> RemoteSpec:
    remote = cfg.get("remote") or {}
    host = str(remote.get("host", "")).strip()
    user = str(remote.get("user", "")).strip()
    identity = str(remote.get("identity_file", "")).strip()
    if not host:
        raise HardeningError("remote.host is missing in securitydiag.config.local.json")
    if not user:
        raise HardeningError("remote.user is missing in securitydiag.config.local.json")
    if not identity:
        raise HardeningError("remote.identity_file is missing in securitydiag.config.local.json")
    identity_file = Path(os.path.expandvars(identity)).expanduser()
    if not identity_file.exists():
        raise HardeningError(f"SSH identity file not found: {identity_file}")
    return RemoteSpec(
        host=host,
        user=user,
        port=int(remote.get("port", 22)),
        identity_file=identity_file,
        strict_host_key_checking=str(remote.get("strict_host_key_checking", "yes")),
        known_hosts_file=(str(remote.get("known_hosts_file")).strip() if remote.get("known_hosts_file") else None),
        connect_timeout_seconds=int(remote.get("connect_timeout_seconds", 10)),
    )


def require_local_tools() -> tuple[str, str]:
    ssh = shutil.which("ssh")
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh:
        raise HardeningError("OpenSSH client 'ssh' was not found in PATH.")
    if not ssh_keygen:
        raise HardeningError("OpenSSH tool 'ssh-keygen' was not found in PATH.")
    return ssh, ssh_keygen


def _run(argv: list[str], *, input_bytes: bytes | None = None, timeout: int = 60) -> CommandResult:
    try:
        cp = subprocess.run(
            argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            shell=False,
        )
        return CommandResult(
            cp.returncode,
            cp.stdout.decode("utf-8", "replace"),
            cp.stderr.decode("utf-8", "replace"),
            False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CommandResult(None, out, err, True)


def ssh_argv(spec: RemoteSpec, user: str | None = None) -> list[str]:
    ssh, _ = require_local_tools()
    argv = [
        ssh,
        "-T",
        "-p",
        str(spec.port),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={spec.connect_timeout_seconds}",
        "-o",
        f"StrictHostKeyChecking={spec.strict_host_key_checking}",
        "-i",
        str(spec.identity_file),
    ]
    if spec.known_hosts_file:
        argv += ["-o", f"UserKnownHostsFile={spec.known_hosts_file}"]
    argv.append(f"{user or spec.user}@{spec.host}")
    return argv


def run_remote_script(
    spec: RemoteSpec,
    script: str,
    *,
    user: str | None = None,
    privileged: bool = False,
    timeout: int = 90,
) -> CommandResult:
    effective_user = user or spec.user
    remote_cmd = "bash -s" if effective_user == "root" or not privileged else "sudo -n bash -s"
    argv = ssh_argv(spec, effective_user) + [remote_cmd]
    payload = script.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    return _run(argv, input_bytes=payload, timeout=timeout)


def run_remote_command(spec: RemoteSpec, command: str, *, user: str | None = None, timeout: int = 30) -> CommandResult:
    return _run(ssh_argv(spec, user) + [command], timeout=timeout)


def public_key_and_fingerprint(identity_file: Path) -> tuple[str, str]:
    _, ssh_keygen = require_local_tools()
    pub_path = Path(str(identity_file) + ".pub")
    temp_path: Path | None = None
    try:
        if pub_path.exists():
            public_line = pub_path.read_text(encoding="utf-8").strip().splitlines()[0].strip()
            fp_source = pub_path
        else:
            derived = _run([ssh_keygen, "-y", "-f", str(identity_file)], timeout=15)
            if derived.exit_code != 0 or not derived.stdout.strip():
                raise HardeningError(f"Could not derive public key from {identity_file}: {derived.stderr.strip()}")
            public_line = derived.stdout.strip().splitlines()[0].strip()
            fd, name = tempfile.mkstemp(prefix="securitydiag-pubkey-", suffix=".pub")
            os.close(fd)
            temp_path = Path(name)
            temp_path.write_text(public_line + "\n", encoding="utf-8")
            fp_source = temp_path
        fp = _run([ssh_keygen, "-lf", str(fp_source), "-E", "sha256"], timeout=15)
        if fp.exit_code != 0:
            raise HardeningError(f"Could not fingerprint public key: {fp.stderr.strip()}")
        fields = fp.stdout.strip().split()
        fingerprint = next((x for x in fields if x.startswith("SHA256:")), "")
        if not fingerprint:
            raise HardeningError("ssh-keygen output did not contain a SHA256 fingerprint.")
        return public_line, fingerprint
    finally:
        if temp_path:
            try:
                temp_path.unlink()
            except OSError:
                pass


def validate_admin_user(username: str) -> str:
    value = username.strip()
    if not USERNAME_RE.fullmatch(value):
        raise HardeningError("Admin username must match ^[a-z_][a-z0-9_-]{0,31}$")
    if value in {"root", "kx-agent"}:
        raise HardeningError(f"Refusing reserved/unsafe admin username: {value}")
    return value


def validate_expected_fingerprint(value: str) -> str:
    value = value.strip()
    if not FINGERPRINT_RE.fullmatch(value):
        raise HardeningError("Expected fingerprint must be a SHA256:... fingerprint.")
    return value


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def preflight(spec: RemoteSpec, expected_fingerprint: str, log: Callable[[str], None]) -> tuple[str, str]:
    public_key, actual_fp = public_key_and_fingerprint(spec.identity_file)
    log(f"Local SSH fingerprint: {actual_fp}")
    if actual_fp != expected_fingerprint:
        raise HardeningError(
            f"Local SSH key fingerprint mismatch. Expected {expected_fingerprint}, got {actual_fp}."
        )
    probe = run_remote_script(
        spec,
        """
set -eu
printf '__READY__ user=%s\\n' "$(id -un)"
command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ] || [ -x /sbin/sshd ]
printf '__SUDO__\\n'
if [ "$(id -u)" -eq 0 ]; then echo root; elif sudo -n true 2>/dev/null; then echo noninteractive; else echo unavailable; fi
""",
        timeout=30,
    )
    if probe.exit_code != 0 or "__READY__" not in probe.stdout:
        raise HardeningError(f"SSH preflight failed for {spec.user}@{spec.host}: {probe.stderr.strip() or probe.stdout.strip()}")
    if spec.user != "root" and "noninteractive" not in probe.stdout:
        raise HardeningError("Current remote user is not root and does not have working sudo -n.")
    log(probe.stdout.strip())
    return public_key, actual_fp


def bootstrap_admin(
    spec: RemoteSpec,
    admin_user: str,
    public_key: str,
    expected_fingerprint: str,
    log: Callable[[str], None],
) -> None:
    user = validate_admin_user(admin_user)
    script = f"""
set -eu
USER_NAME={shell_single_quote(user)}
PUBKEY={shell_single_quote(public_key)}
if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$USER_NAME"
fi
if getent group sudo >/dev/null 2>&1; then
  usermod -aG sudo "$USER_NAME"
fi
passwd -l "$USER_NAME" >/dev/null 2>&1 || true
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
[ -n "$HOME_DIR" ]
install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR/.ssh"
touch "$HOME_DIR/.ssh/authorized_keys"
chown "$USER_NAME:$USER_NAME" "$HOME_DIR/.ssh/authorized_keys"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"
grep -qxF "$PUBKEY" "$HOME_DIR/.ssh/authorized_keys" || printf '%s\\n' "$PUBKEY" >> "$HOME_DIR/.ssh/authorized_keys"
chown "$USER_NAME:$USER_NAME" "$HOME_DIR/.ssh/authorized_keys"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"
SUDOERS="/etc/sudoers.d/90-konnaxion-$USER_NAME"
printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\\n' "$USER_NAME" > "$SUDOERS"
chmod 440 "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null
printf '__BOOTSTRAP_OK__\\n'
"""
    result = run_remote_script(spec, script, privileged=(spec.user != "root"), timeout=60)
    if result.exit_code != 0 or "__BOOTSTRAP_OK__" not in result.stdout:
        raise HardeningError(f"Could not bootstrap {user}: {result.stderr.strip() or result.stdout.strip()}")
    log(f"Created/validated privileged account {user} and installed the existing SSH public key.")

    test = run_remote_command(
        spec,
        "printf '__LOGIN_OK__\\n'; sudo -n true; ssh-keygen -lf \"$HOME/.ssh/authorized_keys\" -E sha256 2>/dev/null | awk '{print $2}'",
        user=user,
        timeout=30,
    )
    if test.exit_code != 0 or "__LOGIN_OK__" not in test.stdout:
        raise HardeningError(f"Fresh SSH login as {user} or sudo -n failed: {test.stderr.strip() or test.stdout.strip()}")
    fingerprints = [line.strip() for line in test.stdout.splitlines() if line.strip().startswith("SHA256:")]
    log(f"{user} authorized-key fingerprints: {', '.join(fingerprints) or 'none'}")
    if fingerprints != [expected_fingerprint]:
        raise HardeningError(
            f"Refusing SSH lockdown: {user} authorized_keys is not exactly the expected key. Observed: {fingerprints}"
        )


def hardening_dropin(admin_user: str) -> str:
    user = validate_admin_user(admin_user)
    return "\n".join(
        [
            "# Managed by SecurityDiag SSH Hardening Assistant.",
            "# Review before changing; this file intentionally restricts interactive SSH.",
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PubkeyAuthentication yes",
            f"AllowUsers {user}",
            "X11Forwarding no",
            "AllowTcpForwarding no",
            "ClientAliveInterval 300",
            "ClientAliveCountMax 2",
            "MaxAuthTries 3",
            "",
        ]
    )


def apply_hardening_with_rollback(
    spec: RemoteSpec,
    admin_user: str,
    log: Callable[[str], None],
    rollback_delay_seconds: int = ROLLBACK_DELAY_SECONDS,
) -> str:
    dropin = hardening_dropin(admin_user)
    stamp = utc_stamp()
    backup_dir = f"/root/.securitydiag-ssh-backups/{stamp}"
    rollback_script = "/root/.securitydiag-ssh-hardening-rollback.sh"
    rollback_pid = "/root/.securitydiag-ssh-hardening-rollback.pid"
    rollback_log = "/root/.securitydiag-ssh-hardening-rollback.log"
    script = f"""
set -eu
DROP={shell_single_quote(DROPIN_PATH)}
BACKDIR={shell_single_quote(backup_dir)}
ROLLBACK={shell_single_quote(rollback_script)}
PIDFILE={shell_single_quote(rollback_pid)}
ROLLLOG={shell_single_quote(rollback_log)}
mkdir -p "$BACKDIR"
if [ -f "$DROP" ]; then
  cp -a "$DROP" "$BACKDIR/original.conf"
  printf 'present\\n' > "$BACKDIR/state"
else
  printf 'absent\\n' > "$BACKDIR/state"
fi
cat > "$ROLLBACK" <<'EOS'
#!/bin/sh
set -eu
DROP={DROPIN_PATH}
BACKDIR={backup_dir}
STATE="$(cat "$BACKDIR/state" 2>/dev/null || echo absent)"
if [ "$STATE" = present ] && [ -f "$BACKDIR/original.conf" ]; then
  cp -af "$BACKDIR/original.conf" "$DROP"
else
  rm -f "$DROP"
fi
SSHD=""
for x in /usr/sbin/sshd /sbin/sshd "$(command -v sshd 2>/dev/null)"; do
  if [ -n "$x" ] && [ -x "$x" ]; then SSHD="$x"; break; fi
done
[ -n "$SSHD" ]
"$SSHD" -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd
EOS
chmod 700 "$ROLLBACK"
nohup sh -c "sleep {int(rollback_delay_seconds)}; '$ROLLBACK'" > "$ROLLLOG" 2>&1 < /dev/null &
printf '%s\\n' "$!" > "$PIDFILE"
cat > "$DROP" <<'EOF'
{dropin.rstrip()}
EOF
chmod 644 "$DROP"
SSHD=""
for x in /usr/sbin/sshd /sbin/sshd "$(command -v sshd 2>/dev/null)"; do
  if [ -n "$x" ] && [ -x "$x" ]; then SSHD="$x"; break; fi
done
[ -n "$SSHD" ]
restore_now() {{
  "$ROLLBACK" || true
}}
if ! "$SSHD" -t; then
  restore_now
  exit 42
fi
if ! (systemctl reload ssh 2>/dev/null || systemctl reload sshd); then
  restore_now
  exit 43
fi
printf '__HARDENED__ backup=%s rollback_seconds=%s\\n' "$BACKDIR" {int(rollback_delay_seconds)}
"""
    result = run_remote_script(spec, script, privileged=(spec.user != "root"), timeout=60)
    if result.exit_code != 0 or "__HARDENED__" not in result.stdout:
        raise HardeningError(f"SSH hardening apply failed and immediate restore was attempted: {result.stderr.strip() or result.stdout.strip()}")
    log(result.stdout.strip())
    return backup_dir


def verify_hardened_login(spec: RemoteSpec, admin_user: str, log: Callable[[str], None]) -> None:
    command = (
        "printf '__POST_RELOAD_LOGIN_OK__\\n'; "
        "sudo -n true; "
        "SSHD=''; for x in /usr/sbin/sshd /sbin/sshd \"$(command -v sshd 2>/dev/null)\"; do "
        "if [ -n \"$x\" ] && [ -x \"$x\" ]; then SSHD=\"$x\"; break; fi; done; "
        "sudo -n \"$SSHD\" -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|allowusers|x11forwarding|allowtcpforwarding|maxauthtries) '"
    )
    result = run_remote_command(spec, command, user=admin_user, timeout=30)
    if result.exit_code != 0 or "__POST_RELOAD_LOGIN_OK__" not in result.stdout:
        raise HardeningError(f"Post-reload login as {admin_user} failed: {result.stderr.strip() or result.stdout.strip()}")
    expected = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no",
        "pubkeyauthentication": "yes",
        "allowusers": admin_user,
        "x11forwarding": "no",
        "allowtcpforwarding": "no",
        "maxauthtries": "3",
    }
    effective: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0] in expected:
            effective[parts[0]] = parts[1]
    mismatches = {k: (effective.get(k), v) for k, v in expected.items() if effective.get(k) != v}
    if mismatches:
        raise HardeningError(f"Post-reload sshd effective config mismatch: {mismatches}")
    log("Fresh post-reload SSH login and effective sshd policy both passed.")


def cancel_rollback(spec: RemoteSpec, admin_user: str, log: Callable[[str], None]) -> None:
    script = """
set -eu
PIDFILE=/root/.securitydiag-ssh-hardening-rollback.pid
ROLLBACK=/root/.securitydiag-ssh-hardening-rollback.sh
if [ -f "$PIDFILE" ]; then
  PID="$(cat "$PIDFILE" 2>/dev/null || true)"
  if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; fi
  rm -f "$PIDFILE"
fi
rm -f "$ROLLBACK"
printf '__ROLLBACK_CANCELLED__\\n'
"""
    result = run_remote_script(spec, script, user=admin_user, privileged=True, timeout=30)
    if result.exit_code != 0 or "__ROLLBACK_CANCELLED__" not in result.stdout:
        raise HardeningError(
            "New SSH access works, but the safety rollback could not be cancelled. "
            "The server may automatically restore the previous SSH policy. "
            f"Details: {result.stderr.strip() or result.stdout.strip()}"
        )
    log("Safety rollback cancelled only after successful fresh SSH verification.")


def wait_for_rollback_recovery(
    spec: RemoteSpec,
    log: Callable[[str], None],
    *,
    timeout_seconds: int = 150,
    interval_seconds: int = 5,
) -> bool:
    log("Post-reload admin login failed. Automatic rollback remains armed; checking for root recovery.")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        probe = run_remote_command(spec, "printf '__ROOT_RECOVERED__\\n'", user=spec.user, timeout=15)
        if probe.exit_code == 0 and "__ROOT_RECOVERED__" in probe.stdout:
            log("Rollback recovery verified: original SSH access is reachable again.")
            return True
        time.sleep(interval_seconds)
    log("Could not verify rollback recovery automatically. Use the provider console before closing any existing SSH session.")
    return False


def update_securitydiag_config(config_path: Path, admin_user: str, fingerprint: str) -> Path:
    cfg = load_json(config_path)
    remote = cfg.setdefault("remote", {})
    remote["user"] = validate_admin_user(admin_user)
    remote["sudo_mode"] = "noninteractive"
    remote["allowed_sudo_users"] = [admin_user]
    remote["allowed_ssh_key_fingerprints"] = [validate_expected_fingerprint(fingerprint)]
    return save_json_with_backup(config_path, cfg)


def host_campaign_command(repo_root: Path) -> list[str]:
    python_exe = Path(os.sys.executable)
    if python_exe.name.lower() == "pythonw.exe":
        candidate = python_exe.with_name("python.exe")
        if candidate.exists():
            python_exe = candidate
    return [str(python_exe), str(repo_root / "securitydiag.py"), "run", "host"]


def run_host_campaign(repo_root: Path, timeout: int = 600) -> CommandResult:
    return _run(host_campaign_command(repo_root), timeout=timeout)
