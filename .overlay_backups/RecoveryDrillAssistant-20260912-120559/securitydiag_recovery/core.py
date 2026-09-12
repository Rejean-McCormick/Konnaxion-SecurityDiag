from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable

from securitydiag_core.config import load_config
from securitydiag_core.remote import RemoteBlocked, remote_ready, run_script, ssh_argv

Progress = Callable[[str], None]
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:@/+\-]+$")
SAFE_PROJECT = re.compile(r"^[A-Za-z0-9_.-]+$")
SAFE_REMOTE_PATH = re.compile(r"^/[A-Za-z0-9._/@%+=:,~\-]+(?:/[A-Za-z0-9._ @%+=:,~\-]+)*$")
ATTESTATION_KEYS = [
    "fresh_vps",
    "old_disk_not_cloned",
    "all_compromised_secrets_rotated",
    "clean_git_source_only",
    "cloud_firewall_verified",
    "old_vps_retired_or_isolated",
]


class RecoveryError(RuntimeError):
    pass


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _emit(progress: Progress | None, message: str) -> None:
    if progress:
        progress(message)


def _tool_root(path: Path | str) -> Path:
    return Path(path).resolve()


def effective_config(tool_root: Path | str) -> dict:
    return load_config(_tool_root(tool_root))


def _require_remote(cfg: dict) -> None:
    ok, msg = remote_ready(cfg)
    if not ok:
        raise RecoveryError(msg)
    if cfg.get("remote", {}).get("sudo_mode") != "noninteractive" and cfg.get("remote", {}).get("user") != "root":
        raise RecoveryError("Recovery operations require remote.sudo_mode=noninteractive for the non-root admin account.")


def _safe_project(cfg: dict) -> str:
    projects = cfg.get("remote", {}).get("docker", {}).get("allowed_compose_projects", [])
    if len(projects) != 1:
        raise RecoveryError("Recovery Assistant requires exactly one remote.docker.allowed_compose_projects entry.")
    project = str(projects[0]).strip()
    if not SAFE_PROJECT.fullmatch(project):
        raise RecoveryError("Configured compose project contains unsafe characters.")
    return project


def _safe_remote_path(value: str, label: str) -> str:
    value = str(value).strip()
    if not SAFE_REMOTE_PATH.fullmatch(value):
        raise RecoveryError(f"Unsafe {label}: {value!r}")
    return value


def _backup_root(cfg: dict) -> str:
    paths = cfg.get("remote", {}).get("backup_paths", [])
    if not paths:
        raise RecoveryError("remote.backup_paths is empty.")
    return _safe_remote_path(str(paths[0]), "backup path")


def _env_paths(cfg: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in cfg.get("remote", {}).get("secret_paths", []):
        p = _safe_remote_path(str(raw), "secret path")
        name = Path(p).name.lower()
        if name in {"django.env", "postgres.env", "redis.env"}:
            result[name] = p
    missing = [x for x in ("django.env", "postgres.env") if x not in result]
    if missing:
        raise RecoveryError(f"Missing required configured secret path(s): {', '.join(missing)}")
    return result


def _normalize_shell_script(script: str) -> str:
    """Normalize generated shell payloads to LF before sending them to Linux."""
    return script.replace("\r\n", "\n").replace("\r", "\n")


def _remote_result(cfg: dict, script: str, *, timeout: int = 90, privileged: bool = True) -> dict:
    script = _normalize_shell_script(script)
    try:
        result = run_script(cfg, script, privileged=privileged, timeout_seconds=timeout)
    except RemoteBlocked as exc:
        raise RecoveryError(str(exc)) from exc
    if result.get("timed_out"):
        raise RecoveryError(f"Remote operation timed out. stderr={result.get('stderr_tail','')[-2000:]}")
    if result.get("exit_code") != 0:
        raise RecoveryError(
            "Remote operation failed with exit code "
            f"{result.get('exit_code')}. stderr={result.get('stderr_tail','')[-4000:]}"
        )
    return result


def discover_runtime(cfg: dict, progress: Progress | None = None) -> dict[str, dict]:
    _require_remote(cfg)
    project = _safe_project(cfg)
    _emit(progress, f"Discovering running containers for compose project {project}...")
    q = shlex.quote(project)
    script = f"""set -euo pipefail
PROJECT={q}
docker ps --filter "label=com.docker.compose.project=$PROJECT" --format '{{{{.ID}}}}|{{{{.Names}}}}|{{{{.Label "com.docker.compose.service"}}}}|{{{{.Image}}}}' | while IFS='|' read -r cid name svc image_ref; do
  [ -n "$svc" ] || continue
  image_id=$(docker inspect -f '{{{{.Image}}}}' "$cid")
  printf '%s|%s|%s|%s\n' "$svc" "$name" "$image_ref" "$image_id"
done
"""
    r = _remote_result(cfg, script, timeout=60, privileged=True)
    discovered: dict[str, dict] = {}
    for line in r.get("stdout_tail", "").splitlines():
        parts = line.strip().split("|", 3)
        if len(parts) != 4:
            continue
        svc, name, image_ref, image_id = parts
        if not all(SAFE_NAME.fullmatch(v) for v in (svc, name, image_ref, image_id)):
            continue
        discovered[svc] = {
            "service": svc,
            "name": name,
            "image_ref": image_ref,
            "image_id": image_id,
        }

    # Recovery uses stable internal roles even when the deployed Compose service
    # names evolve. Konnaxion production currently uses ``django-api`` while
    # older Cookiecutter deployments used ``django``. Prefer the current label
    # and retain the legacy alias for backward compatibility.
    aliases = {
        "postgres": ("postgres",),
        "redis": ("redis",),
        "django": ("django-api", "django"),
    }
    services: dict[str, dict] = {}
    missing: list[str] = []
    for role, candidates in aliases.items():
        match = next((discovered[name] for name in candidates if name in discovered), None)
        if match is None:
            missing.append(role)
        else:
            services[role] = match

    if missing:
        found = ", ".join(sorted(discovered)) or "<none>"
        raise RecoveryError(
            f"Running production service role(s) not found: {', '.join(missing)}. "
            f"Discovered Compose services: {found}"
        )

    _emit(
        progress,
        "Resolved recovery service roles: "
        + ", ".join(f"{role}={services[role]['service']}" for role in ("postgres", "redis", "django")),
    )
    return services


def preflight(tool_root: Path | str, offsite_dir: Path | str | None = None, progress: Progress | None = None) -> dict:
    tool_root = _tool_root(tool_root)
    cfg = effective_config(tool_root)
    _require_remote(cfg)
    target = Path(cfg["_target_root"]).resolve()
    root = _backup_root(cfg)
    envs = _env_paths(cfg)
    services = discover_runtime(cfg, progress)

    if offsite_dir is not None:
        local = Path(offsite_dir).expanduser().resolve()
        for forbidden, label in ((target, "Konnaxion repository"), (tool_root, "SecurityDiag repository")):
            if local == forbidden or local.is_relative_to(forbidden):
                raise RecoveryError(f"Off-server backup destination must not be inside the {label}.")
        local.mkdir(parents=True, exist_ok=True)
        probe = local / ".recovery-assistant-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    else:
        local = None

    paths = " ".join(shlex.quote(x) for x in [root, *envs.values()])
    script = f"""set -euo pipefail
for p in {paths}; do
  if [ ! -e "$p" ]; then echo "MISSING|$p"; exit 21; fi
  stat -c 'PATH|%a|%U|%G|%s|%n' "$p"
done
docker version --format 'DOCKER|{{{{.Server.Version}}}}'
"""
    r = _remote_result(cfg, script, timeout=60, privileged=True)
    _emit(progress, "Preflight passed: SSH/sudo, backup path, env files and Docker runtime are available.")
    return {
        "target": str(target),
        "backup_root": root,
        "env_paths": envs,
        "services": services,
        "offsite_dir": str(local) if local else None,
        "remote_evidence": r.get("stdout_tail", ""),
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _privileged_remote_command(cfg: dict, command: str) -> list[str]:
    user = str(cfg.get("remote", {}).get("user", "")).strip()
    if user == "root":
        remote_cmd = command
    else:
        if cfg.get("remote", {}).get("sudo_mode") != "noninteractive":
            raise RecoveryError("Binary transfer requires remote.sudo_mode=noninteractive.")
        remote_cmd = f"sudo -n {command}"
    return ssh_argv(cfg) + [remote_cmd]


def _download_remote(cfg: dict, remote_path: str, local_path: Path) -> None:
    remote_path = _safe_remote_path(remote_path, "remote backup file")
    local_path.parent.mkdir(parents=True, exist_ok=True)
    argv = _privileged_remote_command(cfg, f"cat -- {shlex.quote(remote_path)}")
    with local_path.open("wb") as out:
        cp = subprocess.run(argv, stdout=out, stderr=subprocess.PIPE, timeout=1800, check=False)
    if cp.returncode != 0:
        local_path.unlink(missing_ok=True)
        raise RecoveryError(f"Downloading {remote_path} failed: {cp.stderr.decode('utf-8','replace')[-3000:]}")


def _upload_remote(cfg: dict, local_path: Path, remote_path: str) -> None:
    remote_path = _safe_remote_path(remote_path, "remote staging file")
    argv = _privileged_remote_command(cfg, f"tee {shlex.quote(remote_path)} >/dev/null")
    with local_path.open("rb") as inp:
        cp = subprocess.run(argv, stdin=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800, check=False)
    if cp.returncode != 0:
        raise RecoveryError(f"Uploading {local_path.name} failed: {cp.stderr.decode('utf-8','replace')[-3000:]}")


def _state_path(cfg: dict) -> Path:
    return Path(cfg["_control_root"]) / "recovery-assistant" / "latest-backup.json"


def save_state(cfg: dict, state: dict) -> Path:
    path = _state_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_state(tool_root: Path | str) -> dict:
    cfg = effective_config(tool_root)
    path = _state_path(cfg)
    if not path.exists():
        raise RecoveryError("No Recovery Assistant backup state exists yet. Create a backup first.")
    return json.loads(path.read_text(encoding="utf-8"))


def create_backup(tool_root: Path | str, offsite_dir: Path | str, progress: Progress | None = None) -> dict:
    tool_root = _tool_root(tool_root)
    cfg = effective_config(tool_root)
    pre = preflight(tool_root, offsite_dir, progress)
    services = pre["services"]
    backup_root = pre["backup_root"]
    run_id = utc_stamp()
    prefix = f"kxrecovery_{run_id}"
    db_name = f"{prefix}_database.sql.gz"
    media_name = f"{prefix}_media.tar.gz"
    sums_name = f"{prefix}_SHA256SUMS.txt"
    db_remote = f"{backup_root}/{db_name}"
    media_remote = f"{backup_root}/{media_name}"
    sums_remote = f"{backup_root}/{sums_name}"

    pg = shlex.quote(services["postgres"]["name"])
    dj = shlex.quote(services["django"]["name"])
    root_q = shlex.quote(backup_root)
    db_q, media_q, sums_q = map(shlex.quote, (db_remote, media_remote, sums_remote))
    _emit(progress, "Creating production PostgreSQL dump and media archive on the VPS...")
    script = f"""set -euo pipefail
umask 077
mkdir -p {root_q}
cleanup_partial() {{ rm -f {db_q} {media_q} {sums_q} >/dev/null 2>&1 || true; }}
trap cleanup_partial ERR
# Keep directory metadata discoverable by the configured admin while files remain root-only.
REMOTE_USER={shlex.quote(str(cfg.get('remote',{}).get('user','root')))}
if [ "$REMOTE_USER" != "root" ]; then
  grp=$(id -gn "$REMOTE_USER")
  chgrp "$grp" {root_q} || true
  chmod g+rx {root_q} || true
fi

docker exec {pg} sh -lc 'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' | gzip -c > {db_q}
gzip -t {db_q}

if docker exec {dj} sh -lc 'command -v tar >/dev/null 2>&1'; then
  docker exec {dj} sh -lc 'exec tar -C /app/konnaxion/media -czf - .' > {media_q}
else
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/media"
  docker cp {dj}:/app/konnaxion/media/. "$tmp/media/"
  tar -C "$tmp/media" -czf {media_q} .
fi
tar -tzf {media_q} >/dev/null

chmod 600 {db_q} {media_q}
(
  cd {root_q}
  sha256sum {shlex.quote(db_name)} {shlex.quote(media_name)} > {shlex.quote(sums_name)}
)
chmod 600 {sums_q}
printf 'DATABASE|%s|%s|%s\n' "$(sha256sum {db_q} | awk '{{print $1}}')" "$(stat -c %s {db_q})" {shlex.quote(db_name)}
printf 'MEDIA|%s|%s|%s\n' "$(sha256sum {media_q} | awk '{{print $1}}')" "$(stat -c %s {media_q})" {shlex.quote(media_name)}
printf 'SUMS|%s|%s|%s\n' "$(sha256sum {sums_q} | awk '{{print $1}}')" "$(stat -c %s {sums_q})" {shlex.quote(sums_name)}
trap - ERR
"""
    r = _remote_result(cfg, script, timeout=1800, privileged=True)
    parsed: dict[str, dict] = {}
    for line in r.get("stdout_tail", "").splitlines():
        parts = line.strip().split("|", 3)
        if len(parts) == 4 and parts[0] in {"DATABASE", "MEDIA", "SUMS"}:
            kind, digest, size, name = parts
            if re.fullmatch(r"[0-9a-f]{64}", digest) and size.isdigit():
                parsed[kind] = {"sha256": digest, "size": int(size), "name": name}
    if not {"DATABASE", "MEDIA", "SUMS"}.issubset(parsed):
        raise RecoveryError("Backup completed but expected hash evidence was not returned.")

    local_root = Path(offsite_dir).expanduser().resolve() / run_id
    local_root.mkdir(parents=True, exist_ok=True)
    _emit(progress, f"Copying encrypted-at-transport backup bytes off the VPS to {local_root}...")
    for kind, remote_path in (("DATABASE", db_remote), ("MEDIA", media_remote), ("SUMS", sums_remote)):
        local_path = local_root / parsed[kind]["name"]
        _download_remote(cfg, remote_path, local_path)
        actual = _sha256_file(local_path)
        if actual != parsed[kind]["sha256"]:
            raise RecoveryError(f"Hash mismatch for off-server copy {local_path.name}.")
        parsed[kind]["local_path"] = str(local_path)
        parsed[kind]["remote_path"] = remote_path
        _emit(progress, f"Verified SHA-256 for {local_path.name}.")

    state = {
        "schema": "securitydiag.recovery-assistant.backup.v1",
        "created_at": utc_iso(),
        "run_id": run_id,
        "compose_project": _safe_project(cfg),
        "remote_host": cfg.get("remote", {}).get("host"),
        "backup_root": backup_root,
        "offsite_root": str(local_root),
        "services": services,
        "files": parsed,
        "offsite_copy_verified": True,
    }
    manifest = local_root / "recovery-assistant-manifest.json"
    manifest.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    state_path = save_state(cfg, state)
    _emit(progress, f"Backup + off-server copy verified. State: {state_path}")
    return state


def _env_arg(path: str) -> str:
    return f"--env-file {shlex.quote(path)}"


def isolated_restore_drill(tool_root: Path | str, progress: Progress | None = None) -> dict:
    tool_root = _tool_root(tool_root)
    cfg = effective_config(tool_root)
    _require_remote(cfg)
    pre = preflight(tool_root, None, progress)
    envs = pre["env_paths"]
    state = load_state(tool_root)
    if state.get("offsite_copy_verified") is not True:
        raise RecoveryError("Latest backup state does not contain a verified off-server copy.")

    files = state.get("files", {})
    db_local = Path(files.get("DATABASE", {}).get("local_path", ""))
    media_local = Path(files.get("MEDIA", {}).get("local_path", ""))
    if not db_local.is_file() or not media_local.is_file():
        raise RecoveryError("The off-server database/media files recorded in latest backup state are missing.")
    if _sha256_file(db_local) != files["DATABASE"].get("sha256"):
        raise RecoveryError("Off-server database backup hash no longer matches recorded evidence.")
    if _sha256_file(media_local) != files["MEDIA"].get("sha256"):
        raise RecoveryError("Off-server media backup hash no longer matches recorded evidence.")

    services = pre["services"]
    drill_id = "kxrd_" + utc_stamp().lower()
    stage = f"/var/tmp/{drill_id}"
    net = drill_id + "_net"
    pg = drill_id + "_postgres"
    redis = drill_id + "_redis"
    app = drill_id + "_django"
    media_vol = drill_id + "_media"
    db_stage = f"{stage}/database.sql.gz"
    media_stage = f"{stage}/media.tar.gz"
    _emit(progress, "Creating isolated remote staging directory...")
    _remote_result(cfg, f"set -euo pipefail\numask 077\nmkdir -p {shlex.quote(stage)}\nchmod 700 {shlex.quote(stage)}\n", privileged=True)
    try:
        _emit(progress, "Uploading the verified off-server copy back to isolated staging...")
        _upload_remote(cfg, db_local, db_stage)
        _upload_remote(cfg, media_local, media_stage)
        expected_db = files["DATABASE"]["sha256"]
        expected_media = files["MEDIA"]["sha256"]
        check = _remote_result(
            cfg,
            f"set -euo pipefail\n"
            f"test \"$(sha256sum {shlex.quote(db_stage)} | awk '{{print $1}}')\" = {shlex.quote(expected_db)}\n"
            f"test \"$(sha256sum {shlex.quote(media_stage)} | awk '{{print $1}}')\" = {shlex.quote(expected_media)}\n"
            f"gzip -t {shlex.quote(db_stage)}\n"
            f"tar -tzf {shlex.quote(media_stage)} >/dev/null\n",
            privileged=True,
            timeout=300,
        )
        _emit(progress, "Staged off-server copy hashes and archive integrity verified.")

        pg_image = services["postgres"]["image_id"]
        redis_image = services["redis"]["image_id"]
        django_image = services["django"]["image_id"]
        for value in (net, pg, redis, app, media_vol, pg_image, redis_image, django_image):
            if not SAFE_NAME.fullmatch(value):
                raise RecoveryError(f"Unsafe runtime identifier discovered: {value!r}")

        django_env = envs["django.env"]
        postgres_env = envs["postgres.env"]
        postgres_env_arg = _env_arg(postgres_env)
        django_env_args = f"{_env_arg(django_env)} {postgres_env_arg}"

        _emit(progress, "Launching internal-only PostgreSQL/Redis/Django restore drill...")
        script = f"""set -euo pipefail
STAGE={shlex.quote(stage)}
NET={shlex.quote(net)}
PG={shlex.quote(pg)}
REDIS={shlex.quote(redis)}
APP={shlex.quote(app)}
MEDIA_VOL={shlex.quote(media_vol)}
cleanup() {{
  docker rm -f "$APP" "$REDIS" "$PG" >/dev/null 2>&1 || true
  docker volume rm "$MEDIA_VOL" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$STAGE" >/dev/null 2>&1 || true
}}
trap cleanup EXIT

docker network create --internal "$NET" >/dev/null
docker volume create "$MEDIA_VOL" >/dev/null

docker run --rm --user 0:0 -v "$MEDIA_VOL:/restore" -v "$STAGE:/staging:ro" --entrypoint sh {shlex.quote(django_image)} -lc '
  set -e
  tar -xzf /staging/media.tar.gz -C /restore
  uid=$(id -u django); gid=$(id -g django)
  chown -R "$uid:$gid" /restore
' >/dev/null
MEDIA_FILES=$(docker run --rm -v "$MEDIA_VOL:/restore:ro" --entrypoint sh {shlex.quote(django_image)} -lc 'find /restore -type f | wc -l' | tr -d '[:space:]')

docker run -d --name "$PG" --network "$NET" --network-alias postgres {postgres_env_arg} {shlex.quote(pg_image)} >/dev/null
docker run -d --name "$REDIS" --network "$NET" --network-alias redis {shlex.quote(redis_image)} >/dev/null

ready=0
for i in $(seq 1 90); do
  if docker exec "$PG" sh -lc 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" = 1 ] || {{ echo 'PostgreSQL did not become ready' >&2; exit 31; }}

gzip -dc "$STAGE/database.sql.gz" | docker exec -i "$PG" sh -lc 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null
TABLE_COUNT=$(docker exec "$PG" sh -lc 'psql -At -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select count(*) from information_schema.tables where table_schema=current_schema();"' | tr -d '[:space:]')
MIGRATIONS=$(docker exec "$PG" sh -lc 'psql -At -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select count(*) from django_migrations;"' | tr -d '[:space:]')
case "$TABLE_COUNT" in ''|*[!0-9]*) exit 32;; esac
case "$MIGRATIONS" in ''|*[!0-9]*) exit 33;; esac
[ "$TABLE_COUNT" -gt 0 ] || exit 34
[ "$MIGRATIONS" -gt 0 ] || exit 35

docker run -d --name "$APP" --network "$NET" {django_env_args} -v "$MEDIA_VOL:/app/konnaxion/media" {shlex.quote(django_image)} /start >/dev/null
HTTP_STATUS=''
for i in $(seq 1 90); do
  HTTP_STATUS=$(docker exec "$APP" python -c 'import http.client; c=http.client.HTTPConnection("127.0.0.1",5000,timeout=2); c.request("GET","/accounts/login/",headers={{"Host":"konnaxion.com","X-Forwarded-Proto":"https"}}); r=c.getresponse(); print(r.status)' 2>/dev/null | tail -1 | tr -d '[:space:]' || true)
  case "$HTTP_STATUS" in 2??|3??|4??) break;; esac
  sleep 1
done
case "$HTTP_STATUS" in 2??|3??|4??) ;; *) docker logs --tail 80 "$APP" >&2 || true; exit 36;; esac

USER_COUNT=$(docker exec "$APP" python /app/manage.py shell -c 'from django.contrib.auth import get_user_model; print(get_user_model().objects.count())' 2>/dev/null | tail -1 | tr -d '[:space:]')
case "$USER_COUNT" in ''|*[!0-9]*) exit 37;; esac
printf 'TABLE_COUNT|%s\n' "$TABLE_COUNT"
printf 'MIGRATIONS|%s\n' "$MIGRATIONS"
printf 'USER_COUNT|%s\n' "$USER_COUNT"
printf 'MEDIA_FILES|%s\n' "$MEDIA_FILES"
printf 'HTTP_STATUS|%s\n' "$HTTP_STATUS"
printf 'NETWORK_INTERNAL|true\n'
"""
        # Source files may be checked out with CRLF on Windows. Normalize the
        # generated Linux shell payload explicitly before validation/transmission.
        script = _normalize_shell_script(script)
        r = _remote_result(cfg, script, timeout=1800, privileged=True)
        evidence: dict[str, object] = {}
        for line in r.get("stdout_tail", "").splitlines():
            if "|" not in line:
                continue
            k, v = line.strip().split("|", 1)
            if k in {"TABLE_COUNT", "MIGRATIONS", "USER_COUNT", "MEDIA_FILES", "HTTP_STATUS"} and v.isdigit():
                evidence[k.lower()] = int(v)
            elif k == "NETWORK_INTERNAL":
                evidence["network_internal"] = v.lower() == "true"
        required = {"table_count", "migrations", "user_count", "media_files", "http_status", "network_internal"}
        if not required.issubset(evidence):
            raise RecoveryError("Restore drill ran but did not return complete verification evidence.")
        if evidence["network_internal"] is not True:
            raise RecoveryError("Restore drill network was not confirmed internal-only.")

        attestation = {
            "schema": "securitydiag.restore-drill.v1",
            "performed_at": utc_iso(),
            "operator": os.environ.get("USERNAME") or os.environ.get("USER") or "local-operator",
            "isolated_target": True,
            "database_restored": True,
            "application_booted": True,
            "critical_data_verified": True,
            "offsite_copy_verified": True,
            "evidence": {
                "backup_run_id": state.get("run_id"),
                "database_sha256": files["DATABASE"]["sha256"],
                "media_sha256": files["MEDIA"]["sha256"],
                "restore_network_internal": True,
                **evidence,
            },
        }
        rel = cfg.get("recovery", {}).get("restore_attestation_file", "securitydiag/attestations/restore-drill.local.json")
        att_path = (Path(cfg["_target_root"]) / rel).resolve()
        target = Path(cfg["_target_root"]).resolve()
        if not att_path.is_relative_to(target):
            raise RecoveryError("Configured restore attestation path escapes the target repository.")
        att_path.parent.mkdir(parents=True, exist_ok=True)
        att_path.write_text(json.dumps(attestation, indent=2, ensure_ascii=False), encoding="utf-8")
        drill_evidence = Path(cfg["_control_root"]) / "recovery-assistant" / f"drill-{drill_id}.json"
        drill_evidence.parent.mkdir(parents=True, exist_ok=True)
        drill_evidence.write_text(json.dumps(attestation, indent=2, ensure_ascii=False), encoding="utf-8")
        _emit(progress, f"Isolated restore drill PASS. Attestation written to {att_path}")
        return {"attestation_path": str(att_path), "evidence_path": str(drill_evidence), "attestation": attestation}
    except Exception:
        # Best-effort cleanup if failure happened before the remote script installed its trap.
        try:
            cleanup = (
                f"docker rm -f {shlex.quote(app)} {shlex.quote(redis)} {shlex.quote(pg)} >/dev/null 2>&1 || true\n"
                f"docker volume rm {shlex.quote(media_vol)} >/dev/null 2>&1 || true\n"
                f"docker network rm {shlex.quote(net)} >/dev/null 2>&1 || true\n"
                f"rm -rf {shlex.quote(stage)} >/dev/null 2>&1 || true\n"
            )
            _remote_result(cfg, cleanup, privileged=True, timeout=30)
        except Exception:
            pass
        raise


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def record_release_attestations(tool_root: Path | str, values: dict[str, bool]) -> Path:
    tool_root = _tool_root(tool_root)
    if set(values) != set(ATTESTATION_KEYS):
        raise RecoveryError("Release attestations must include exactly the six SecurityDiag incident-recovery keys.")
    if any(v is not True for v in values.values()):
        raise RecoveryError("All six release attestations must be explicitly confirmed true before recording them.")
    local = tool_root / "securitydiag.config.local.json"
    if not local.exists():
        data: dict = {"schema": "securitydiag.config.v1.1"}
    else:
        data = _read_json(local)
    backup_dir = Path.home() / ".securitydiag-recovery" / "config-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    if local.exists():
        shutil.copy2(local, backup_dir / f"securitydiag.config.local.{utc_stamp()}.json")
    release = data.setdefault("release", {})
    release["require_attestations"] = True
    release["attestations"] = {k: True for k in ATTESTATION_KEYS}
    local.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return local


def current_release_attestations(tool_root: Path | str) -> dict[str, bool]:
    cfg = effective_config(tool_root)
    values = cfg.get("release", {}).get("attestations", {})
    return {k: values.get(k) is True for k in ATTESTATION_KEYS}


def run_securitydiag_release(tool_root: Path | str, progress: Progress | None = None) -> dict:
    tool_root = _tool_root(tool_root)
    script = tool_root / "securitydiag.py"
    if not script.exists():
        raise RecoveryError(f"Missing {script}")
    exe = sys.executable
    _emit(progress, "Running SecurityDiag release campaign...")
    cp = subprocess.run([exe, str(script), "run", "release"], cwd=tool_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3600, check=False)
    output = (cp.stdout or "") + (("\n" + cp.stderr) if cp.stderr else "")
    _emit(progress, output.strip())
    return {"exit_code": cp.returncode, "output": output}


def default_offsite_dir() -> Path:
    return Path.home() / "KonnaxionRecovery" / "konnaxion-prod"
