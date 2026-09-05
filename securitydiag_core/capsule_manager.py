from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SAFE_INSTANCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

CANONICAL_CAPSULE_STATUSES = {
    "PASS", "WARN", "FAIL_BLOCKING", "SKIPPED", "UNKNOWN"
}

def resolve_capsule_repo(cfg: dict[str, Any]) -> Path | None:
    cm = cfg.get("capsule_manager", {})
    raw = str(cm.get("repo_root", "auto")).strip()
    target = Path(cfg["_target_root"]).resolve(strict=False)
    if raw.lower() == "auto":
        candidate = target.parent / "Konnaxion_Capsule_Manager"
    else:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = target / candidate
    candidate = candidate.resolve(strict=False)
    return candidate if candidate.exists() and candidate.is_dir() else None

def capsule_enabled(cfg: dict[str, Any]) -> bool:
    return bool(cfg.get("capsule_manager", {}).get("enabled", False))

def instance_id(cfg: dict[str, Any]) -> str:
    value = str(cfg.get("capsule_manager", {}).get("instance_id", "")).strip()
    if not value:
        return ""
    if not SAFE_INSTANCE_ID.fullmatch(value):
        raise ValueError("capsule_manager.instance_id contains unsafe characters")
    return value

def inspect_local_policy(repo: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    cm = cfg.get("capsule_manager", {})
    files = cm.get("policy_files", {})
    result: dict[str, Any] = {"repo": str(repo), "files": {}, "checks": {}}

    for key, rel in files.items():
        path = (repo / str(rel)).resolve(strict=False)
        try:
            path.relative_to(repo)
        except ValueError:
            result["files"][key] = {"exists": False, "unsafe_path": True}
            continue
        result["files"][key] = {"exists": path.exists(), "path": str(path)}

    auth = repo / str(files.get("agent_auth", "kx_agent/auth.py"))
    runtime = repo / str(files.get("runtime", "policies/runtime_policy.yaml"))
    gate = repo / str(files.get("security_gate", "policies/security_gate.yaml"))

    auth_text = auth.read_text(encoding="utf-8", errors="replace") if auth.exists() else ""
    runtime_text = runtime.read_text(encoding="utf-8", errors="replace") if runtime.exists() else ""
    gate_text = gate.read_text(encoding="utf-8", errors="replace") if gate.exists() else ""

    checks = result["checks"]
    checks["agent_local_bind_declared"] = all(x in auth_text for x in ("127.0.0.1", "::1", "LOCAL_BIND_HOSTS"))
    checks["agent_forbidden_operations_declared"] = "FORBIDDEN_AGENT_OPERATIONS" in auth_text and "shell.exec" in auth_text and "docker.run" in auth_text
    checks["runtime_private_by_default"] = "deny_by_default: true" in runtime_text
    checks["runtime_blocks_privileged"] = "privileged_allowed: false" in runtime_text
    checks["runtime_blocks_host_network"] = "host_network_allowed: false" in runtime_text
    checks["runtime_blocks_docker_socket"] = "docker_socket_mount_allowed: false" in runtime_text
    checks["runtime_blocks_unknown_images"] = "unknown_images_allowed: false" in runtime_text
    checks["runtime_requires_signed_capsules"] = "reject_unsigned_capsules: true" in runtime_text
    checks["gate_has_fail_blocking"] = "FAIL_BLOCKING" in gate_text
    checks["gate_has_unknown"] = "UNKNOWN" in gate_text
    checks["temporary_public_requires_expiration"] = "requires_expiration: true" in gate_text or "public_temporary_requires_expiration: true" in runtime_text
    return result

def gate_status_from_payload(payload: dict[str, Any]) -> str:
    status = str(
        payload.get("security_status")
        or payload.get("status")
        or (payload.get("summary") or {}).get("status")
        or "UNKNOWN"
    ).strip().upper()
    return status if status in CANONICAL_CAPSULE_STATUSES else "UNKNOWN"

def normalize_gate_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("checks")
    if raw is None:
        raw = payload.get("results")
    if raw is None and isinstance(payload.get("report"), dict):
        raw = payload["report"].get("results")

    out: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        for check, value in raw.items():
            if isinstance(value, dict):
                status = str(value.get("status", "UNKNOWN")).upper()
                message = str(value.get("message", ""))
            else:
                status = str(value).upper()
                message = ""
            out.append({"check": str(check), "status": status, "message": message})
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                out.append({
                    "check": str(item.get("check") or item.get("name") or ""),
                    "status": str(item.get("status") or "UNKNOWN").upper(),
                    "message": str(item.get("message") or ""),
                })
    return out

def gate_is_release_acceptable(payload: dict[str, Any], *, unknown_is_blocking: bool = True) -> tuple[bool, dict[str, Any]]:
    status = gate_status_from_payload(payload)
    results = normalize_gate_results(payload)
    blocking = [
        item for item in results
        if item["status"] == "FAIL_BLOCKING"
        or (unknown_is_blocking and item["status"] == "UNKNOWN")
    ]
    acceptable = status in {"PASS", "WARN"} and not blocking
    return acceptable, {"status": status, "blocking": blocking, "results": results}

def remote_probe_script(cfg: dict[str, Any]) -> str:
    cm = cfg.get("capsule_manager", {})
    iid = instance_id(cfg)
    if not iid:
        raise ValueError("capsule_manager.instance_id is required for remote Capsule Manager checks")

    gate_tpl = str(cm.get("security_gate_remote_path_template", "/opt/konnaxion/instances/{instance_id}/state/security-gate.json"))
    env_tpl = str(cm.get("runtime_env_remote_path_template", "/opt/konnaxion/instances/{instance_id}/env/runtime.env"))
    gate_path = gate_tpl.format(instance_id=iid)
    env_path = env_tpl.format(instance_id=iid)
    token_path = str(cm.get("agent_token_path", "/opt/konnaxion/manager/agent.token"))
    audit_path = str(cm.get("audit_path", "/opt/konnaxion/agent/audit/agent-audit.jsonl"))
    service = str(cm.get("agent_service_name", "kx-agent"))
    port = int(cm.get("agent_port", 8765))

    # All interpolated values are validated/static config. No secrets are read.
    return f"""
set +e
echo "__KX_AGENT_LISTENER__"
ss -ltnp 2>/dev/null | grep -E ':{port}[[:space:]]' || true
echo "__KX_AGENT_SERVICE__"
systemctl show {service} -p User -p Group -p NoNewPrivileges -p ProtectSystem -p ProtectHome -p PrivateTmp -p RestrictSUIDSGID -p CapabilityBoundingSet -p AmbientCapabilities 2>/dev/null || true
echo "__KX_TOKEN_STAT__"
stat -Lc '%a|%U|%G|%n' {token_path} 2>/dev/null || true
echo "__KX_AUDIT_STAT__"
stat -Lc '%a|%U|%G|%s|%Y|%n' {audit_path} 2>/dev/null || true
echo "__KX_RUNTIME_PROFILE__"
if [ -r {env_path} ]; then
  grep -E '^(KX_NETWORK_PROFILE|KX_EXPOSURE_MODE|KX_PUBLIC_MODE_ENABLED|KX_PUBLIC_MODE_EXPIRES_AT|KX_HOST)=' {env_path} 2>/dev/null || true
fi
echo "__KX_SECURITY_GATE__"
if [ -r {gate_path} ]; then
  cat {gate_path}
else
  echo '{{"status":"UNKNOWN","reason":"security-gate evidence file missing"}}'
fi
"""
