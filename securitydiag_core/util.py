from __future__ import annotations
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

SECRET_RX = [
    re.compile(r"(?i)(DJANGO_SECRET_KEY|POSTGRES_PASSWORD|DATABASE_URL|API[_-]?KEY|ACCESS[_-]?TOKEN|PRIVATE[_-]?KEY)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

def redact(text: str, replacement="<REDACTED>"):
    if not text:
        return text
    out = text
    for rx in SECRET_RX:
        if rx.groups >= 2:
            out = rx.sub(lambda m: f"{m.group(1)}={replacement}", out)
        else:
            out = rx.sub(replacement, out)
    return out

def tail_text(text: str, limit_bytes: int):
    raw = (text or "").encode("utf-8", "replace")
    if len(raw) <= limit_bytes:
        return text or ""
    return raw[-limit_bytes:].decode("utf-8", "replace")

def safe_rel(root: Path, path: Path):
    try:
        return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except Exception:
        return str(path)

def parse_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1","true","yes","on"}
