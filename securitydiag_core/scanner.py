from __future__ import annotations
import os
from pathlib import Path


def iter_files(root: Path, cfg, *, max_files=None, stats=None):
    scan=cfg.get("scan",{})
    excluded=set(scan.get("exclude_dirs",[]))
    max_files=int(max_files or scan.get("max_files",20000))
    count=0
    state = stats if stats is not None else {}
    state.setdefault("files_yielded", 0)
    state.setdefault("limit_reached", False)
    for base,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in excluded]
        for name in files:
            if count >= max_files:
                state["limit_reached"] = True
                return
            p=Path(base)/name
            try: rel=p.relative_to(root).as_posix()
            except Exception: continue
            yield p,rel
            count+=1
            state["files_yielded"] = count


def bounded_text_status(path: Path, max_bytes=1048576):
    """Return ``(text, reason)`` where reason explains skipped content."""
    try:
        if path.stat().st_size>max_bytes:
            return None, "too_large"
        raw=path.read_bytes()
        if b"\x00" in raw[:4096]:
            return None, "binary"
        return raw.decode("utf-8","replace"), None
    except Exception:
        return None, "read_error"


def bounded_text(path: Path, max_bytes=1048576):
    text, _reason = bounded_text_status(path, max_bytes)
    return text
