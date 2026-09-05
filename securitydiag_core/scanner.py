from __future__ import annotations
import os
from pathlib import Path

def iter_files(root: Path, cfg, *, max_files=None):
    scan=cfg.get("scan",{})
    excluded=set(scan.get("exclude_dirs",[]))
    max_files=int(max_files or scan.get("max_files",20000))
    count=0
    for base,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in excluded]
        for name in files:
            p=Path(base)/name
            try: rel=p.relative_to(root).as_posix()
            except Exception: continue
            yield p,rel
            count+=1
            if count>=max_files: return

def bounded_text(path: Path, max_bytes=1048576):
    try:
        if path.stat().st_size>max_bytes: return None
        raw=path.read_bytes()
        if b"\\x00" in raw[:4096]: return None
        return raw.decode("utf-8","replace")
    except Exception:
        return None
