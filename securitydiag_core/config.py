from __future__ import annotations
import copy
from pathlib import Path
from .util import read_json

class ConfigError(RuntimeError): pass

def _merge(base, overlay):
    out=copy.deepcopy(base)
    for k,v in overlay.items():
        if isinstance(v,dict) and isinstance(out.get(k),dict):
            out[k]=_merge(out[k],v)
        else:
            out[k]=copy.deepcopy(v)
    return out

def load_config(tool_root: Path, target_override=None):
    base_path=tool_root/"securitydiag.config.json"
    if not base_path.exists():
        raise ConfigError(f"Missing configuration: {base_path}")
    cfg=read_json(base_path)
    local=tool_root/"securitydiag.config.local.json"
    if local.exists():
        cfg=_merge(cfg,read_json(local))
    if cfg.get("schema") not in {"securitydiag.config.v1", "securitydiag.config.v1.1"}:
        raise ConfigError("Unsupported config schema")
    target_value=target_override or cfg.get("target_repo_root","auto")
    if str(target_value).lower()=="auto":
        target=tool_root.parent
    else:
        p=Path(str(target_value)).expanduser()
        target=p if p.is_absolute() else tool_root/p
    target=target.resolve(strict=False)
    if not target.exists() or not target.is_dir():
        raise ConfigError(f"Target repository root is not a directory: {target}")
    control=Path(cfg.get("control_dir",".securitydiag"))
    if control.is_absolute():
        raise ConfigError("control_dir must be relative")
    control_abs=(target/control).resolve(strict=False)
    if not control_abs.is_relative_to(target):
        raise ConfigError("control_dir escapes target repository")
    cfg["_tool_root"]=str(tool_root.resolve())
    cfg["_target_root"]=str(target)
    cfg["_control_root"]=str(control_abs)
    return cfg
