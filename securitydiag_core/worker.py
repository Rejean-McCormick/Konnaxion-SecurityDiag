from __future__ import annotations
import importlib
from pathlib import Path
from .config import load_config
from .manifest import load_manifest
from .report import Report

def run_worker(tool_root: Path, level_id, run_id, output: Path, target_override=None):
    cfg=load_config(tool_root,target_override)
    cfg["_run_root"]=str(output.parent.parent.parent)
    manifest=load_manifest(tool_root)
    meta=next((x for x in manifest["levels"] if x["id"]==level_id),None)
    if not meta: raise RuntimeError(f"Unknown level: {level_id}")
    report=Report(run_id,level_id,meta["name"],meta.get("purpose",""),cfg["_target_root"])
    try:
        mod=importlib.import_module(meta["module"])
        mod.run(cfg,report)
        report.write(output)
        return 0
    except Exception as e:
        report.add("securitydiag.level.exception","ERROR","diagnostics",
                   f"Level raised {type(e).__name__}.",
                   evidence={"error":str(e)[:1000]})
        report.write(output,override_verdict="ERROR")
        return 30
