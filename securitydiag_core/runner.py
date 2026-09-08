from __future__ import annotations
import shutil, subprocess, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from . import SUMMARY_SCHEMA, VERSION
from .config import load_config
from .manifest import load_manifest, resolve_selection
from .util import read_json, redact, redact_data, utc_now, write_json
from .verdicts import campaign_verdict, exit_code
from .vcs import git_info

HARD_DEP_BLOCK={"BLOCKED","ERROR","INFRA_ERROR","CONFIG_ERROR"}

def make_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:8]

def blocked(meta,run_id,target,deps):
    now=utc_now()
    return {"schema":"securitydiag.report.v1","standard":"SecurityDiag","standard_version":VERSION,
            "run_id":run_id,"level_id":meta["id"],"level_name":meta["name"],"purpose":meta.get("purpose",""),
            "target_repo_root":str(target),"started_at":now,"ended_at":now,"verdict":"BLOCKED",
            "findings":[{"id":"dependencies.required.blocked","verdict":"BLOCKED","category":"dependency",
                         "message":"A required dependency did not produce usable evidence.","evidence":{"dependencies":deps}}],
            "artifacts":[],"metrics":{}}

def run_campaign(tool_root:Path,selection:str,target_override=None,fail_fast=None):
    m=load_manifest(tool_root); cfg=load_config(tool_root,target_override)
    levels=resolve_selection(m,selection)
    target=Path(cfg["_target_root"]); control=Path(cfg["_control_root"])
    run_id=make_run_id(); run_root=control/"runs"/run_id; run_root.mkdir(parents=True,exist_ok=True)
    write_json(run_root/"effective_config.json",redact_data({k:v for k,v in cfg.items() if not k.startswith("_")}))
    before=git_info(target) if cfg.get("execution",{}).get("protect_tracked_files",True) else None
    results={}; started=utc_now()
    ff=cfg.get("execution",{}).get("fail_fast",False) if fail_fast is None else fail_fast
    for meta in levels:
        deps={d:results[d].get("verdict") for d in meta.get("depends_on",[]) if d in results}
        bad={d:v for d,v in deps.items() if v in HARD_DEP_BLOCK}
        out=run_root/"levels"/meta["id"]/"result.json"; out.parent.mkdir(parents=True,exist_ok=True)
        if bad:
            data=blocked(meta,run_id,target,bad); write_json(out,data); results[meta["id"]]=data; continue
        if ff and any(r.get("verdict") in {"FAIL","ERROR","CONFIG_ERROR"} for r in results.values()):
            data=blocked(meta,run_id,target,{"fail_fast":"campaign stopped"}); write_json(out,data); results[meta["id"]]=data; continue
        timeout=int(meta.get("timeout_seconds") or cfg.get("execution",{}).get("default_timeout_seconds",120))
        cmd=[sys.executable,str(tool_root/"securitydiag.py"),"_worker","--level",meta["id"],
             "--run-id",run_id,"--output",str(out),"--target",str(target)]
        try:
            cp=subprocess.run(cmd,cwd=str(target),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              text=True,encoding="utf-8",errors="replace",timeout=timeout,shell=False,check=False)
            if out.exists():
                data=read_json(out)
            else:
                now=utc_now()
                data={"schema":"securitydiag.report.v1","standard":"SecurityDiag","standard_version":VERSION,
                      "run_id":run_id,"level_id":meta["id"],"level_name":meta["name"],"purpose":meta.get("purpose",""),
                      "target_repo_root":str(target),"started_at":now,"ended_at":now,
                      "verdict":"INFRA_ERROR",
                      "findings":[{"id":"diagnostics.worker.missing_result","verdict":"INFRA_ERROR","category":"diagnostics",
                                   "message":"Worker did not produce a result.",
                                   "evidence":{"return_code":cp.returncode,"stderr_tail":redact((cp.stderr or "")[-2000:])}}],
                      "artifacts":[],"metrics":{}}
                write_json(out,data)
        except subprocess.TimeoutExpired:
            now=utc_now()
            data={"schema":"securitydiag.report.v1","standard":"SecurityDiag","standard_version":VERSION,
                  "run_id":run_id,"level_id":meta["id"],"level_name":meta["name"],"purpose":meta.get("purpose",""),
                  "target_repo_root":str(target),"started_at":now,"ended_at":now,"verdict":"INFRA_ERROR",
                  "findings":[{"id":"diagnostics.worker.timeout","verdict":"INFRA_ERROR","category":"diagnostics",
                               "message":f"Level exceeded {timeout}s timeout."}],"artifacts":[],"metrics":{}}
            write_json(out,data)
        results[meta["id"]]=data

    ordered=[results[x["id"]] for x in levels]
    required={x["id"]:bool(x.get("required",False)) for x in levels}
    verdict=campaign_verdict(ordered,required)
    after=git_info(target) if before is not None else None
    protection=None
    if before and before.get("repository") and after and after.get("repository") and before.get("tracked_status")!=after.get("tracked_status"):
        protection={"verdict":"ERROR","message":"Tracked Git state changed during SecurityDiag.",
                    "before":before.get("tracked_status"),"after":after.get("tracked_status")}
        verdict="ERROR"
    counts={}
    for r in ordered: counts[r.get("verdict","ERROR")]=counts.get(r.get("verdict","ERROR"),0)+1
    summary={"schema":SUMMARY_SCHEMA,"standard":"SecurityDiag","standard_version":VERSION,
             "run_id":run_id,"selection":selection,"target_repo_root":str(target),
             "started_at":started,"ended_at":utc_now(),"verdict":verdict,"counts":counts,
             "expected_levels":[x["id"] for x in levels],
             "required_levels":[x["id"] for x in levels if x.get("required")],
             "levels":[{"id":r["level_id"],"name":r["level_name"],"verdict":r["verdict"],
                        "result":str((run_root/"levels"/r["level_id"]/"result.json").relative_to(run_root))}
                       for r in ordered],
             "target_protection":protection}
    write_json(run_root/"summary.json",summary)
    txt=[f"SecurityDiag {selection} - {verdict}",f"Run: {run_id}",f"Target: {target}",""]
    txt += [f"{r['level_id']:>3}  {r['verdict']:<12} {r['level_name']}" for r in ordered]
    (run_root/"summary.txt").write_text("\n".join(txt)+"\n",encoding="utf-8")
    md=[f"# SecurityDiag — {selection}",f"**Verdict:** {verdict}",f"**Run:** `{run_id}`",f"**Target:** `{target}`","",
        "| Level | Verdict | Name |","|---|---|---|"]
    md += [f"| {r['level_id']} | {r['verdict']} | {r['level_name']} |" for r in ordered]
    (run_root/"summary.md").write_text("\n".join(md)+"\n",encoding="utf-8")
    latest=control/"latest"
    if latest.exists(): shutil.rmtree(latest)
    latest.mkdir(parents=True,exist_ok=True)
    shutil.copy2(run_root/"summary.json",latest/"summary.json")
    shutil.copy2(run_root/"summary.txt",latest/"summary.txt")
    shutil.copy2(run_root/"summary.md",latest/"summary.md")
    for r in ordered:
        src=run_root/"levels"/r["level_id"]/"result.json"
        dst=latest/"levels"/r["level_id"]/"result.json"; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,dst)
    return summary,exit_code(verdict),run_root
