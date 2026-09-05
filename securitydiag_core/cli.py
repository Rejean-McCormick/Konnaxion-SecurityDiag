from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from . import VERSION, REPORT_SCHEMA, SUMMARY_SCHEMA
from .config import load_config
from .manifest import load_manifest
from .runner import run_campaign
from .worker import run_worker
from .util import read_json

def parser():
    p=argparse.ArgumentParser(prog="securitydiag",description="Read-only security qualification framework")
    p.add_argument("--version",action="version",version=f"SecurityDiag {VERSION}")
    sub=p.add_subparsers(dest="cmd",required=True)
    sub.add_parser("doctor")
    sub.add_parser("list")
    sc=sub.add_parser("show-config"); sc.add_argument("--target")
    r=sub.add_parser("run"); r.add_argument("selection"); r.add_argument("--target"); r.add_argument("--fail-fast",action="store_true")
    v=sub.add_parser("verify-run"); v.add_argument("summary")
    w=sub.add_parser("_worker"); w.add_argument("--level",required=True); w.add_argument("--run-id",required=True)
    w.add_argument("--output",required=True); w.add_argument("--target")
    return p

def main(argv=None):
    args=parser().parse_args(argv)
    tool=Path(__file__).resolve().parent.parent
    try:
        if args.cmd=="doctor":
            m=load_manifest(tool); cfg=load_config(tool)
            print(f"SecurityDiag {VERSION}")
            print(f"Target: {cfg['_target_root']}")
            print(f"Levels: {len(m['levels'])}")
            print("Mode: read-only diagnostics")
            return 0
        if args.cmd=="list":
            m=load_manifest(tool)
            for x in m["levels"]: print(f"{x['id']}  {x['name']}")
            print("\\nCampaigns:")
            for k,v in m.get("campaigns",{}).items(): print(f"{k:12} {v.get('description','')}")
            return 0
        if args.cmd=="show-config":
            cfg=load_config(tool,args.target)
            print(json.dumps({k:v for k,v in cfg.items() if not k.startswith("_")},indent=2,ensure_ascii=False)); return 0
        if args.cmd=="run":
            summary,code,run_root=run_campaign(tool,args.selection,args.target,args.fail_fast)
            print((run_root/"summary.txt").read_text(encoding="utf-8"),end="")
            print(f"Evidence: {run_root}")
            return code
        if args.cmd=="verify-run":
            p=Path(args.summary); s=read_json(p)
            if s.get("schema")!=SUMMARY_SCHEMA: print("Invalid summary schema",file=sys.stderr); return 30
            base=p.parent
            missing=[]
            for row in s.get("levels",[]):
                rp=base/row["result"]
                if not rp.exists(): missing.append(str(rp))
                else:
                    r=read_json(rp)
                    if r.get("schema")!=REPORT_SCHEMA: missing.append(str(rp)+" (schema)")
            if missing:
                print("INVALID"); [print(" -",x) for x in missing]; return 30
            print("VALID"); return 0
        if args.cmd=="_worker":
            return run_worker(tool,args.level,args.run_id,Path(args.output),args.target)
    except Exception as e:
        print(f"SecurityDiag error: {type(e).__name__}: {e}",file=sys.stderr)
        return 30
    return 64
