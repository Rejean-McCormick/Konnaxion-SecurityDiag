from __future__ import annotations
from pathlib import Path
from .util import read_json

class ManifestError(RuntimeError): pass

def load_manifest(tool_root: Path):
    p=tool_root/"securitydiag_manifest.json"
    if not p.exists(): raise ManifestError(f"Missing manifest: {p}")
    m=read_json(p)
    if m.get("schema")!="securitydiag.manifest.v1":
        raise ManifestError("Unsupported manifest schema")
    levels=m.get("levels")
    if not isinstance(levels,list) or not levels:
        raise ManifestError("Manifest must declare levels")
    ids=[x.get("id") for x in levels]
    if any(not x for x in ids) or len(ids)!=len(set(ids)):
        raise ManifestError("Level IDs must be non-empty and unique")
    known=set(ids)
    for x in levels:
        for dep in x.get("depends_on",[]):
            if dep not in known:
                raise ManifestError(f"{x['id']} depends on unknown {dep}")
    return m

def resolve_selection(m,name):
    lm={x["id"]:x for x in m["levels"]}
    if name in lm: selected={name}
    elif name in m.get("campaigns",{}): selected=set(m["campaigns"][name].get("levels",[]))
    else: raise ManifestError(f"Unknown level or campaign: {name}")
    changed=True
    while changed:
        changed=False
        for lid in list(selected):
            for dep in lm[lid].get("depends_on",[]):
                if dep not in selected:
                    selected.add(dep); changed=True
    return sorted((lm[x] for x in selected), key=lambda x:(x.get("order",0),x["id"]))
