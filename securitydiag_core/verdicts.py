from __future__ import annotations

VERDICTS = (
    "PASS", "WARN", "FAIL", "SKIP", "BLOCKED", "PARTIAL",
    "ERROR", "INFRA_ERROR", "CONFIG_ERROR",
)
RANK = {
    "PASS":0, "WARN":1, "SKIP":2, "PARTIAL":3, "BLOCKED":4,
    "INFRA_ERROR":5, "FAIL":6, "ERROR":7, "CONFIG_ERROR":8,
}
def worst(verdicts):
    vals=[v for v in verdicts if v in RANK]
    return max(vals, key=lambda v:RANK[v]) if vals else "PASS"

def level_verdict(findings, default="PASS"):
    if not findings:
        return default
    vals=[f.get("verdict","PASS") for f in findings]
    substantive=[v for v in vals if v!="SKIP"]
    return worst(substantive) if substantive else "SKIP"

def campaign_verdict(results, required_map):
    if not results: return "CONFIG_ERROR"
    if any(r.get("verdict") in {"ERROR","CONFIG_ERROR"} for r in results): return "ERROR"
    if any(r.get("verdict")=="FAIL" for r in results): return "FAIL"
    incomplete={"SKIP","BLOCKED","PARTIAL","INFRA_ERROR"}
    if any(required_map.get(r.get("level_id"),False) and r.get("verdict") in incomplete for r in results):
        return "BLOCKED"
    if any(r.get("verdict") in incomplete for r in results): return "WARN"
    if any(r.get("verdict")=="WARN" for r in results): return "WARN"
    return "PASS"

def exit_code(verdict):
    if verdict in {"PASS","WARN"}: return 0
    if verdict=="FAIL": return 10
    if verdict in {"SKIP","BLOCKED","PARTIAL"}: return 20
    return 30
