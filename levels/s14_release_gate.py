from __future__ import annotations

from pathlib import Path

from securitydiag_core.util import read_json

BAD = {
    "FAIL",
    "ERROR",
    "CONFIG_ERROR",
    "INFRA_ERROR",
    "BLOCKED",
    "PARTIAL",
}

def _load_prior(run_root: Path) -> list[dict]:
    level_root = run_root / "levels"
    prior = []
    if not level_root.exists():
        return prior

    for path in sorted(level_root.glob("S*/result.json")):
        try:
            result = read_json(path)
        except Exception:
            continue
        if result.get("level_id") == "S14":
            continue
        prior.append(result)
    return prior

def _capsule_gate_evidence(prior: list[dict]) -> dict | None:
    for result in prior:
        if result.get("level_id") != "S09":
            continue
        for finding in result.get("findings", []):
            if finding.get("id") == "capsule.security_gate.evidence":
                return finding
    return None

def run(cfg, report):
    run_root = Path(cfg.get("_run_root", ""))
    prior_results = _load_prior(run_root)

    prior = [
        {
            "id": item.get("level_id"),
            "name": item.get("level_name"),
            "verdict": item.get("verdict"),
        }
        for item in prior_results
    ]
    bad = [item for item in prior if item["verdict"] in BAD]
    warns = [item for item in prior if item["verdict"] == "WARN"]

    report.add(
        "release.prior_levels.complete",
        "FAIL" if bad else "PASS",
        "release_gate",
        "One or more security levels are not release-acceptable."
        if bad
        else "No prior security level is failed/blocked/incomplete.",
        evidence={"bad": bad, "warnings": warns},
    )

    cm = cfg.get("capsule_manager", {})
    cm_required = bool(cm.get("enabled", False) and cm.get("require_for_release", True))
    if cm_required:
        gate = _capsule_gate_evidence(prior_results)
        if gate is None:
            report.add(
                "release.capsule_manager.security_gate",
                "FAIL",
                "release_gate",
                "Capsule Manager Security Gate evidence is missing from S09.",
                recommendation=(
                    "Configure capsule_manager.instance_id and run S09/host evidence "
                    "before release."
                ),
                release_blocker=True,
            )
            capsule_ok = False
        else:
            capsule_ok = gate.get("verdict") == "PASS"
            report.add(
                "release.capsule_manager.security_gate",
                "PASS" if capsule_ok else "FAIL",
                "release_gate",
                "Capsule Manager Security Gate evidence is release-acceptable."
                if capsule_ok
                else "Capsule Manager Security Gate is not release-acceptable.",
                evidence=gate.get("evidence"),
                release_blocker=not capsule_ok,
            )
    else:
        capsule_ok = True
        report.add(
            "release.capsule_manager.security_gate",
            "SKIP",
            "release_gate",
            "Capsule Manager release integration is disabled.",
        )

    release_cfg = cfg.get("release", {})
    required = release_cfg.get("require_attestations", True)
    attestations = release_cfg.get("attestations", {})
    missing = [key for key, value in attestations.items() if value is not True]

    if required:
        report.add(
            "release.incident_recovery.attestations",
            "BLOCKED" if missing else "PASS",
            "release_gate",
            "Required incident-recovery attestations are incomplete."
            if missing
            else "All required incident-recovery attestations are recorded.",
            evidence={
                "missing": missing,
                "recorded": [key for key, value in attestations.items() if value is True],
            },
            recommendation=(
                "Do not mark the deployment releasable until each human-controlled "
                "recovery condition is genuinely verified."
                if missing
                else None
            ),
        )
    else:
        report.add(
            "release.incident_recovery.attestations",
            "WARN",
            "release_gate",
            "Human incident-recovery attestations are disabled.",
        )

    if not bad and not missing and capsule_ok:
        report.add(
            "release.security_gate",
            "PASS",
            "release_gate",
            "SecurityDiag + Capsule Manager release gate is satisfied. Warnings remain visible and must be dispositioned.",
        )
    elif bad or not capsule_ok:
        report.add(
            "release.security_gate",
            "FAIL",
            "release_gate",
            "Combined release gate is not satisfied due to failed/incomplete technical evidence.",
        )
    else:
        report.add(
            "release.security_gate",
            "BLOCKED",
            "release_gate",
            "Combined release gate awaits human incident-recovery attestations.",
        )
