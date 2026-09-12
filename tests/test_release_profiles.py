from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from levels import s14_release_gate


ATTESTATIONS = {
    "fresh_vps": False,
    "old_disk_not_cloned": False,
    "all_compromised_secrets_rotated": False,
    "clean_git_source_only": False,
    "cloud_firewall_verified": False,
    "old_vps_retired_or_isolated": False,
}


class FakeReport:
    def __init__(self):
        self.findings = []

    def add(self, finding_id, verdict, category, message, **kwargs):
        self.findings.append(
            {
                "id": finding_id,
                "verdict": verdict,
                "category": category,
                "message": message,
                **kwargs,
            }
        )

    def by_id(self, finding_id):
        return next(item for item in self.findings if item["id"] == finding_id)


class ReleaseProfileTests(unittest.TestCase):
    def _cfg(self, root: str, profile: str | None = None):
        release = {
            "require_attestations": True,
            "attestations": dict(ATTESTATIONS),
        }
        if profile is not None:
            release["profile"] = profile
        return {
            "_run_root": root,
            "release": release,
            "capsule_manager": {"enabled": False, "require_for_release": False},
        }

    def _run(self, cfg):
        report = FakeReport()
        with patch.object(s14_release_gate, "_required_prior_level_ids", return_value=[]):
            s14_release_gate.run(cfg, report)
        return report

    def test_standard_release_is_default_and_does_not_block_on_incident_attestations(self):
        with tempfile.TemporaryDirectory() as td:
            report = self._run(self._cfg(td))
        self.assertEqual(report.by_id("release.profile")["verdict"], "PASS")
        self.assertEqual(
            report.by_id("release.profile")["evidence"]["profile"],
            "standard_release",
        )
        self.assertEqual(
            report.by_id("release.incident_recovery.attestations")["verdict"],
            "SKIP",
        )
        self.assertEqual(report.by_id("release.security_gate")["verdict"], "PASS")

    def test_incident_recovery_blocks_when_attestations_are_missing(self):
        with tempfile.TemporaryDirectory() as td:
            report = self._run(self._cfg(td, "incident_recovery"))
        self.assertEqual(
            report.by_id("release.incident_recovery.attestations")["verdict"],
            "BLOCKED",
        )
        self.assertEqual(report.by_id("release.security_gate")["verdict"], "BLOCKED")

    def test_incident_recovery_passes_when_all_attestations_are_true(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(td, "incident_recovery")
            cfg["release"]["attestations"] = {k: True for k in ATTESTATIONS}
            report = self._run(cfg)
        self.assertEqual(
            report.by_id("release.incident_recovery.attestations")["verdict"],
            "PASS",
        )
        self.assertEqual(report.by_id("release.security_gate")["verdict"], "PASS")

    def test_invalid_profile_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            report = self._run(self._cfg(td, "anything_goes"))
        self.assertEqual(report.by_id("release.profile")["verdict"], "CONFIG_ERROR")
        self.assertEqual(report.by_id("release.security_gate")["verdict"], "FAIL")

    def test_incident_attestations_can_be_explicitly_disabled(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(td, "incident_recovery")
            cfg["release"]["require_attestations"] = False
            report = self._run(cfg)
        self.assertEqual(
            report.by_id("release.incident_recovery.attestations")["verdict"],
            "WARN",
        )
        self.assertEqual(report.by_id("release.security_gate")["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
