from __future__ import annotations

import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOADER = SourceFileLoader("securitydiag_launcher_test_module", str(ROOT / "SecurityDiagLauncher.pyw"))
SPEC = spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
LAUNCHER = module_from_spec(SPEC)
LOADER.exec_module(LAUNCHER)


class LauncherTests(unittest.TestCase):
    def test_host_is_default_gui_campaign(self):
        self.assertEqual(LAUNCHER.CAMPAIGNS[0], ("Host VPS", "host"))

    def test_build_run_command_preserves_fail_fast(self):
        command = LAUNCHER.build_command("run", "external", True)
        self.assertEqual(command[-3:], ["run", "external", "--fail-fast"])

    def test_evidence_path_is_detected(self):
        match = LAUNCHER.EVIDENCE_RE.search(r"SecurityDiag host - PASS\nEvidence: C:\Konnaxion\.securitydiag\runs\abc\n".replace("\\n", "\n"))
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), r"C:\Konnaxion\.securitydiag\runs\abc")


if __name__ == "__main__":
    unittest.main()
