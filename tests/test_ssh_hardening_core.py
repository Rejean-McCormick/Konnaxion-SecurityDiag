from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "ssh_hardening_core.py"
SPEC = importlib.util.spec_from_file_location("ssh_hardening_core", MODULE_PATH)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


class SSHHardeningCoreTests(unittest.TestCase):
    def test_dropin_matches_securitydiag_s06_contract(self):
        text = mod.hardening_dropin("kx-admin")
        expected = [
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PubkeyAuthentication yes",
            "AllowUsers kx-admin",
            "X11Forwarding no",
            "AllowTcpForwarding no",
            "MaxAuthTries 3",
        ]
        for line in expected:
            self.assertIn(line, text)

    def test_reserved_user_rejected(self):
        with self.assertRaises(mod.HardeningError):
            mod.validate_admin_user("root")
        with self.assertRaises(mod.HardeningError):
            mod.validate_admin_user("kx-agent")

    def test_config_update_is_narrow_and_backed_up(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "securitydiag.config.local.json"
            original = {
                "schema": "securitydiag.config.v1.1",
                "application": {"keep": True},
                "remote": {
                    "host": "example.test",
                    "user": "root",
                    "identity_file": "C:/keys/id_ed25519",
                    "secret_paths": ["/x"],
                },
            }
            path.write_text(json.dumps(original), encoding="utf-8")
            backup = mod.update_securitydiag_config(path, "kx-admin", mod.DEFAULT_EXPECTED_FINGERPRINT)
            updated = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(backup.exists())
            self.assertEqual(updated["application"], original["application"])
            self.assertEqual(updated["remote"]["secret_paths"], ["/x"])
            self.assertEqual(updated["remote"]["user"], "kx-admin")
            self.assertEqual(updated["remote"]["allowed_sudo_users"], ["kx-admin"])
            self.assertEqual(updated["remote"]["allowed_ssh_key_fingerprints"], [mod.DEFAULT_EXPECTED_FINGERPRINT])

    def test_expected_fingerprint_validation(self):
        self.assertEqual(
            mod.validate_expected_fingerprint(mod.DEFAULT_EXPECTED_FINGERPRINT),
            mod.DEFAULT_EXPECTED_FINGERPRINT,
        )
        with self.assertRaises(mod.HardeningError):
            mod.validate_expected_fingerprint("not-a-fingerprint")


if __name__ == "__main__":
    unittest.main()
