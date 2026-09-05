import tempfile
import unittest
from pathlib import Path

from securitydiag_core.capsule_manager import (
    gate_is_release_acceptable,
    inspect_local_policy,
)

class CapsuleManagerBridgeTests(unittest.TestCase):
    def test_unknown_is_blocking(self):
        ok, detail = gate_is_release_acceptable(
            {"status": "UNKNOWN", "results": []},
            unknown_is_blocking=True,
        )
        self.assertFalse(ok)
        self.assertEqual(detail["status"], "UNKNOWN")

    def test_pass_is_acceptable(self):
        ok, detail = gate_is_release_acceptable(
            {
                "status": "PASS",
                "results": [
                    {"check": "capsule_signature", "status": "PASS"},
                    {"check": "image_checksums", "status": "PASS"},
                ],
            }
        )
        self.assertTrue(ok)
        self.assertEqual(detail["blocking"], [])

    def test_local_policy_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "kx_agent").mkdir()
            (root / "policies").mkdir()
            (root / "kx_agent" / "auth.py").write_text(
                'LOCAL_BIND_HOSTS={"127.0.0.1","::1"}\n'
                'FORBIDDEN_AGENT_OPERATIONS={"shell.exec","docker.run"}\n',
                encoding="utf-8",
            )
            (root / "policies" / "runtime_policy.yaml").write_text(
                "networks:\n  deny_by_default: true\n"
                "container_security:\n"
                "  privileged_allowed: false\n"
                "  host_network_allowed: false\n"
                "  docker_socket_mount_allowed: false\n"
                "  unknown_images_allowed: false\n"
                "  public_temporary_requires_expiration: true\n"
                "enforcement:\n  reject_unsigned_capsules: true\n",
                encoding="utf-8",
            )
            (root / "policies" / "security_gate.yaml").write_text(
                "statuses:\n  - PASS\n  - WARN\n  - FAIL_BLOCKING\n  - UNKNOWN\n"
                "profile_rules:\n  public_temporary:\n    requires_expiration: true\n",
                encoding="utf-8",
            )
            cfg = {
                "capsule_manager": {
                    "policy_files": {
                        "agent_auth": "kx_agent/auth.py",
                        "runtime": "policies/runtime_policy.yaml",
                        "security_gate": "policies/security_gate.yaml",
                    }
                }
            }
            result = inspect_local_policy(root, cfg)
            self.assertTrue(all(result["checks"].values()))

if __name__ == "__main__":
    unittest.main()
