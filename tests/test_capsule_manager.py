import tempfile
import unittest
from pathlib import Path

from securitydiag_core.capsule_manager import (
    gate_is_release_acceptable,
    inspect_local_policy,
    release_required_gate_checks,
    remote_probe_script,
)


class CapsuleManagerBridgeTests(unittest.TestCase):
    def test_unknown_is_blocking(self):
        ok, detail = gate_is_release_acceptable(
            {"status": "UNKNOWN", "results": []},
            unknown_is_blocking=True,
            required_checks=("capsule_signature",),
        )
        self.assertFalse(ok)
        self.assertEqual(detail["status"], "UNKNOWN")

    def test_complete_pass_is_acceptable(self):
        ok, detail = gate_is_release_acceptable(
            {
                "status": "PASS",
                "results": [
                    {"check": "capsule_signature", "status": "PASS", "blocking": True},
                    {"check": "image_checksums", "status": "PASS", "blocking": True},
                ],
            },
            required_checks=("capsule_signature", "image_checksums"),
        )
        self.assertTrue(ok)
        self.assertEqual(detail["blocking"], [])
        self.assertEqual(detail["missing_required_checks"], [])

    def test_aggregate_pass_with_empty_results_is_rejected(self):
        ok, detail = gate_is_release_acceptable(
            {"status": "PASS", "results": []},
            required_checks=("capsule_signature",),
        )
        self.assertFalse(ok)
        self.assertEqual(detail["missing_required_checks"], ["capsule_signature"])

    def test_missing_required_check_is_rejected(self):
        ok, detail = gate_is_release_acceptable(
            {
                "status": "PASS",
                "results": [{"check": "capsule_signature", "status": "PASS"}],
            },
            required_checks=("capsule_signature", "image_checksums"),
        )
        self.assertFalse(ok)
        self.assertEqual(detail["missing_required_checks"], ["image_checksums"])

    def test_required_skipped_is_rejected(self):
        ok, detail = gate_is_release_acceptable(
            {
                "status": "PASS",
                "results": [{"check": "capsule_signature", "status": "SKIPPED"}],
            },
            required_checks=("capsule_signature",),
        )
        self.assertFalse(ok)
        self.assertEqual(detail["skipped_required_checks"][0]["check"], "capsule_signature")

    def test_required_warn_is_acceptable(self):
        ok, _detail = gate_is_release_acceptable(
            {
                "status": "WARN",
                "results": [{"check": "firewall_enabled", "status": "WARN"}],
            },
            required_checks=("firewall_enabled",),
        )
        self.assertTrue(ok)

    def test_remote_probe_quotes_configured_paths(self):
        cfg = {
            "capsule_manager": {
                "instance_id": "demo-001",
                "agent_token_path": "/opt/konnaxion/manager/agent token;touch /tmp/pwn",
                "audit_path": "/opt/konnaxion/agent/audit/audit log.jsonl",
            }
        }
        script = remote_probe_script(cfg)
        self.assertIn("'/opt/konnaxion/manager/agent token;touch /tmp/pwn'", script)
        self.assertIn("'/opt/konnaxion/agent/audit/audit log.jsonl'", script)

    def test_release_required_checks_cannot_weaken_canonical_baseline(self):
        cfg = {"capsule_manager": {"required_gate_checks": ["capsule_signature"]}}
        with self.assertRaises(ValueError):
            release_required_gate_checks(cfg)

    def test_remote_probe_rejects_unsafe_service_name(self):
        cfg = {
            "capsule_manager": {
                "instance_id": "demo-001",
                "agent_service_name": "kx-agent; touch /tmp/pwn",
            }
        }
        with self.assertRaises(ValueError):
            remote_probe_script(cfg)

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
