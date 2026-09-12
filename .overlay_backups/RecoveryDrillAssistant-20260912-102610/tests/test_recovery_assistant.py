from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from securitydiag_recovery import core


class RecoveryAssistantTests(unittest.TestCase):
    def test_default_offsite_is_outside_repo_specific(self):
        self.assertIn("KonnaxionRecovery", str(core.default_offsite_dir()))

    def test_release_attestation_keys_are_exact(self):
        self.assertEqual(
            set(core.ATTESTATION_KEYS),
            {
                "fresh_vps",
                "old_disk_not_cloned",
                "all_compromised_secrets_rotated",
                "clean_git_source_only",
                "cloud_firewall_verified",
                "old_vps_retired_or_isolated",
            },
        )

    def test_record_release_attestations_requires_all_true(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "securitydiag.config.local.json").write_text('{"schema":"securitydiag.config.v1.1"}', encoding="utf-8")
            values = {k: True for k in core.ATTESTATION_KEYS}
            values["fresh_vps"] = False
            with self.assertRaises(core.RecoveryError):
                core.record_release_attestations(root, values)

    def test_record_release_attestations_preserves_existing_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / "securitydiag.config.local.json"
            p.write_text(json.dumps({"schema":"securitydiag.config.v1.1", "remote":{"host":"example"}}), encoding="utf-8")
            values = {k: True for k in core.ATTESTATION_KEYS}
            core.record_release_attestations(root, values)
            data = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(data["remote"]["host"], "example")
            self.assertTrue(all(data["release"]["attestations"].values()))
            self.assertTrue((Path.home() / ".securitydiag-recovery" / "config-backups").exists())

    def test_preflight_rejects_offsite_inside_target(self):
        with tempfile.TemporaryDirectory() as td:
            tool = Path(td) / "SecurityDiag"
            target = Path(td) / "Konnaxion"
            tool.mkdir(); target.mkdir()
            cfg = {
                "_target_root": str(target),
                "remote": {
                    "enabled": True,
                    "user": "root",
                    "host": "example",
                    "backup_paths": ["/opt/konnaxion/backups"],
                    "secret_paths": ["/x/django.env", "/x/postgres.env"],
                    "docker": {"allowed_compose_projects": ["proj"]},
                },
                "execution": {"allow_network": True},
            }
            with mock.patch.object(core, "effective_config", return_value=cfg), \
                 mock.patch.object(core, "_require_remote"), \
                 mock.patch.object(core, "discover_runtime", return_value={"postgres":{},"django":{},"redis":{}}):
                with self.assertRaises(core.RecoveryError):
                    core.preflight(tool, target / "Backups")

    def test_safe_remote_path_blocks_shell_metacharacters(self):
        with self.assertRaises(core.RecoveryError):
            core._safe_remote_path("/tmp/a;rm -rf /", "test")


    def test_restore_drill_script_is_internal_only_and_writes_attestation(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tool = base / "SecurityDiag"
            target = base / "Konnaxion"
            offsite = base / "offsite"
            tool.mkdir(); target.mkdir(); offsite.mkdir()
            db = offsite / "database.sql.gz"
            media = offsite / "media.tar.gz"
            db.write_bytes(b"db")
            media.write_bytes(b"media")
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            cfg = {
                "_target_root": str(target),
                "_control_root": str(target / ".securitydiag"),
                "recovery": {},
                "remote": {
                    "user": "kx-admin", "host": "example", "sudo_mode": "noninteractive",
                    "backup_paths": ["/opt/konnaxion/backups"],
                    "secret_paths": ["/opt/konnaxion/env/django.env", "/opt/konnaxion/env/postgres.env"],
                    "docker": {"allowed_compose_projects": ["proj"]},
                },
                "execution": {"allow_network": True},
            }
            pre = {
                "backup_root": "/opt/konnaxion/backups",
                "env_paths": {"django.env": "/opt/konnaxion/env/django.env", "postgres.env": "/opt/konnaxion/env/postgres.env"},
                "services": {
                    "postgres": {"name": "pg", "image_id": "sha256:aaa"},
                    "django": {"name": "dj", "image_id": "sha256:bbb"},
                    "redis": {"name": "rd", "image_id": "sha256:ccc"},
                },
            }
            state = {
                "offsite_copy_verified": True,
                "run_id": "backup-1",
                "files": {
                    "DATABASE": {"local_path": str(db), "sha256": digest(db)},
                    "MEDIA": {"local_path": str(media), "sha256": digest(media)},
                },
            }
            scripts = []
            def fake_remote(_cfg, script, **_kwargs):
                scripts.append(script)
                stdout = ""
                if "NETWORK_INTERNAL|true" in script:
                    stdout = "TABLE_COUNT|50\nMIGRATIONS|100\nUSER_COUNT|3\nMEDIA_FILES|4\nHTTP_STATUS|200\nNETWORK_INTERNAL|true\n"
                return {"exit_code": 0, "timed_out": False, "stdout_tail": stdout, "stderr_tail": ""}
            with mock.patch.object(core, "effective_config", return_value=cfg), \
                 mock.patch.object(core, "_require_remote"), \
                 mock.patch.object(core, "preflight", return_value=pre), \
                 mock.patch.object(core, "load_state", return_value=state), \
                 mock.patch.object(core, "_upload_remote"), \
                 mock.patch.object(core, "_remote_result", side_effect=fake_remote):
                result = core.isolated_restore_drill(tool)
            restore_script = next(x for x in scripts if "NETWORK_INTERNAL|true" in x)
            self.assertIn("docker network create --internal", restore_script)
            self.assertNotIn(" --publish ", restore_script)
            self.assertNotIn(" -p ", restore_script)
            self.assertTrue(Path(result["attestation_path"]).exists())
            att = json.loads(Path(result["attestation_path"]).read_text(encoding="utf-8"))
            self.assertTrue(att["isolated_target"])
            self.assertTrue(att["offsite_copy_verified"])
            if shutil.which("bash"):
                cp = subprocess.run(["bash", "-n"], input=restore_script, text=True, capture_output=True, check=False)
                self.assertEqual(cp.returncode, 0, cp.stderr)


if __name__ == "__main__":
    unittest.main()
