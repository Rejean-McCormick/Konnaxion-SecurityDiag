import os
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile

from levels.s04_app_production import _django_check_environment, run


class _Report:
    def __init__(self):
        self.findings = []

    def add(self, finding_id, verdict, category, message, **kwargs):
        self.findings.append({
            "id": finding_id,
            "verdict": verdict,
            "category": category,
            "message": message,
            **kwargs,
        })

class DjangoCheckEnvironmentTests(unittest.TestCase):
    def test_environment_is_merged_without_mutating_process(self):
        original = os.environ.get("SECURITYDIAG_PARENT_TEST")
        with patch.dict(os.environ, {"SECURITYDIAG_PARENT_TEST": "parent"}, clear=False):
            cfg = {"environment": {"DJANGO_SECRET_KEY": "synthetic-value"}}
            env = _django_check_environment(cfg)
            self.assertEqual(env["SECURITYDIAG_PARENT_TEST"], "parent")
            self.assertEqual(env["DJANGO_SECRET_KEY"], "synthetic-value")
            self.assertNotEqual(os.environ.get("DJANGO_SECRET_KEY"), "synthetic-value")
        self.assertEqual(os.environ.get("SECURITYDIAG_PARENT_TEST"), original)

    def test_environment_must_be_mapping(self):
        with self.assertRaises(ValueError):
            _django_check_environment({"environment": ["DJANGO_SECRET_KEY=value"]})

    def test_environment_values_must_be_strings(self):
        with self.assertRaises(ValueError):
            _django_check_environment({"environment": {"PORT": 8000}})

    @patch("levels.s04_app_production._check_common_auth_contract")
    @patch("levels.s04_app_production.run_command")
    def test_run_passes_merged_environment_to_command(self, run_command, _auth):
        run_command.return_value = {
            "exit_code": 0,
            "stdout_tail": "",
            "stderr_tail": "",
        }
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            prod = root / "backend/config/settings/production.py"
            prod.parent.mkdir(parents=True, exist_ok=True)
            prod.write_text(
                'SECRET_KEY = env("DJANGO_SECRET_KEY")\n'
                'ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS")\n'
                'SECURE_SSL_REDIRECT = True\n'
                'SESSION_COOKIE_SECURE = True\n'
                'CSRF_COOKIE_SECURE = True\n'
                'SECURE_HSTS_SECONDS = 60\n',
                encoding="utf-8",
            )
            compose = root / "backend/docker-compose.production.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            report = _Report()
            cfg = {
                "_target_root": str(root),
                "phase": "production",
                "application": {
                    "django_check": {
                        "enabled": True,
                        "command": ["python", "manage.py", "check", "--deploy"],
                        "cwd": "backend",
                        "environment": {"DJANGO_SECRET_KEY": "synthetic-value"},
                    }
                },
                "remote": {},
            }
            with patch.dict(os.environ, {"SECURITYDIAG_PARENT_TEST": "parent"}, clear=False):
                run(cfg, report)

            kwargs = run_command.call_args.kwargs
            self.assertEqual(kwargs["env"]["DJANGO_SECRET_KEY"], "synthetic-value")
            self.assertEqual(kwargs["env"]["SECURITYDIAG_PARENT_TEST"], "parent")
            finding = next(x for x in report.findings if x["id"] == "app.django.check_deploy")
            self.assertEqual(finding["verdict"], "PASS")
            self.assertEqual(
                finding["evidence"]["configured_environment_keys"],
                ["DJANGO_SECRET_KEY"],
            )


if __name__ == "__main__":
    unittest.main()
