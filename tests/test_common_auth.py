import tempfile
import unittest
from pathlib import Path

from levels.s04_app_production import _check_common_auth_contract


class _Report:
    def __init__(self):
        self.findings = []

    def add(self, finding_id, verdict, category, message, **kwargs):
        item = {
            "id": finding_id,
            "verdict": verdict,
            "category": category,
            "message": message,
            **kwargs,
        }
        self.findings.append(item)
        return item


class CommonAuthSecurityTests(unittest.TestCase):
    def test_common_auth_contract_passes_for_expected_shape(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for rel in (
                "backend/config/settings",
                "backend/konnaxion/users",
                "backend/requirements",
                "frontend",
            ):
                (root / rel).mkdir(parents=True, exist_ok=True)

            (root / "backend/config/settings/base.py").write_text(
                '\n'.join([
                    '"allauth.socialaccount.providers.openid_connect",',
                    'COMMON_OIDC_ENABLED = env.bool("COMMON_OIDC_ENABLED", default=False)',
                    'SOCIALACCOUNT_ONLY = False',
                    'SOCIALACCOUNT_EMAIL_AUTHENTICATION = False',
                    'SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = False',
                    'SOCIALACCOUNT_PROVIDERS["openid_connect"] = {"APPS": [{"settings": {"uid_field": "sub"}}]}',
                ]),
                encoding="utf-8",
            )
            (root / "backend/config/settings/production.py").write_text(
                'CSRF_COOKIE_SECURE = True\n'
                'CSRF_COOKIE_HTTPONLY = False\n'
                'CSRF_COOKIE_NAME = "csrftoken"\n'
                'DJANGO_ADMIN_FORCE_ALLAUTH = True\n',
                encoding="utf-8",
            )
            (root / "backend/config/urls.py").write_text(
                'path("accounts/", include("allauth.urls"))\n',
                encoding="utf-8",
            )
            (root / "backend/konnaxion/users/models.py").write_text(
                'def can_interactive_login(self): pass\n',
                encoding="utf-8",
            )
            (root / "backend/konnaxion/users/adapters.py").write_text(
                'x = user.can_interactive_login\n',
                encoding="utf-8",
            )
            (root / "backend/requirements/base.txt").write_text(
                'django-allauth[mfa,socialaccount]==65.9.0\n',
                encoding="utf-8",
            )
            (root / "frontend/env.production.example").write_text(
                'NEXT_PUBLIC_API_BASE=/api\n',
                encoding="utf-8",
            )
            (root / "frontend/package.json").write_text(
                '{"dependencies": {}}\n',
                encoding="utf-8",
            )

            report = _Report()
            cfg = {"application": {}}
            _check_common_auth_contract(cfg, report, root, cfg["application"])
            verdicts = {x["id"]: x["verdict"] for x in report.findings}

            self.assertEqual(verdicts["app.auth.oidc_capability"], "PASS")
            self.assertEqual(verdicts["app.auth.local_login_preserved"], "PASS")
            self.assertEqual(verdicts["app.auth.no_email_auto_link"], "PASS")
            self.assertEqual(verdicts["app.auth.accounts_route"], "PASS")
            self.assertEqual(verdicts["app.auth.legacy_drf_token_endpoint"], "PASS")
            self.assertEqual(verdicts["app.auth.interactive_account_policy"], "PASS")
            self.assertEqual(verdicts["app.auth.browser_csrf_contract"], "PASS")
            self.assertEqual(verdicts["app.auth.admin_allauth"], "PASS")
            self.assertEqual(verdicts["app.auth.same_origin_api"], "PASS")
            self.assertEqual(verdicts["app.auth.oidc_dependencies"], "PASS")
            self.assertEqual(verdicts["app.auth.legacy_auth0_residue"], "PASS")


if __name__ == "__main__":
    unittest.main()
