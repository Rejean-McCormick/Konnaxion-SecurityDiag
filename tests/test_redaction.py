import unittest
from securitydiag_core.util import redact, redact_data


class RedactionTests(unittest.TestCase):
    def test_secret_assignment_redacted(self):
        value="DJANGO_SECRET_KEY=abcdefghijklmnopqrstuvwxyz123456"
        out=redact(value)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456",out)
        self.assertIn("<REDACTED>",out)

    def test_github_token_redacted(self):
        token="ghp_"+"A"*30
        self.assertNotIn(token,redact(token))

    def test_structured_config_redacts_nested_secret_values(self):
        data={
            "application":{"DJANGO_SECRET_KEY":"super-secret-value"},
            "remote":{"password":"password-value"},
        }
        out=redact_data(data)
        self.assertEqual(out["application"]["DJANGO_SECRET_KEY"],"<REDACTED>")
        self.assertEqual(out["remote"]["password"],"<REDACTED>")

    def test_structured_config_preserves_non_secret_token_path_metadata(self):
        data={
            "capsule_manager":{"agent_token_path":"/opt/konnaxion/manager/agent.token"},
            "repo_security":{"placeholder_tokens":["changeme","example"]},
        }
        out=redact_data(data)
        self.assertEqual(out,data)


if __name__=="__main__":
    unittest.main()
