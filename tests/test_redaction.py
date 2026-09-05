import unittest
from securitydiag_core.util import redact

class RedactionTests(unittest.TestCase):
    def test_secret_assignment_redacted(self):
        value="DJANGO_SECRET_KEY=abcdefghijklmnopqrstuvwxyz123456"
        out=redact(value)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456",out)
        self.assertIn("<REDACTED>",out)

    def test_github_token_redacted(self):
        token="ghp_"+"A"*30
        self.assertNotIn(token,redact(token))

if __name__=="__main__":
    unittest.main()
