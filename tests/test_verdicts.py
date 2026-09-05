import unittest
from securitydiag_core.verdicts import worst, campaign_verdict, exit_code, level_verdict

class VerdictTests(unittest.TestCase):
    def test_worst(self):
        self.assertEqual(worst(["PASS","WARN"]),"WARN")
        self.assertEqual(worst(["WARN","FAIL"]),"FAIL")

    def test_required_blocked_blocks_campaign(self):
        rows=[{"level_id":"S00","verdict":"PASS"},{"level_id":"S01","verdict":"BLOCKED"}]
        self.assertEqual(campaign_verdict(rows,{"S00":True,"S01":True}),"BLOCKED")

    def test_optional_skip_does_not_hide_pass(self):
        findings=[{"verdict":"PASS"},{"verdict":"SKIP"}]
        self.assertEqual(level_verdict(findings),"PASS")

    def test_fail_is_fail(self):
        rows=[{"level_id":"S00","verdict":"FAIL"}]
        self.assertEqual(campaign_verdict(rows,{"S00":True}),"FAIL")
        self.assertEqual(exit_code("FAIL"),10)

if __name__=="__main__":
    unittest.main()
