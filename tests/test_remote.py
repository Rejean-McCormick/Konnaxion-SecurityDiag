import unittest
from securitydiag_core.remote import remote_ready

class RemoteTests(unittest.TestCase):
    def test_network_disabled_blocks(self):
        cfg={"execution":{"allow_network":False},"remote":{"enabled":True,"host":"example.com","user":"deploy"}}
        ok,msg=remote_ready(cfg)
        self.assertFalse(ok)
        self.assertIn("Network",msg)

    def test_bad_host_blocks(self):
        cfg={"execution":{"allow_network":True},"remote":{"enabled":True,"host":"x;rm -rf /","user":"deploy"}}
        ok,msg=remote_ready(cfg)
        self.assertFalse(ok)

if __name__=="__main__":
    unittest.main()
