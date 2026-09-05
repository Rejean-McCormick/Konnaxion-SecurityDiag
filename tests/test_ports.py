import unittest
from levels.s07_firewall_ports import extract_ports

class PortTests(unittest.TestCase):
    def test_public_and_loopback(self):
        text='''__SS__
LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*
LISTEN 0 4096 [::]:6379 [::]:*
__UFW__
Status: active
'''
        rows=extract_ports(text)
        by_port={r["port"]:r for r in rows}
        self.assertTrue(by_port[443]["public_bind"])
        self.assertFalse(by_port[3000]["public_bind"])
        self.assertTrue(by_port[6379]["public_bind"])

if __name__=="__main__":
    unittest.main()
