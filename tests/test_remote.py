import unittest
from unittest.mock import patch
from securitydiag_core.remote import remote_ready, run_script, ssh_argv

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

    def test_ssh_disables_tty(self):
        cfg={"execution":{"allow_network":True},"remote":{"enabled":True,"host":"example.com","user":"deploy"}}
        with patch("securitydiag_core.remote.shutil.which", return_value="ssh"):
            self.assertIn("-T", ssh_argv(cfg))

    def test_run_script_sends_lf_only_bytes(self):
        cfg={"execution":{"allow_network":True},"remote":{"enabled":True,"host":"example.com","user":"deploy"}}
        fake=type("CP",(),{"returncode":0,"stdout":b"OK\n","stderr":b""})()
        captured={}
        def runner(argv, **kwargs):
            captured.update(kwargs)
            return fake
        with patch("securitydiag_core.remote.shutil.which", return_value="ssh"), \
             patch("securitydiag_core.remote.subprocess.run", side_effect=runner):
            result=run_script(cfg,"echo one\r\necho two\r\n")
        self.assertEqual(result["exit_code"],0)
        self.assertIsInstance(captured["input"],bytes)
        self.assertNotIn(b"\r",captured["input"])
        self.assertEqual(captured["input"],b"echo one\necho two\n")

    def test_root_privileged_does_not_require_sudo(self):
        cfg={"execution":{"allow_network":True},"remote":{"enabled":True,"host":"example.com","user":"root","sudo_mode":"none"}}
        fake=type("CP",(),{"returncode":0,"stdout":b"OK\n","stderr":b""})()
        captured={}
        def runner(argv, **kwargs):
            captured["argv"]=argv
            return fake
        with patch("securitydiag_core.remote.shutil.which", return_value="ssh"), \
             patch("securitydiag_core.remote.subprocess.run", side_effect=runner):
            result=run_script(cfg,"id\n",privileged=True)
        self.assertEqual(result["exit_code"],0)
        self.assertEqual(captured["argv"][-1],"bash -s")

if __name__=="__main__":
    unittest.main()
