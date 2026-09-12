import unittest
from unittest.mock import patch

from levels import s06_ssh, s07_firewall_ports, s10_secret_permissions


class _Report:
    def __init__(self):
        self.findings=[]
        self.metrics={}

    def add(self, finding_id, verdict, category, message, evidence=None, recommendation=None):
        self.findings.append({
            "id": finding_id,
            "verdict": verdict,
            "category": category,
            "message": message,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    def by_id(self, finding_id):
        return next(x for x in self.findings if x["id"] == finding_id)


CFG={
    "phase":"production",
    "execution":{"allow_network":True},
    "remote":{
        "enabled":True,
        "host":"example.com",
        "user":"kx-admin",
        "sudo_mode":"noninteractive",
        "secret_paths":["/opt/app/env/django.env"],
        "allowed_ssh_key_fingerprints":["SHA256:test"],
        "forbidden_public_ports":[3000,5432,6379,8765],
        "require_ufw":True,
    },
}


class NonRootRemoteAuditTests(unittest.TestCase):
    def test_s06_uses_privileged_collection(self):
        result={
            "exit_code":0,
            "timed_out":False,
            "stdout_tail":("permitrootlogin no\npasswordauthentication no\n"
                           "kbdinteractiveauthentication no\npubkeyauthentication yes\n"
                           "allowusers kx-admin\nx11forwarding no\n"
                           "allowtcpforwarding no\nmaxauthtries 3\n"),
            "stderr_tail":"",
        }
        report=_Report()
        with patch("levels.s06_ssh.run_script", return_value=result) as mocked:
            s06_ssh.run(CFG, report)
        self.assertTrue(mocked.call_args.kwargs["privileged"])
        self.assertEqual(report.by_id("ssh.root_login.disabled")["verdict"],"PASS")
        self.assertEqual(report.by_id("ssh.password_auth.disabled")["verdict"],"PASS")

    def test_s07_uses_privileged_collection_and_absolute_ufw_candidates(self):
        result={
            "exit_code":0,
            "timed_out":False,
            "stdout_tail":("__SS__\nLISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
                           "__UFW__\nStatus: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"),
            "stderr_tail":"",
        }
        report=_Report()
        with patch("levels.s07_firewall_ports.run_script", return_value=result) as mocked:
            s07_firewall_ports.run(CFG, report)
        self.assertTrue(mocked.call_args.kwargs["privileged"])
        self.assertIn("/usr/sbin/ufw", s07_firewall_ports.SCRIPT)
        self.assertEqual(report.by_id("network.ufw.active")["verdict"],"PASS")
        self.assertEqual(report.by_id("network.ufw.default_deny_incoming")["verdict"],"PASS")

    def test_s10_keeps_user_ssh_evidence_unprivileged_and_secret_metadata_privileged(self):
        ssh_result={
            "exit_code":0,
            "timed_out":False,
            "stdout_tail":("__SSH_DIR__\n700|kx-admin|kx-admin|/home/kx-admin/.ssh\n"
                           "600|kx-admin|kx-admin|/home/kx-admin/.ssh/authorized_keys\n"
                           "__AUTHORIZED_KEY_FINGERPRINTS__\nSHA256:test\n"),
            "stderr_tail":"",
        }
        secret_result={
            "exit_code":0,
            "timed_out":False,
            "stdout_tail":"__SECRETS__\n600|root|root|/opt/app/env/django.env\n",
            "stderr_tail":"",
        }
        report=_Report()
        with patch("levels.s10_secret_permissions.run_script", side_effect=[ssh_result, secret_result]) as mocked:
            s10_secret_permissions.run(CFG, report)
        first=mocked.call_args_list[0]
        second=mocked.call_args_list[1]
        self.assertFalse(first.kwargs.get("privileged",False))
        self.assertTrue(second.kwargs["privileged"])
        self.assertEqual(report.by_id("secrets.ssh_permissions")["verdict"],"PASS")
        self.assertEqual(report.by_id("secrets.authorized_keys.allowlist")["verdict"],"PASS")
        self.assertEqual(report.by_id("secrets.production_paths")["verdict"],"PASS")

    def test_s10_privileged_secret_metadata_never_reads_file_contents(self):
        ssh_result={"exit_code":0,"timed_out":False,"stdout_tail":"__SSH_DIR__\n__AUTHORIZED_KEY_FINGERPRINTS__\n","stderr_tail":""}
        secret_result={"exit_code":0,"timed_out":False,"stdout_tail":"__SECRETS__\n600|root|root|/opt/app/env/django.env\n","stderr_tail":""}
        report=_Report()
        with patch("levels.s10_secret_permissions.run_script", side_effect=[ssh_result,secret_result]) as mocked:
            s10_secret_permissions.run(CFG, report)
        privileged_script=mocked.call_args_list[1].args[1]
        self.assertIn("stat -Lc", privileged_script)
        self.assertNotIn("cat ", privileged_script)
        self.assertNotIn("head ", privileged_script)


if __name__ == "__main__":
    unittest.main()
