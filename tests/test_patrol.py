import os, tempfile, unittest
from patrol.scan import guard, ScopeError, check_secrets, check_workflows, consent_signals

class T(unittest.TestCase):
    def test_guard(self):
        self.assertEqual(guard("Super"), "fitzyracing1/Super")
        with self.assertRaises(ScopeError):
            guard("torvalds/linux")
    def test_checks(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".github/workflows"))
        open(os.path.join(d, ".github/workflows/a.yml"), "w").write("on: pull_request_target\npermissions: write-all\n")
        open(os.path.join(d, "k.txt"), "w").write("key = AKIA" + "ABCDEFGHIJKLMNOP\n")
        self.assertEqual(len(check_secrets(d)), 1)
        issues = {w["issue"] for w in check_workflows(d)}
        self.assertIn("permissions: write-all", issues)
        self.assertTrue(consent_signals(d)["security_md"] is None)

if __name__ == "__main__":
    unittest.main()
