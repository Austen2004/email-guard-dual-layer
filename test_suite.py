"""
Automated Test Suite for DualShield Email Guard.
Validates detection, layer coordination, and enforcement actions.
"""

import sys
import unittest
from layer1_traditional import TraditionalRuleEngine
from layer2_ml import MLEmailClassifier
from fusion_engine import DualShieldFusionEngine
from sample_emails import SAMPLE_EMAILS

class TestDualShieldDefense(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fusion = DualShieldFusionEngine()
        cls.samples = {s["id"]: s for s in SAMPLE_EMAILS}

    def test_phishing_paypal_blocked(self):
        """Phishing email with spoofed sender and raw IP link must be BLOCKED."""
        sample = self.samples["sample_phish_paypal"]
        verdict = self.fusion.inspect_email(sample)
        
        self.assertEqual(verdict.action, "BLOCKED")
        self.assertIn(verdict.threat_level, ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(verdict.layer1_report["score"], 50)
        self.assertGreaterEqual(verdict.layer2_report["spam_probability"], 0.70)
        self.assertIsNotNone(verdict.user_notification)

    def test_malware_attachment_blocked(self):
        """Double extension executable attachment (.pdf.exe) must trigger hard block."""
        sample = self.samples["sample_malware_invoice"]
        verdict = self.fusion.inspect_email(sample)
        
        self.assertEqual(verdict.action, "BLOCKED")
        self.assertTrue(verdict.layer1_report["is_hard_block"])
        self.assertIn("RULE_DOUBLE_EXTENSION", [r["rule_id"] for r in verdict.layer1_report["triggered_rules"]])

    def test_ceo_fraud_blocked_or_flagged(self):
        """CEO Fraud wire transfer with reply-to discrepancy must not pass cleanly."""
        sample = self.samples["sample_ceo_fraud"]
        verdict = self.fusion.inspect_email(sample)
        
        self.assertIn(verdict.action, ["BLOCKED", "NOTIFIED"])
        self.assertNotEqual(verdict.action, "ALLOWED")

    def test_crypto_scam_blocked(self):
        """Crypto giveaway scam must be recognized as spam/scam."""
        sample = self.samples["sample_crypto_scam"]
        verdict = self.fusion.inspect_email(sample)
        
        self.assertEqual(verdict.action, "BLOCKED")
        self.assertGreaterEqual(verdict.layer2_report["spam_probability"], 0.70)

    def test_marketing_borderline_flagged_with_notification(self):
        """Aggressive marketing with shorteners and high caps must trigger warning NOTIFIED."""
        sample = self.samples["sample_marketing_borderline"]
        verdict = self.fusion.inspect_email(sample)
        
        # Borderline should be either NOTIFIED or BLOCKED, never silent clean ALLOWED
        self.assertIn(verdict.action, ["NOTIFIED", "BLOCKED"])
        self.assertIsNotNone(verdict.user_notification)
        self.assertIsNotNone(verdict.injected_banner_html)

    def test_unverified_vendor_notified(self):
        """Unverified external sender with failed DKIM/SPF must be NOTIFIED with warning banner."""
        sample = self.samples["sample_unverified_vendor"]
        verdict = self.fusion.inspect_email(sample)
        
        self.assertEqual(verdict.action, "NOTIFIED")
        self.assertEqual(verdict.threat_level, "SUSPICIOUS")
        self.assertIsNotNone(verdict.user_notification)
        self.assertIsNotNone(verdict.injected_banner_html)

    def test_legitimate_google_docs_allowed(self):
        """Legitimate Google Docs email from genuine domain with passing SPF/DKIM must be ALLOWED."""
        sample = self.samples["sample_legit_google_docs"]
        verdict = self.fusion.inspect_email(sample)
        
        self.assertEqual(verdict.action, "ALLOWED")
        self.assertEqual(verdict.threat_level, "SAFE")
        self.assertLess(verdict.layer1_report["score"], 30)
        self.assertLess(verdict.layer2_report["spam_probability"], 0.40)

    def test_legitimate_work_meeting_allowed(self):
        """Legitimate internal team meeting email must be ALLOWED."""
        sample = self.samples["sample_legit_work_meeting"]
        verdict = self.fusion.inspect_email(sample)
        
        self.assertEqual(verdict.action, "ALLOWED")
        self.assertEqual(verdict.threat_level, "SAFE")

    def test_legitimate_github_pr_allowed(self):
        """Legitimate GitHub PR notification must be ALLOWED."""
        sample = self.samples["sample_legit_github_pr"]
        verdict = self.fusion.inspect_email(sample)
        
        self.assertEqual(verdict.action, "ALLOWED")
        self.assertEqual(verdict.threat_level, "SAFE")

    def test_legitimate_stripe_receipt_allowed(self):
        """Legitimate Stripe payment receipt must be ALLOWED."""
        sample = self.samples["sample_legit_stripe_receipt"]
        verdict = self.fusion.inspect_email(sample)
        
        self.assertEqual(verdict.action, "ALLOWED")
        self.assertEqual(verdict.threat_level, "SAFE")

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestDualShieldDefense)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
