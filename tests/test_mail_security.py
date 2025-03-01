"""
Tests for mail security provider detection.
"""

import unittest
from mail_security.providers import detect_mail_provider, EMAIL_SECURITY_PROVIDERS

class TestMailSecurityProviders(unittest.TestCase):
    def test_proofpoint_detection(self):
        mx_records = [
            ("mx1-us1.ppe-hosted.com", 10),
            ("mx2-us1.ppe-hosted.com", 20)
        ]
        result = detect_mail_provider(mx_records)
        self.assertEqual(len(result["providers"]), 2)
        self.assertEqual(result["providers"][0]["name"], "Proofpoint")
        self.assertFalse(result["multiple_providers"])
        self.assertIsNone(result["security_risk"])

    def test_mixed_provider_detection(self):
        mx_records = [
            ("mx1-us1.ppe-hosted.com", 10),
            ("mx2-us1.ppe-hosted.com", 20),
            ("aspmx.l.google.com", 30)
        ]
        result = detect_mail_provider(mx_records)
        self.assertEqual(len(result["providers"]), 3)
        self.assertTrue(result["multiple_providers"])
        self.assertIsNotNone(result["security_risk"])
        self.assertEqual(result["security_risk"]["risk_level"], "HIGH")

    def test_mimecast_detection(self):
        mx_records = [
            ("us-smtp-inbound-1.mimecast.com", 10),
            ("us-smtp-inbound-2.mimecast.com", 20)
        ]
        result = detect_mail_provider(mx_records)
        self.assertEqual(len(result["providers"]), 2)
        self.assertEqual(result["providers"][0]["name"], "Mimecast")
        self.assertFalse(result["multiple_providers"])
        self.assertIsNone(result["security_risk"])

    def test_google_workspace_detection(self):
        mx_records = [
            ("aspmx.l.google.com", 1),
            ("alt1.aspmx.l.google.com", 5),
            ("alt2.aspmx.l.google.com", 5),
            ("alt3.aspmx.l.google.com", 10),
            ("alt4.aspmx.l.google.com", 10)
        ]
        result = detect_mail_provider(mx_records)
        self.assertEqual(len(result["providers"]), 5)
        self.assertEqual(result["providers"][0]["name"], "Google Workspace")
        self.assertFalse(result["multiple_providers"])
        self.assertIsNone(result["security_risk"])

    def test_microsoft_365_detection(self):
        mx_records = [
            ("example-com.mail.protection.outlook.com", 10)
        ]
        result = detect_mail_provider(mx_records)
        self.assertEqual(len(result["providers"]), 1)
        self.assertEqual(result["providers"][0]["name"], "Microsoft 365")
        self.assertFalse(result["multiple_providers"])
        self.assertIsNone(result["security_risk"])

if __name__ == "__main__":
    unittest.main() 