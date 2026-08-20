import unittest

from detectors.sms_detector import analyze_sms
from detectors.otp_detector import analyze_otp_message
from detectors.url_detector import analyze_url


class TestScamShieldDetectors(unittest.TestCase):

    def test_sms_detector(self):

        message = (
            "URGENT: Your bank account will be blocked. "
            "Verify your KYC immediately."
        )

        result = analyze_sms(message)

        self.assertIsNotNone(result)

        self.assertIsInstance(
            result.risk_score,
            (int, float)
        )

        self.assertGreaterEqual(
            result.risk_score,
            0
        )

        self.assertLessEqual(
            result.risk_score,
            100
        )


    def test_otp_detector(self):

        message = (
            "Your bank verification OTP is 482913. "
            "Share this OTP immediately to complete KYC."
        )

        result = analyze_otp_message(message)

        self.assertIsNotNone(result)

        self.assertIsInstance(
            result.risk_score,
            (int, float)
        )

        self.assertGreaterEqual(
            result.risk_score,
            0
        )

        self.assertLessEqual(
            result.risk_score,
            100
        )


    def test_url_detector(self):

        url = (
            "http://secure-kyc-verify.example.com/login"
        )

        result = analyze_url(url)

        self.assertIsNotNone(result)

        self.assertIsInstance(
            result.risk_score,
            (int, float)
        )

        self.assertGreaterEqual(
            result.risk_score,
            0
        )

        self.assertLessEqual(
            result.risk_score,
            100
        )


if __name__ == "__main__":
    unittest.main()