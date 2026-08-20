import unittest

from intelligence.attack_chain import AttackChain
from intelligence.risk_engine import RiskEngine
from intelligence.scam_result import ScamResult


class TestRiskEngine(unittest.TestCase):

    def create_result(self, score, scam_type="Test Scam"):

        return ScamResult(
            input_type="TEST",
            risk_score=score,
            risk_level="SUSPICIOUS",
            scam_type=scam_type,
            indicators=["Test suspicious indicator"],
            recommended_actions=["Verify through an official channel."]
        )


    def test_empty_results(self):

        engine = RiskEngine()

        result = engine.calculate_final_risk([])

        self.assertEqual(
            result.risk_score,
            0
        )

        self.assertEqual(
            result.risk_level,
            "LOW"
        )


    def test_risk_score_never_exceeds_100(self):

        engine = RiskEngine()

        results = [
            self.create_result(90),
            self.create_result(90)
        ]

        result = engine.calculate_final_risk(
            results
        )

        self.assertLessEqual(
            result.risk_score,
            100
        )


    def test_suspicious_risk_level(self):

        engine = RiskEngine()

        results = [
            self.create_result(30)
        ]

        result = engine.calculate_final_risk(
            results
        )

        self.assertEqual(
            result.risk_level,
            "SUSPICIOUS"
        )


class TestAttackChain(unittest.TestCase):

    def test_sms_otp_chain(self):

        chain = AttackChain()

        chain.add_event(
            "SMS",
            "SMS message analyzed"
        )

        chain.add_event(
            "OTP",
            "OTP-related message analyzed"
        )

        result = chain.analyze_chain()

        self.assertGreater(
            result["risk_score"],
            0
        )

        self.assertEqual(
            result["risk_level"],
            "SUSPICIOUS"
        )


    def test_empty_attack_chain(self):

        chain = AttackChain()

        result = chain.analyze_chain()

        self.assertEqual(
            result["risk_score"],
            0
        )

        self.assertEqual(
            result["risk_level"],
            "LOW"
        )


if __name__ == "__main__":
    unittest.main()