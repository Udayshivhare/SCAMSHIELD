from detectors.sms_detector import analyze_sms
from detectors.otp_detector import analyze_otp_message
from detectors.url_detector import analyze_url
from detectors.pdf_detector import analyze_pdf
from detectors.qr_detector import analyze_qr
from detectors.email_detector import analyze_email
from detectors.call_detector import analyze_call

from intelligence.risk_engine import RiskEngine
from intelligence.attack_chain import AttackChain


class UnifiedAnalyzer:

    def __init__(self):
        self.risk_engine = RiskEngine()
        self.attack_chain = AttackChain()

    def analyze_sms(self, message):
        result = analyze_sms(message)

        self.attack_chain.add_event(
            "SMS",
            "SMS message analyzed"
        )

        return self.risk_engine.calculate_final_risk(
            [result]
        )

    def analyze_otp(self, message):
        result = analyze_otp_message(message)

        self.attack_chain.add_event(
            "OTP",
            "OTP-related message analyzed"
        )

        return self.risk_engine.calculate_final_risk(
            [result]
        )

    def analyze_url(self, url):
        result = analyze_url(url)

        self.attack_chain.add_event(
            "URL",
            "URL analyzed"
        )

        return self.risk_engine.calculate_final_risk(
            [result]
        )

    def analyze_pdf(self, file_path):
        result = analyze_pdf(file_path)

        self.attack_chain.add_event(
            "PDF",
            "PDF document analyzed"
        )

        return self.risk_engine.calculate_final_risk(
            [result]
        )

    def analyze_qr(self, image_path):
        result = analyze_qr(image_path)

        self.attack_chain.add_event(
            "QR",
            "QR code analyzed"
        )

        return self.risk_engine.calculate_final_risk(
            [result]
        )

    def analyze_email(self, subject, body, sender=""):
        result = analyze_email(
            subject,
            body,
            sender
        )

        self.attack_chain.add_event(
            "EMAIL",
            "Email analyzed"
        )

        return self.risk_engine.calculate_final_risk(
            [result]
        )

    def analyze_call(self, transcript):
        result = analyze_call(transcript)

        self.attack_chain.add_event(
            "CALL",
            "Call transcript analyzed"
        )

        return self.risk_engine.calculate_final_risk(
            [result]
        )

    def analyze_multiple(self, results):
        return self.risk_engine.calculate_final_risk(
            results
        )

    def get_attack_chain(self):
        return self.attack_chain.analyze_chain()