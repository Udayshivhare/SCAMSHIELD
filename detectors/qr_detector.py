import cv2

from intelligence.scam_result import ScamResult


def analyze_qr(image_path):
    indicators = []
    recommended_actions = []
    risk_score = 0

    try:
        image = cv2.imread(image_path)

        if image is None:
            return ScamResult(
                input_type="QR",
                risk_score=100,
                risk_level="CRITICAL",
                scam_type="QR Analysis Failed",
                indicators=["QR image could not be loaded"],
                recommended_actions=[
                    "Do not scan an unknown QR code."
                ]
            )

        detector = cv2.QRCodeDetector()

        decoded_data, points, _ = detector.detectAndDecode(image)

        if not decoded_data:
            return ScamResult(
                input_type="QR",
                risk_score=20,
                risk_level="LOW",
                scam_type="QR Code Not Decoded",
                indicators=["No readable QR content was detected"],
                recommended_actions=[
                    "Do not scan the QR code unless its source is trusted."
                ]
            )

        decoded_lower = decoded_data.lower()

        indicators.append("QR code successfully decoded")

        # URL inside QR
        if decoded_lower.startswith("http://") or decoded_lower.startswith("https://"):
            indicators.append("QR code contains a URL")
            risk_score += 20

        # UPI payment request
        if decoded_lower.startswith("upi://"):
            indicators.append("QR code contains a UPI payment URI")
            risk_score += 20

        # Suspicious payment-related words
        suspicious_words = [
            "payment",
            "pay",
            "collect",
            "upi",
            "verify",
            "refund",
            "cashback",
            "reward"
        ]

        for word in suspicious_words:
            if word in decoded_lower:
                indicators.append(
                    f"QR content contains payment-related keyword: {word}"
                )
                risk_score += 10

        risk_score = min(risk_score, 100)

        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "LOW"

        if decoded_lower.startswith("upi://"):
            scam_type = "Potential QR Payment Scam"
        elif decoded_lower.startswith(("http://", "https://")):
            scam_type = "Potential QR Phishing"
        else:
            scam_type = "QR Content Analysis"

        recommended_actions.append(
            "Verify the QR code source before scanning or making a payment."
        )

        if decoded_lower.startswith("upi://"):
            recommended_actions.append(
                "Check the recipient name and payment details before approving."
            )

        if decoded_lower.startswith(("http://", "https://")):
            recommended_actions.append(
                "Do not enter passwords, OTPs, PINs, or card details on an unknown website."
            )

        return ScamResult(
            input_type="QR",
            risk_score=risk_score,
            risk_level=risk_level,
            scam_type=scam_type,
            indicators=indicators,
            recommended_actions=recommended_actions
        )

    except Exception as error:
        return ScamResult(
            input_type="QR",
            risk_score=100,
            risk_level="CRITICAL",
            scam_type="QR Analysis Failed",
            indicators=[f"Could not safely analyze QR image: {error}"],
            recommended_actions=[
                "Do not scan or interact with the QR code.",
                "Verify the source through an official channel."
            ]
        )