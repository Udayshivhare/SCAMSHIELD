from intelligence.scam_result import ScamResult


def analyze_email(subject, body, sender=""):
    indicators = []
    recommended_actions = []
    risk_score = 0

    text = f"{subject} {body}".lower()
    sender_lower = sender.lower()

    suspicious_phrases = [
        "urgent",
        "immediately",
        "account blocked",
        "account suspended",
        "verify your account",
        "kyc",
        "payment",
        "refund",
        "prize",
        "winner",
        "claim now",
        "click here",
        "otp",
        "password",
        "bank",
        "challan"
    ]

    for phrase in suspicious_phrases:
        if phrase in text:
            indicators.append(
                f"Suspicious email phrase: {phrase}"
            )
            risk_score += 8

    # Detect common financial/scam combinations
    if "otp" in text and (
        "bank" in text
        or "payment" in text
        or "transaction" in text
    ):
        indicators.append(
            "OTP request combined with financial context"
        )
        risk_score += 25

        recommended_actions.append(
            "Never share an OTP through email or with another person."
        )

    if "password" in text or "login" in text:
        indicators.append(
            "Email requests account credentials or login action"
        )
        risk_score += 20

        recommended_actions.append(
            "Do not enter your password through an email link."
        )

    if "click here" in text:
        indicators.append(
            "Email contains a call-to-action to click a link"
        )
        risk_score += 15

        recommended_actions.append(
            "Do not click links until the sender is verified."
        )

    # Basic sender checks
    if sender_lower:
        if "gmail.com" in sender_lower or "yahoo.com" in sender_lower:
            indicators.append(
                "Sender uses a general email provider"
            )
            risk_score += 5

    if not sender:
        indicators.append(
            "Sender information was not provided"
        )

    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "LOW"

    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        scam_type = "Potential Phishing Email"
    else:
        scam_type = "No Strong Email Scam Indicator"

    if not recommended_actions:
        recommended_actions.append(
            "Verify the sender and message through an official channel."
        )

    return ScamResult(
        input_type="EMAIL",
        risk_score=risk_score,
        risk_level=risk_level,
        scam_type=scam_type,
        indicators=indicators,
        recommended_actions=recommended_actions
    )