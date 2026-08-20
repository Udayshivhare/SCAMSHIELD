from intelligence.scam_result import ScamResult


def analyze_sms(message):
    message_lower = message.lower()

    indicators = []
    recommended_actions = []
    risk_score = 0

    scam_keywords = [
        "otp",
        "verify",
        "kyc",
        "account blocked",
        "account suspended",
        "click here",
        "urgent",
        "immediately",
        "payment",
        "refund",
        "prize",
        "lottery"
    ]

    for keyword in scam_keywords:
        if keyword in message_lower:
            indicators.append(f"Suspicious keyword: {keyword}")
            risk_score += 10

    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "LOW"

    if "otp" in message_lower:
        recommended_actions.append("Never share your OTP with anyone.")

    if "click here" in message_lower:
        recommended_actions.append("Do not click the link before verifying the sender.")

    if "kyc" in message_lower:
        recommended_actions.append("Verify KYC requests through the organization's official website.")

    if not recommended_actions:
        recommended_actions.append("Verify the message and sender before taking any action.")

    if risk_score >= 50:
        scam_type = "Potential SMS Scam"
    else:
        scam_type = "No Strong Scam Indicator"

    return ScamResult(
        input_type="SMS",
        risk_score=min(risk_score, 100),
        risk_level=risk_level,
        scam_type=scam_type,
        indicators=indicators,
        recommended_actions=recommended_actions
    )