from intelligence.scam_result import ScamResult


def analyze_otp_message(message):
    message_lower = message.lower()

    indicators = []
    recommended_actions = []
    risk_score = 0

    otp_detected = "otp" in message_lower or "one time password" in message_lower

    otp_request_phrases = [
        "share the otp",
        "tell me the otp",
        "send me the otp",
        "provide the otp",
        "give me the otp",
        "tell us the otp",
        "enter the otp"
    ]

    financial_words = [
        "bank",
        "account",
        "payment",
        "transaction",
        "card",
        "upi",
        "money"
    ]

    urgency_words = [
        "urgent",
        "immediately",
        "right now",
        "within",
        "expire",
        "blocked",
        "suspended"
    ]

    if otp_detected:
        indicators.append("OTP mentioned")
        risk_score += 10

    otp_requested = False

    for phrase in otp_request_phrases:
        if phrase in message_lower:
            otp_requested = True
            indicators.append("OTP sharing/request detected")
            risk_score += 40
            break

    financial_context = False

    for word in financial_words:
        if word in message_lower:
            financial_context = True
            indicators.append(f"Financial context: {word}")
            risk_score += 10
            break

    urgency_detected = False

    for word in urgency_words:
        if word in message_lower:
            urgency_detected = True
            indicators.append(f"Urgency indicator: {word}")
            risk_score += 10
            break

    if otp_requested:
        recommended_actions.append("Never share your OTP with another person.")

    if financial_context:
        recommended_actions.append(
            "Verify the transaction directly through your bank's official channel."
        )

    if urgency_detected:
        recommended_actions.append(
            "Do not act under pressure or urgency."
        )

    if not recommended_actions:
        recommended_actions.append(
            "Never share OTPs, PINs, or passwords with unknown persons."
        )

    risk_score = min(risk_score, 100)

    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "LOW"

    if otp_requested and financial_context:
        scam_type = "Potential OTP Financial Scam"
    elif otp_requested:
        scam_type = "Potential OTP Scam"
    else:
        scam_type = "OTP Mentioned - No Strong Scam Indicator"

    return ScamResult(
        input_type="OTP/SMS",
        risk_score=risk_score,
        risk_level=risk_level,
        scam_type=scam_type,
        indicators=indicators,
        recommended_actions=recommended_actions
    )