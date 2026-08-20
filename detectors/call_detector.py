from intelligence.scam_result import ScamResult


def analyze_call(transcript):
    transcript_lower = transcript.lower()

    indicators = []
    recommended_actions = []
    risk_score = 0

    impersonation_words = [
        "bank",
        "police",
        "cyber crime",
        "government",
        "rbi",
        "income tax",
        "court",
        "customs",
        "courier",
        "electricity department"
    ]

    urgency_words = [
        "immediately",
        "urgent",
        "right now",
        "within 10 minutes",
        "within 24 hours",
        "do not disconnect",
        "last warning"
    ]

    financial_words = [
        "payment",
        "transfer money",
        "bank account",
        "upi",
        "card",
        "refund",
        "transaction"
    ]

    credential_words = [
        "otp",
        "pin",
        "password",
        "cvv",
        "card number",
        "verification code"
    ]

    threat_words = [
        "arrest",
        "legal action",
        "case will be filed",
        "account will be blocked",
        "account will be frozen",
        "fine",
        "penalty"
    ]

    # Impersonation detection
    for word in impersonation_words:
        if word in transcript_lower:
            indicators.append(
                f"Possible impersonation of authority/organization: {word}"
            )
            risk_score += 10
            break

    # Urgency detection
    for word in urgency_words:
        if word in transcript_lower:
            indicators.append(
                f"Urgency or pressure tactic: {word}"
            )
            risk_score += 15
            break

    # Financial request detection
    for word in financial_words:
        if word in transcript_lower:
            indicators.append(
                f"Financial context detected: {word}"
            )
            risk_score += 15
            break

    # Credential/OTP request
    for word in credential_words:
        if word in transcript_lower:
            indicators.append(
                f"Sensitive credential request: {word}"
            )
            risk_score += 30

            recommended_actions.append(
                "Never share OTPs, PINs, CVVs, passwords, or verification codes over a call."
            )
            break

    # Threat detection
    for word in threat_words:
        if word in transcript_lower:
            indicators.append(
                f"Threat or intimidation tactic: {word}"
            )
            risk_score += 20

            recommended_actions.append(
                "Do not make decisions under threats or intimidation."
            )
            break

    # Strong combination
    if (
        ("otp" in transcript_lower or "verification code" in transcript_lower)
        and (
            "bank" in transcript_lower
            or "upi" in transcript_lower
            or "payment" in transcript_lower
        )
    ):
        indicators.append(
            "OTP request combined with financial context"
        )
        risk_score += 25

    risk_score = min(risk_score, 100)

    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "LOW"

    if risk_score >= 50:
        scam_type = "Potential Phone/Call Scam"
    else:
        scam_type = "No Strong Call Scam Indicator"

    if not recommended_actions:
        recommended_actions.append(
            "Verify the caller independently before taking any action."
        )

    recommended_actions.append(
        "Do not share financial or identity information with an unknown caller."
    )

    return ScamResult(
        input_type="CALL",
        risk_score=risk_score,
        risk_level=risk_level,
        scam_type=scam_type,
        indicators=indicators,
        recommended_actions=list(dict.fromkeys(recommended_actions))
    )