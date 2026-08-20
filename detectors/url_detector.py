from intelligence.scam_result import ScamResult
from urllib.parse import urlparse


def analyze_url(url):
    indicators = []
    recommended_actions = []
    risk_score = 0

    url_lower = url.lower()

    try:
        parsed_url = urlparse(url)

        domain = parsed_url.netloc
        path = parsed_url.path

        if not domain:
            indicators.append("Invalid or incomplete URL")
            risk_score += 30

        # Check whether HTTPS is used
        if parsed_url.scheme != "https":
            indicators.append("URL does not use HTTPS")
            risk_score += 20

        # Check for IP address instead of normal domain
        if domain.replace(".", "").isdigit():
            indicators.append("URL uses an IP address instead of a domain")
            risk_score += 30

        # Suspicious URL words
        suspicious_words = [
            "login",
            "verify",
            "kyc",
            "update",
            "payment",
            "refund",
            "secure",
            "account",
            "otp",
            "challan"
        ]

        for word in suspicious_words:
            if word in url_lower:
                indicators.append(f"Sensitive URL keyword: {word}")
                risk_score += 5

        # URL contains @ symbol
        if "@" in url:
            indicators.append("URL contains suspicious '@' character")
            risk_score += 20

        # Very long URL
        if len(url) > 100:
            indicators.append("Unusually long URL")
            risk_score += 10

        # Too many subdomains
        if domain.count(".") >= 3:
            indicators.append("Unusually complex domain structure")
            risk_score += 15

        # Suspicious domain words
        suspicious_domains = [
            "verify",
            "secure",
            "update",
            "account",
            "payment",
            "support"
        ]

        for word in suspicious_domains:
            if word in domain:
                indicators.append(
                    f"Suspicious domain keyword: {word}"
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

        if risk_score >= 50:
            scam_type = "Potential Phishing URL"
        else:
            scam_type = "No Strong URL Scam Indicator"

        if risk_score >= 50:
            recommended_actions.append(
                "Do not enter passwords, OTPs, PINs, or card details."
            )

        if risk_score >= 50:
            recommended_actions.append(
                "Verify the website through the organization's official website."
            )

        if not recommended_actions:
            recommended_actions.append(
                "Verify the URL and sender before opening it."
            )

        return ScamResult(
            input_type="URL",
            risk_score=risk_score,
            risk_level=risk_level,
            scam_type=scam_type,
            indicators=indicators,
            recommended_actions=recommended_actions
        )

    except Exception:
        return ScamResult(
            input_type="URL",
            risk_score=100,
            risk_level="CRITICAL",
            scam_type="Invalid or Unsafe URL",
            indicators=["URL could not be safely analyzed"],
            recommended_actions=[
                "Do not open the URL.",
                "Verify the source through an official channel."
            ]
        )