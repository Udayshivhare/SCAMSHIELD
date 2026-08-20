import fitz

from intelligence.scam_result import ScamResult
from utils.url_extractor import extract_urls
from detectors.url_detector import analyze_url

def analyze_pdf(file_path):
    indicators = []
    recommended_actions = []
    risk_score = 0

    try:
        document = fitz.open(file_path)

        extracted_text = ""

        for page in document:
            extracted_text += page.get_text()

        document.close()

        text_lower = extracted_text.lower()

        urls_found = extract_urls(extracted_text)

        for url in urls_found:
            url_result = analyze_url(url)

            risk_score += url_result.risk_score

            indicators.append(
                f"URL found in PDF: {url}"
            )

            for indicator in url_result.indicators:
                indicators.append(
                    f"URL indicator: {indicator}"
                )

            for action in url_result.recommended_actions:
                if action not in recommended_actions:
                    recommended_actions.append(action)
        scam_keywords = [
            "otp",
            "kyc",
            "pay immediately",
            "payment",
            "click here",
            "account blocked",
            "account suspended",
            "challan",
            "verify your account",
            "refund",
            "urgent",
            "penalty"
        ]

        for keyword in scam_keywords:
            if keyword in text_lower:
                indicators.append(
                    f"Suspicious PDF keyword: {keyword}"
                )
                risk_score += 10

        if "otp" in text_lower:
            recommended_actions.append(
                "Never share an OTP mentioned in the document."
            )

        if "payment" in text_lower or "pay immediately" in text_lower:
            recommended_actions.append(
                "Do not make a payment based only on the PDF."
            )

        if "challan" in text_lower:
            recommended_actions.append(
                "Verify the challan through the official government portal."
            )

        if "click here" in text_lower:
            recommended_actions.append(
                "Do not click links in the document before verification."
            )

        if not recommended_actions:
            recommended_actions.append(
                "Verify the document and its sender before taking action."
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

        if risk_score >= 50:
            scam_type = "Potential Malicious/Scam PDF"
        else:
            scam_type = "No Strong PDF Scam Indicator"

        return ScamResult(
            input_type="PDF",
            risk_score=risk_score,
            risk_level=risk_level,
            scam_type=scam_type,
            indicators=indicators,
            recommended_actions=recommended_actions
        )

    except Exception as error:
        return ScamResult(
            input_type="PDF",
            risk_score=100,
            risk_level="CRITICAL",
            scam_type="PDF Analysis Failed",
            indicators=[f"Could not safely analyze PDF: {error}"],
            recommended_actions=[
                "Do not open or interact with the document.",
                "Verify the sender through an official channel."
            ]
        )