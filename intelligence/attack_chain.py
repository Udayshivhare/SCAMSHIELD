class AttackChain:

    def __init__(self):
        self.events = []

    def add_event(self, event_type, description):
        event = {
            "type": event_type,
            "description": description
        }

        self.events.append(event)

    def get_events(self):
        return self.events

    def analyze_chain(self):
        event_types = [
            event["type"]
            for event in self.events
        ]

        indicators = []
        risk_score = 0

        # SMS → PDF → URL
        if (
            "SMS" in event_types
            and "PDF" in event_types
            and "URL" in event_types
        ):
            indicators.append(
                "SMS → PDF → URL attack pattern detected"
            )
            risk_score += 30

        # SMS → OTP
        if (
            "SMS" in event_types
            and "OTP" in event_types
        ):
            indicators.append(
                "SMS → OTP attack pattern detected"
            )
            risk_score += 30

        # PDF → URL → OTP
        if (
            "PDF" in event_types
            and "URL" in event_types
            and "OTP" in event_types
        ):
            indicators.append(
                "PDF → URL → OTP attack pattern detected"
            )
            risk_score += 40

        # Full multi-stage pattern
        if (
            "SMS" in event_types
            and "PDF" in event_types
            and "URL" in event_types
            and "OTP" in event_types
        ):
            indicators.append(
                "Multi-stage scam attack chain detected"
            )
            risk_score += 50

        risk_score = min(risk_score, 100)

        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "LOW"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
            "events": self.events
        }