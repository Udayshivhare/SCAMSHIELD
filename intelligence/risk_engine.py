from intelligence.scam_result import ScamResult


class RiskEngine:

    def calculate_final_risk(self, results):

        if not results:

            return ScamResult(
                input_type="UNKNOWN",
                risk_score=0,
                risk_level="LOW",
                scam_type="No Analysis",
                indicators=[],
                recommended_actions=[
                    "No suspicious input was provided."
                ],
                explanation=[
                    "No suspicious input was provided."
                ]
            )

        total_score = 0
        indicators = []
        recommended_actions = []
        scam_types = []

        # ==========================================
        # COLLECT EVIDENCE
        # ==========================================

        for result in results:

            total_score += result.risk_score

            for indicator in result.indicators:

                if indicator not in indicators:
                    indicators.append(indicator)

            if result.scam_type:

                if result.scam_type not in scam_types:
                    scam_types.append(result.scam_type)

            for action in result.recommended_actions:

                if action not in recommended_actions:
                    recommended_actions.append(action)

        # ==========================================
        # EVIDENCE BONUS
        # ==========================================

        indicator_bonus = min(
            len(indicators) * 3,
            15
        )

        source_bonus = min(
            len(results) * 5,
            15
        )

        final_score = (
            total_score
            + indicator_bonus
            + source_bonus
        )

        final_score = min(
            final_score,
            100
        )

        # ==========================================
        # RISK LEVEL
        # ==========================================

        if final_score >= 80:

            risk_level = "CRITICAL"

        elif final_score >= 60:

            risk_level = "HIGH"

        elif final_score >= 30:

            risk_level = "SUSPICIOUS"

        else:

            risk_level = "LOW"

        # ==========================================
        # SCAM TYPE
        # ==========================================

        if final_score >= 80:

            scam_type = (
                "High-Confidence Scam Pattern"
            )

        elif final_score >= 60:

            scam_type = (
                "Likely Scam Pattern"
            )

        elif scam_types:

            scam_type = scam_types[0]

        else:

            scam_type = (
                "No Strong Scam Indicator"
            )

        # ==========================================
        # EXPLANATION
        # ==========================================

        explanation = []

        if indicators:

            explanation.append(
                f"{len(indicators)} suspicious "
                "indicator(s) were detected."
            )

        if len(results) > 1:

            explanation.append(
                f"{len(results)} different analysis "
                "source(s) contributed to the assessment."
            )

        if final_score >= 80:

            explanation.append(
                "The combined evidence indicates a "
                "high-confidence scam pattern."
            )

        elif final_score >= 60:

            explanation.append(
                "The evidence indicates a likely scam "
                "and should be treated as high risk."
            )

        elif final_score >= 30:

            explanation.append(
                "The evidence contains suspicious "
                "signals that require verification."
            )

        else:

            explanation.append(
                "No strong scam pattern was identified."
            )

        # ==========================================
        # RECOMMENDED ACTIONS
        # ==========================================

        if final_score >= 60:

            actions = [
                (
                    "Do not share passwords, OTPs, PINs, "
                    "CVVs, or other sensitive information."
                ),
                (
                    "Verify the request through the "
                    "organization's official website "
                    "or official contact channel."
                )
            ]

            for action in actions:

                if action not in recommended_actions:
                    recommended_actions.append(action)

        elif final_score >= 30:

            action = (
                "Treat this communication with caution "
                "and verify it through an official channel."
            )

            if action not in recommended_actions:

                recommended_actions.append(action)

        # ==========================================
        # FINAL RESULT
        # ==========================================

        return ScamResult(
            input_type="MULTI-SOURCE",
            risk_score=final_score,
            risk_level=risk_level,
            scam_type=scam_type,
            indicators=indicators,
            recommended_actions=recommended_actions,
            explanation=explanation
        )