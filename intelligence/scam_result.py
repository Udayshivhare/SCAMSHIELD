class ScamResult:

    def __init__(
        self,
        input_type,
        risk_score,
        risk_level,
        scam_type,
        indicators,
        recommended_actions,
        explanation=None
    ):

        self.input_type = input_type

        self.risk_score = risk_score

        self.risk_level = risk_level

        self.scam_type = scam_type

        self.indicators = indicators

        self.recommended_actions = recommended_actions

        self.explanation = explanation or []