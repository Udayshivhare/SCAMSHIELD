import json
import os
from datetime import datetime


HISTORY_FILE = os.path.join(
    "storage",
    "analysis_history.json"
)


def save_result(result):
    history = load_history()

    record = {
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "input_type": result.input_type,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "scam_type": result.scam_type,
        "indicators": result.indicators,
        "recommended_actions": result.recommended_actions
    }

    history.append(record)

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history,
            file,
            indent=4,
            ensure_ascii=False
        )


def load_history():

    if not os.path.exists(HISTORY_FILE):
        return []

    try:

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):

        return []


def clear_history():

    if os.path.exists(HISTORY_FILE):

        os.remove(HISTORY_FILE)