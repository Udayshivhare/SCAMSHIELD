import os
import tempfile

import streamlit as st

from intelligence.unified_analyzer import UnifiedAnalyzer
from storage.history import save_result, load_history, clear_history


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="SCAMSHIELD",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# SESSION STATE
# ==========================================

if "analyzer" not in st.session_state:
    st.session_state.analyzer = UnifiedAnalyzer()

analyzer = st.session_state.analyzer


# ==========================================
# LOAD HISTORY
# ==========================================

history = load_history()


# ==========================================
# HEADER
# ==========================================

st.title("🛡️ SCAMSHIELD")

st.subheader(
    "Digital Scam Intelligence Engine"
)

st.write(
    "Analyze suspicious digital content and identify "
    "possible scam patterns using multiple detection layers."
)


# ==========================================
# DASHBOARD
# ==========================================

st.divider()

st.header("📊 Security Dashboard")

total_analyses = len(history)

high_risk = sum(
    1 for record in history
    if record["risk_level"] == "HIGH"
)

critical_risk = sum(
    1 for record in history
    if record["risk_level"] == "CRITICAL"
)

suspicious_risk = sum(
    1 for record in history
    if record["risk_level"] == "SUSPICIOUS"
)


col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Total Analyses",
        total_analyses
    )

with col2:
    st.metric(
        "Suspicious",
        suspicious_risk
    )

with col3:
    st.metric(
        "High Risk",
        high_risk
    )

with col4:
    st.metric(
        "Critical",
        critical_risk
    )


# ==========================================
# RISK DISTRIBUTION
# ==========================================

if history:

    st.subheader("📈 Risk Distribution")

    chart_data = {
        "LOW": sum(
            1 for record in history
            if record["risk_level"] == "LOW"
        ),
        "SUSPICIOUS": suspicious_risk,
        "HIGH": high_risk,
        "CRITICAL": critical_risk
    }

    st.bar_chart(chart_data)

# ==========================================
# RISK SUMMARY
# ==========================================

if history:

    st.subheader("🧠 Latest Detection")

    latest = history[-1]

    col1, col2, col3 = st.columns(3)

    with col1:
        st.write("**Input Type**")
        st.write(latest["input_type"])

    with col2:
        st.write("**Risk Level**")
        st.write(latest["risk_level"])

    with col3:
        st.write("**Risk Score**")
        st.write(
            f"{latest['risk_score']}/100"
        )

    st.write(
        f"**Scam Type:** {latest['scam_type']}"
    )


# ==========================================
# SIDEBAR
# ==========================================

with st.sidebar:

    st.header("🛡️ SCAMSHIELD")

    st.write("Detection Modules")

    st.write("📱 SMS")
    st.write("🔐 OTP")
    st.write("🔗 URL")
    st.write("📄 PDF")
    st.write("🔳 QR")
    st.write("📧 Email")
    st.write("📞 Call")

    st.divider()

    if st.button("🗑️ Clear Attack Chain"):

        st.session_state.analyzer = UnifiedAnalyzer()

        st.rerun()

    if st.button("🧹 Clear Analysis History"):

        clear_history()

        st.success(
            "Analysis history cleared."
        )

        st.rerun()


# ==========================================
# RESULT DISPLAY
# ==========================================

def display_result(result):

    save_result(result)

    st.divider()

    st.subheader("🔍 Analysis Result")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Risk Score",
            f"{result.risk_score}/100"
        )

    with col2:
        st.metric(
            "Risk Level",
            result.risk_level
        )

    with col3:
        st.metric(
            "Scam Type",
            result.scam_type
        )

    st.subheader("🧠 Why SCAMSHIELD Flagged This")

    if  result.explanation:

      for reason in result.explanation:
        st.write(f"• {reason}")

    else:

      st.write(
        "No additional explanation is available."
    )  

    st.subheader("⚠️ Indicators")

    if result.indicators:

        for indicator in result.indicators:
            st.warning(indicator)

    else:

        st.success(
            "No suspicious indicators detected."
        )

    st.subheader("🛡️ Recommended Actions")

    for action in result.recommended_actions:
        st.info(action)


# ==========================================
# INPUT TYPE
# ==========================================

input_type = st.selectbox(
    "What do you want to analyze?",
    [
        "SMS",
        "OTP",
        "URL",
        "PDF",
        "QR",
        "EMAIL",
        "CALL"
    ]
)


# ==========================================
# SMS
# ==========================================

if input_type == "SMS":

    message = st.text_area(
        "Paste the suspicious SMS",
        height=200,
        placeholder="Example: Your bank account will be blocked..."
    )

    if st.button("🔍 Analyze SMS"):

        if message.strip():

            result = analyzer.analyze_sms(message)

            display_result(result)

        else:

            st.warning(
                "Please enter an SMS message first."
            )


# ==========================================
# OTP
# ==========================================

elif input_type == "OTP":

    message = st.text_area(
        "Paste the OTP-related message",
        height=200,
        placeholder="Example: Your verification OTP is..."
    )

    if st.button("🔍 Analyze OTP"):

        if message.strip():

            result = analyzer.analyze_otp(message)

            display_result(result)

        else:

            st.warning(
                "Please enter an OTP-related message first."
            )


# ==========================================
# URL
# ==========================================

elif input_type == "URL":

    url = st.text_input(
        "Enter the suspicious URL",
        placeholder="https://example.com"
    )

    if st.button("🔍 Analyze URL"):

        if url.strip():

            result = analyzer.analyze_url(url)

            display_result(result)

        else:

            st.warning(
                "Please enter a URL first."
            )


# ==========================================
# PDF
# ==========================================

elif input_type == "PDF":

    uploaded_file = st.file_uploader(
        "Upload a suspicious PDF",
        type=["pdf"]
    )

    if st.button("🔍 Analyze PDF"):

        if uploaded_file is not None:

            suffix = ".pdf"

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=suffix
            ) as temp_file:

                temp_file.write(
                    uploaded_file.getbuffer()
                )

                file_path = temp_file.name

            try:

                result = analyzer.analyze_pdf(
                    file_path
                )

                display_result(result)

            finally:

                if os.path.exists(file_path):
                    os.remove(file_path)

        else:

            st.warning(
                "Please upload a PDF first."
            )


# ==========================================
# QR
# ==========================================

elif input_type == "QR":

    uploaded_file = st.file_uploader(
        "Upload a QR code image",
        type=["png", "jpg", "jpeg"]
    )

    if st.button("🔍 Analyze QR"):

        if uploaded_file is not None:

            extension = os.path.splitext(
                uploaded_file.name
            )[1]

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=extension
            ) as temp_file:

                temp_file.write(
                    uploaded_file.getbuffer()
                )

                file_path = temp_file.name

            try:

                result = analyzer.analyze_qr(
                    file_path
                )

                display_result(result)

            finally:

                if os.path.exists(file_path):
                    os.remove(file_path)

        else:

            st.warning(
                "Please upload a QR image first."
            )


# ==========================================
# EMAIL
# ==========================================

elif input_type == "EMAIL":

    sender = st.text_input(
        "Sender email",
        placeholder="sender@example.com"
    )

    subject = st.text_input(
        "Email subject"
    )

    body = st.text_area(
        "Email body",
        height=200
    )

    if st.button("🔍 Analyze Email"):

        if subject.strip() or body.strip():

            result = analyzer.analyze_email(
                subject,
                body,
                sender
            )

            display_result(result)

        else:

            st.warning(
                "Please enter the email content."
            )


# ==========================================
# CALL
# ==========================================

elif input_type == "CALL":

    transcript = st.text_area(
        "Paste the call transcript",
        height=250,
        placeholder="Paste a call transcript here..."
    )

    if st.button("🔍 Analyze Call"):

        if transcript.strip():

            result = analyzer.analyze_call(
                transcript
            )

            display_result(result)

        else:

            st.warning(
                "Please enter a call transcript first."
            )


# ==========================================
# ATTACK CHAIN
# ==========================================

st.divider()

st.header("🔗 Attack Chain Intelligence")

attack_result = analyzer.get_attack_chain()


if attack_result["events"]:

    col1, col2 = st.columns(2)

    with col1:

        st.metric(
            "Chain Risk Score",
            f"{attack_result['risk_score']}/100"
        )

    with col2:

        st.metric(
            "Chain Risk Level",
            attack_result["risk_level"]
        )

    st.subheader("Detected Pattern")

    if attack_result["indicators"]:

        for indicator in attack_result["indicators"]:
            st.error(indicator)

    else:

        st.success(
            "No multi-stage attack pattern detected yet."
        )

    st.subheader("Events")

    for event in attack_result["events"]:

        st.write(
            f"**{event['type']}** → "
            f"{event['description']}"
        )

else:

    st.info(
        "No events analyzed yet. "
        "Start an analysis above."
    )


# ==========================================
# ANALYSIS HISTORY
# ==========================================

st.divider()

st.header("🧾 Analysis History")

history = load_history()

if history:

    st.write(
        f"Total analyses recorded: **{len(history)}**"
    )

    for record in reversed(history[-10:]):

        with st.expander(
            f"{record['input_type']} — "
            f"{record['risk_level']} — "
            f"{record['timestamp']}"
        ):

            st.write(
                f"**Risk Score:** "
                f"{record['risk_score']}/100"
            )

            st.write(
                f"**Scam Type:** "
                f"{record['scam_type']}"
            )

            st.write("**Indicators:**")

            for indicator in record["indicators"]:
                st.write(
                    f"- {indicator}"
                )

            st.write(
                "**Recommended Actions:**"
            )

            for action in record["recommended_actions"]:
                st.write(
                    f"- {action}"
                )

else:

    st.info(
        "No analysis history yet."
    )


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "SCAMSHIELD Prototype — "
    "Always verify suspicious communications "
    "through official channels."
)