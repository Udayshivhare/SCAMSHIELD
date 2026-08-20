# 🛡️ SCAMSHIELD

## Digital Scam Intelligence Engine

SCAMSHIELD is a Python-based cybersecurity prototype designed to analyze suspicious digital content and identify potential scam patterns.

It combines multiple detection modules, risk scoring, attack-chain analysis, analysis history, and a Streamlit dashboard into one application.

---

## 🎯 Problem Statement

Digital scams can arrive through many channels, including:

- SMS
- OTP requests
- Suspicious URLs
- PDF documents
- QR codes
- Emails
- Phone-call transcripts

SCAMSHIELD aims to analyze these different inputs and provide a simple risk assessment to help users recognize potentially fraudulent activity.

---

## 🚀 Features

### Multi-Channel Detection

SCAMSHIELD currently supports:

- 📱 SMS Detection
- 🔐 OTP Detection
- 🔗 URL Detection
- 📄 PDF Detection
- 🔳 QR Detection
- 📧 Email Detection
- 📞 Call Transcript Detection

### 🧠 Risk Engine

The Risk Engine combines detection evidence and produces:

- Risk Score
- Risk Level
- Scam Type
- Suspicious Indicators
- Recommended Actions
- Explainable Risk Assessment

Risk levels currently include:

| Score | Risk Level |
|---:|---|
| 0–29 | LOW |
| 30–59 | SUSPICIOUS |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

---

## 🔗 Attack Chain Intelligence

SCAMSHIELD can correlate multiple suspicious events during the same analysis session.

Example:

```text
SMS
 ↓
OTP
 ↓
Attack Chain