from intelligence.unified_analyzer import UnifiedAnalyzer


analyzer = UnifiedAnalyzer()


# -----------------------------
# Test 1: Suspicious SMS
# -----------------------------

sms_message = """
URGENT: Your bank account will be blocked.
Verify your KYC immediately.
Do not delay.
"""

sms_result = analyzer.analyze_sms(sms_message)


# -----------------------------
# Test 2: OTP
# -----------------------------

otp_message = """
Your bank verification OTP is 482913.
Never share this OTP with anyone.
"""

otp_result = analyzer.analyze_otp(otp_message)


# -----------------------------
# Test 3: Suspicious URL
# -----------------------------

url = "http://secure-kyc-verify.example.com/login"

url_result = analyzer.analyze_url(url)


# -----------------------------
# Display individual results
# -----------------------------

print("\n========================================")
print("       SCAMSHIELD DETECTOR RESULTS")
print("========================================")

print("\nSMS")
print(f"Risk Score: {sms_result.risk_score}/100")
print(f"Risk Level: {sms_result.risk_level}")

print("\nOTP")
print(f"Risk Score: {otp_result.risk_score}/100")
print(f"Risk Level: {otp_result.risk_level}")

print("\nURL")
print(f"Risk Score: {url_result.risk_score}/100")
print(f"Risk Level: {url_result.risk_level}")


# -----------------------------
# Attack Chain
# -----------------------------

attack_result = analyzer.get_attack_chain()


print("\n========================================")
print("       SCAMSHIELD ATTACK CHAIN")
print("========================================")

print(f"Risk Score: {attack_result['risk_score']}/100")
print(f"Risk Level: {attack_result['risk_level']}")

print("\nAttack Indicators:")

for indicator in attack_result["indicators"]:
    print(f"- {indicator}")

print("\nEvents:")

for event in attack_result["events"]:
    print(
        f"- {event['type']}: "
        f"{event['description']}"
    )