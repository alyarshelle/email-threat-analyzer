from .parser import parse_email
from .detector import detect_phishing
from .scoring import assess_email_risk


def analyze_email(raw_email):
    parsed_email = parse_email(raw_email)
    findings = detect_phishing(parsed_email)
    risk = assess_email_risk(findings)

    return {
        "parsed_email": parsed_email,
        "findings": findings,
        "risk_assessment": risk
    }

raw_email = """\
From: security@company-support.com
To: employee@company.com
Subject: Urgent: Account Verification Required
Date: Thu, 5 Nov 2026 10:30:00 -0500

Dear Employee,

We have detected unusual activity on your account.

Your account will be suspended unless you verify your identity immediately.

Please confirm your account credentials within 24 hours to avoid losing access.

Thank you,
IT Security Department
"""
print(analyze_email(raw_email))