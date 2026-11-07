# A weak indicator: mentions the IT department.
# A stronger indicator: claims to be IT support and requests credentials.
# A very strong indicator: impersonates IT support, requests credentials, 
# and provides a suspicious login link.

risk_weights = {
    "urgency": 10,
    "threatening language": 15,
    "credential verification": 25,
    "claimed organizational identity": 15
}

findingsExample = [
    {
        "category": "phishing",
        "indicator": "urgency",
        "evidence": ["immediately"],
        "description": "The email uses time pressure."
    },
    {
        "category": "account verification",
        "indicator": "credential verification",
        "evidence": ["verify your account"],
        "description": "The email requests account verification."
    }
]

def calculate_risk(findings):
    risk = 0
    for f in findings:
        risk += risk_weights.get(f['indicator'], 0)
    return min(risk, 100)

# value = calculate_risk(findingsExample)

def get_risk_level(score):
    scores = {
        (0, 19) : "Low",
        (20, 39) : "Medium",
        (40, 69) : "High",
        (70, 100) : "Critical"
    }
    for (start, end), result in scores.items():
        if start <= score <= end:
            return result
# print(get_risk_level(value))

def assess_email_risk(findings):
    value = calculate_risk(findings)
    return {
        "risk_score" : value, 
        "risk_level" : get_risk_level(value)
    }

print(assess_email_risk(findingsExample))