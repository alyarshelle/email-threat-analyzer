# KEYWORDS FOR DIFFERENT TYPES OF POTENTIAL THREATS
urgency_keywords = {"urgent", "immediately", "within 24 hours"}
threat_keywords = {
    "account suspended", "account will be suspended", "account terminated",
    "account disabled", "access revoked", "access will be denied",
    "permanently closed", "legal action" }
account_keywords = {
    "verify your account", "confirm your identity", "verify your identity",
    "confirm your account", "validate your credentials", "verify your information",
    "update your credentials", "confirm your password", "re-enter your password",
    "account verification required"
}
impersonation_keywords = {
    "i am the ceo", "i am your manager", "this is the IT department",
    "on behalf of the CEO", "this is your HR department", 
    "i am contacting you from IT", "your company administrator", 
    "your system administrator"
}
# dectecotrs -> urgency, therathing language, account verifcaitno, impersonation

def detect_urgency(email):
    words = []
    if email['subject'] and email['body']:
        subjectBody = f"{email['body']} {email['subject']}".lower()
    elif email['subject']:
        subjectBody = email['subject'].lower()
    elif email['body']:
        subjectBody = email['body'].lower()
    else:
        return words

    for uK in urgency_keywords:
        if uK in subjectBody:
            words.append(uK)
    if not words:
        return None
    
    return {
        "category": "phishing",
        "indicator": "urgency",
        "evidence": words,
        "description": "The email uses time pressure to encourage the recipient to take immediate action."
    }

def detect_threats(email):
    words = []
    if email['subject'] and email['body']:
        subjectBody = f"{email['body']} {email['subject']}".lower()
    elif email['subject']:
        subjectBody = email['subject'].lower()
    elif email['body']:
        subjectBody = email['body'].lower()
    else:
        return words

    for uK in threat_keywords:
        if uK in subjectBody:
            words.append(uK)

    if not words:
        return None
    
    return {
        "category": "threat",
        "indicator": "threatening language",
        "evidence": words,
        "description": "The email uses threatening language to encourage the recipient to take immediate action."
    }

def detect_account_verification(email):
    words = []
    if email['subject'] and email['body']:
        subjectBody = f"{email['body']} {email['subject']}".lower()
    elif email['subject']:
        subjectBody = email['subject'].lower()
    elif email['body']:
        subjectBody = email['body'].lower()
    else:
        return words

    for uK in account_keywords:
        if uK in subjectBody:
            words.append(uK)

    if not words:
        return None
    
    return {
        "category": "account verification",
        "indicator": "credential verificaiton",
        "evidence": words,
        "description": "The email uses the word verify your credenitals/account to encourage the recipient to take immediate action."
    }

def detect_impersonation(email):
    words = []
    if email['subject'] and email['body']:
        subjectBody = f"{email['body']} {email['subject']}".lower()
    elif email['subject']:
        subjectBody = email['subject'].lower()
    elif email['body']:
        subjectBody = email['body'].lower()
    else:
        return words

    for uK in impersonation_keywords:
        if uK in subjectBody:
            words.append(uK)

    if not words:
        return None
    
    return {
        "category": "impersonation",
        "indicator": "claimed organizational identity",
        "evidence": words,
        "description": "The email pretends to be apart of the company to encourage the recipient to take immediate action."
    }

email1 = {
    "subject": "URGENT: Account restricted",
    "body": "Please verify your account within 24 hours."
}

email2 = {
    "subject": '""',
    "body": '""'
}

email3 = {
    "subject": "Action required immediately",
    "body": "Please respond within 24 hours."
}

email4 = {
    "subject": "Immediate action required",
    "body": "Your account will be suspended unless you respond within 24 hours."
}

email5 = {
    "subject": "Meeting tomorrow",
    "body": "Just confirming our meeting at 10 AM."
}

email6 = {
    "subject": "Password Confirmation Needed",
    "body": "Your credentials need to be updated. Please confirm your password to complete the process."
}

email7 = {
    "subject": "Confidential Request",
    "body": "I am the CEO of the company. I need you to handle a confidential request on my behalf. Please do not discuss this with anyone else."
}

email8 = {
    "subject": "HR Update",
    "body": "The HR department has published the new holiday schedule."
}

email9 = {
    "subject": "Management Announcement",
    "body": "The CEO will be visiting the office next week."
}

# print(detect_urgency(email4))
# print(detect_urgency(email5))
# print(detect_threats(email4))
# print(detect_threats(email5))

def detect_phishing(email):
    findings = []
    urgency = detect_urgency(email)
    threats = detect_threats(email)
    account = detect_account_verification(email)
    impersonation = detect_impersonation(email)

    if urgency:
        findings.append(urgency)
    if threats:
        findings.append(threats)
    if account:
        findings.append(account)
    if impersonation:
        findings.append(impersonation)

    return findings

# print(detect_phishing(email6))
# print(detect_phishing(email7))
print(detect_phishing(email8))
print(detect_phishing(email9))

# nexst up accoutn verification and impersonation

def detect_suspicious_urls(email):
    pass