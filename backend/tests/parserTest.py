from backend.parser import parse_email

example = """From: support@paypa1-security.example
To: user@example.com
Subject: Urgent: Your account has been restricted!

Dear Customer,

We detected unusual activity on your account. Your account has been temporarily restricted.

Please verify your identity within 24 hours to avoid permanent suspension.

Verify your account here:
http://paypa1-login.example.test/verify

Thank you,
Security Team
"""

example2 = """From: support@paypa1-security.example
To: user@example.com
Subject: ""

Dear Customer,

We detected unusual activity on your account. Your account has been temporarily restricted.

Please verify your identity within 24 hours to avoid permanent suspension.

Verify your account here:

Thank you,
Security Team
"""

example3 = """From: support@paypa1-security.example
To: user@example.com

Dear Customer,

We detected unusual activity on your account. Your account has been temporarily restricted.

Please verify your identity within 24 hours to avoid permanent suspension.

Verify your account here:
https://hi.org, https://goodbye.com

Thank you,
Security Team
"""

def test_sender():
    result = parse_email(example)
    assert result["sender"] == "support@paypa1-security.example"

def test_recipient():
    result = parse_email(example)
    assert result["recipient"] == "user@example.com" 

def test_subject():
    result = parse_email(example)
    assert result["subject"] == "Urgent: Your account has been restricted!"

def test_urls():
    result = parse_email(example)
    assert result["urls"] == ["http://paypa1-login.example.test/verify"]

def test_body():
    result = parse_email(example)
    assert result["body"] == """Dear Customer,

We detected unusual activity on your account. Your account has been temporarily restricted.

Please verify your identity within 24 hours to avoid permanent suspension.

Verify your account here:
http://paypa1-login.example.test/verify

Thank you,
Security Team"""    

def test_missing_subject():
    result = parse_email(example2)
    assert result["subject"] == '""'

def test_missing_urls():
    result = parse_email(example2)
    assert result["urls"] == []

def test_multiple_urls():
    result = parse_email(example3)
    assert result["urls"] == ["https://hi.org", "https://goodbye.com"]