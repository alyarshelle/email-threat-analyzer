from backend.analyzer import analyze_email

def test_analyze_email():
    result = analyze_email(raw_email)

    assert "parsed_email" in result
    assert "findings" in result
    assert "risk_assessment" in result

    assert result["parsed_email"]["sender"] == "security@company-support.com"
    assert result["parsed_email"]["subject"] == "Urgent: Account Verification Required"

    assert len(result["findings"]) > 0

    assert result["risk_assessment"]["risk_score"] > 0
    assert result["risk_assessment"]["risk_level"] in {
        "Low", "Medium", "High", "Critical"
    }

def test_analyze_email2():
    result = analyze_email(raw_email2)

    assert result["findings"] == []
    assert result["risk_assessment"]["risk_score"] == 0
    assert result["risk_assessment"]["risk_level"] == "Low"

def test_email_without_subject():
    raw_email = """\
        From: colleague@company.com
        To: employee@company.com

        Hi,

        Just checking in about the project update.

        Thanks!
    """

    result = analyze_email(raw_email)

    assert result["parsed_email"]["subject"] == ""
    assert result["findings"] == []
    assert result["risk_assessment"]["risk_score"] == 0

def test_empty_email():
    result = analyze_email('""')

    assert result["parsed_email"]["sender"] == ''
    assert result["parsed_email"]["recipient"] == ''
    assert result["parsed_email"]["subject"] == ''
    assert result["parsed_email"]["body"] == '""'
    assert result["parsed_email"]["urls"] == []
    assert result["findings"] == []
    assert result["risk_assessment"]["risk_score"] == 0
    assert result["risk_assessment"]["risk_level"] == "Low"

def test_email_with_multiple_urls():
    raw_email = """\
        From: colleague@company.com
        To: employee@company.com
        Subject: Useful resources

        Here are two resources:
        https://example.com
        https://example.org
    """

    result = analyze_email(raw_email)

    urls = result["parsed_email"]["urls"]

    assert len(urls) == 2
    assert "https://example.com" in urls
    assert "https://example.org" in urls

def test_html_email():
    raw_email = """\
        From: colleague@company.com
        To: employee@company.com
        Subject: HTML email
        Content-Type: text/html

        <html>
        <body>
        <h1>Hello</h1>
        <p>This is an HTML email.</p>
        </body>
        </html>
    """

    result = analyze_email(raw_email)

    body = result["parsed_email"]["body"]

    assert "Hello" in body
    assert "This is an HTML email." in body

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

raw_email2 = """\
From: colleague@company.com
To: employee@company.com
Subject: Team lunch

Hi,

Just confirming that we're meeting for lunch tomorrow at noon.

See you then!
"""