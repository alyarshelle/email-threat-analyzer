from parser import *

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

results = parse_email(example)
print(results)