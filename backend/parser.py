from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlparse
import re


class EmailBodyHTMLParser(HTMLParser):
    """Extract readable text and links from an HTML email."""

    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.urls = []

    def handle_data(self, data):
        text = data.strip()
        if text:
            self.text_parts.append(text)

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            attributes = dict(attrs)
            href = attributes.get("href")
            if href:
                self.urls.append(href)


def extract_urls(text):
    """Find HTTP and HTTPS URLs in plain-text email content."""

    pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(pattern, text, flags=re.IGNORECASE)

    # Remove common trailing punctuation.
    return list(dict.fromkeys(
        url.rstrip(".,;:!?)]}") for url in urls
    ))


def parse_email(raw_email):
    """
    Accept a complete raw email and return normalized email data.
    This function does not determine whether an email is malicious.
    """

    if not isinstance(raw_email, str) or not raw_email.strip():
        raise ValueError("Email input must be a non-empty string.")

    message = Parser(policy=policy.default).parsestr(raw_email)

    sender = parseaddr(message.get("From", ""))[1]
    recipient = parseaddr(message.get("To", ""))[1]
    subject = message.get("Subject", "")
    date = message.get("Date", "")

    plain_text_parts = []
    html_parts = []
    html_urls = []

    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            continue

        if content_type == "text/plain":
            plain_text_parts.append(content)

        elif content_type == "text/html":
            html_parser = EmailBodyHTMLParser()
            html_parser.feed(content)

            html_parts.append(" ".join(html_parser.text_parts))
            html_urls.extend(html_parser.urls)

    # Prefer plain text when available; otherwise use HTML text.
    if plain_text_parts:
        body = "\n".join(plain_text_parts).strip()
    else:
        body = "\n".join(html_parts).strip()

    body = unescape(body)

    urls = list(dict.fromkeys(
        extract_urls(body) + html_urls
    ))

    return {
        "sender": sender,
        "recipient": recipient,
        "subject": str(subject),
        "date": str(date),
        "body": body,
        "urls": urls,
    }
