import email
from email import policy
from email.parser import BytesParser

def parse_email(file_path):
    """
    Parse .eml email file and return a dict with headers and body
    """
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    parsed = {
        "Subject": msg.get("Subject", ""),
        "From": msg.get("From", ""),
        "To": msg.get("To", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Authentication-Results": msg.get("Authentication-Results", ""),
        "Received": msg.get_all("Received", []),
        "Body": get_email_body(msg)
    }
    return parsed

def get_email_body(msg):
    """
    Extract plain text from email
    """
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
    else:
        return msg.get_payload(decode=True).decode(errors="ignore")
    return ""
