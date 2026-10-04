import os
import urllib.request
import urllib.error
import json
from typing import Dict, Any

def send_email(to: str, subject: str, body: str) -> Dict[str, Any]:
    provider = os.environ.get("EMAIL_PROVIDER", "mock").lower()

    if provider == "mock":
        return _send_mock(to, subject, body)
    elif provider == "brevo":
        return _send_brevo(to, subject, body)
    elif provider in ("smtp", "gmail"):
        return _send_smtp(to, subject, body)
    else:
        # Fallback to mock
        return _send_mock(to, subject, body)


def _send_smtp(to: str, subject: str, body: str) -> Dict[str, Any]:
    """Send transactional email via standard Python smtplib (Gmail / Custom SMTP)."""
    import smtplib
    import uuid
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    user = os.environ.get("GMAIL_USER") or os.environ.get("SMTP_USER") or os.environ.get("BREVO_SENDER_EMAIL")
    password = (os.environ.get("GMAIL_APP_PASSWORD") or os.environ.get("SMTP_PASSWORD") or "").replace(" ", "")
    host = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "587"))

    if not user or not password:
        return {
            "success": False,
            "provider": "smtp",
            "api_called": False,
            "error": "GMAIL_USER (or SMTP_USER) and GMAIL_APP_PASSWORD (or SMTP_PASSWORD) must be set in .env"
        }

    try:
        msg = MIMEMultipart()
        msg["From"] = user
        msg["To"] = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        server = smtplib.SMTP(host, port, timeout=15)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(user, password)
        server.send_message(msg)
        server.quit()

        msg_id = f"smtp-{uuid.uuid4()}"
        return {
            "success": True,
            "provider": "smtp",
            "api_called": True,
            "message_id": msg_id,
            "recipient": to[:3] + "***" + to[to.find("@"):] if "@" in to else to
        }
    except Exception as e:
        return {
            "success": False,
            "provider": "smtp",
            "api_called": True,
            "error": f"SMTP Error: {str(e)}"
        }


def _send_mock(to: str, subject: str, body: str) -> Dict[str, Any]:
    import uuid
    return {
        "success": True,
        "provider": "mock",
        "api_called": False,
        "message_id": f"mock-{uuid.uuid4()}",
        "recipient": to
    }


def _send_brevo(to: str, subject: str, body: str) -> Dict[str, Any]:
    api_key = os.environ.get("BREVO_API_KEY")
    sender_email = os.environ.get("BREVO_SENDER_EMAIL")
    sender_name = os.environ.get("BREVO_SENDER_NAME", "SentinelGate")

    if not api_key or not sender_email:
        return {
            "success": False,
            "provider": "brevo",
            "api_called": False,
            "error": "BREVO_API_KEY or BREVO_SENDER_EMAIL is not set in environment variables."
        }

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }
    
    payload = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": to}],
        "subject": subject,
        "htmlContent": f"<html><body><p>{body}</p></body></html>",
        "textContent": body
    }

    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode('utf-8')
            res_json = json.loads(res_body)
            message_id = res_json.get("messageId")
            
            return {
                "success": True,
                "provider": "brevo",
                "api_called": True,
                "message_id": message_id,
                "recipient": to[:3] + "***" + to[to.find("@"):] if "@" in to else to
            }
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode('utf-8')
        try:
            error_json = json.loads(error_msg)
            sanitized_error = error_json.get("message", "Unknown API error")
        except:
            sanitized_error = str(e)

        return {
            "success": False,
            "provider": "brevo",
            "api_called": True,
            "error": sanitized_error
        }
    except Exception as e:
        return {
            "success": False,
            "provider": "brevo",
            "api_called": True,
            "error": str(e)
        }

if __name__ == "__main__":
    print(send_email("test@example.com", "Test", "Test body"))
