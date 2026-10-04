import os

path = 'backend/tests/test_email_integration.py'
with open(path, 'r') as f:
    t = f.read()

t = t.replace('gmail_service.send_gmail', 'email_service.send_email')
t = t.replace('GMAIL_DEMO_RECIPIENT', 'BREVO_DEMO_RECIPIENT')
t = t.replace('EMAIL_PROVIDER"] = "gmail"', 'EMAIL_PROVIDER"] = "brevo"')
t = t.replace('test_gmail_adapter', 'test_brevo_adapter')
t = t.replace('test_block_gmail', 'test_block_brevo')
t = t.replace('test_ask_human_gmail', 'test_ask_human_brevo')
t = t.replace('test_deny_human_gmail', 'test_deny_human_brevo')
t = t.replace('Gmail API', 'brevo API')
t = t.replace('"provider": "gmail"', '"provider": "brevo"')
t = t.replace('gmail_api', 'email_api')

with open(path, 'w') as f:
    f.write(t)
