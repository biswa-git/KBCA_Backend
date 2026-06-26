import os
import json
import urllib.request
from dotenv import load_dotenv

load_dotenv()

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
# Resend requires verified domains for production. 
# "onboarding@resend.dev" only works for sending to your own email.
# You can add SENDER_EMAIL to your Render env vars once you verify your custom domain.
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "onboarding@resend.dev")

def send_resend_email(to_email: str, subject: str, html: str, email_label: str):
    if not RESEND_API_KEY:
        print(f"Warning: RESEND_API_KEY not set. Cannot send {email_label}.", flush=True)
        return

    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "KBCA-App/1.0"
    }
    
    data = {
        "from": f"KBCA <{SENDER_EMAIL}>",
        "to": [to_email],
        "subject": subject,
        "html": html
    }

    try:
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req) as response:  # nosec B310
            response.read()
            print(f"{email_label} successfully sent via Resend to {to_email}!", flush=True)
    except Exception as e:
        print(f"Error sending {email_label} via Resend: {e}", flush=True)
        if hasattr(e, 'read'):
            print(f"Resend error details: {e.read().decode('utf-8')}", flush=True)


def send_otp_email(to_email: str, otp: str):
    subject = "Your KBCA Account Verification Code"
    body = f"""
    <html>
      <body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #c9a763;">কোন্ডাপুর বাঙালি সাংস্কৃতিক সংঘ</h2>
          <p>Your one-time password (OTP) for account verification is:</p>
          <div style="font-size: 24px; font-weight: bold; padding: 10px; background-color: #f5f5f5; border-radius: 5px; text-align: center; letter-spacing: 5px;">
            {otp}
          </div>
          <p>This code will expire in 10 minutes.</p>
          <p>If you did not request this code, please ignore this email.</p>
        </div>
      </body>
    </html>
    """
    send_resend_email(to_email, subject, body, "OTP email")


def send_password_reset_email(to_email: str, reset_link: str, reset_token: str):
    subject = "Reset Your KBCA Account Password"
    body = f"""
    <html>
      <body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #c9a763;">কোন্ডাপুর বাঙালি সাংস্কৃতিক সংঘ</h2>
          <p>We received a request to reset the password for your KBCA account.</p>
          <p>Click the button below to go to the password reset page. This reset token will expire in <strong>15 minutes</strong>.</p>
          <div style="text-align: center; margin: 32px 0;">
            <a href="{reset_link}"
               style="background-color: #c9a763; color: #0a0a0a; padding: 14px 32px;
                      text-decoration: none; font-weight: bold; font-size: 14px;
                      letter-spacing: 1px; display: inline-block;">
              RESET PASSWORD
            </a>
          </div>
          <p style="color: #888; font-size: 13px;">
            Your reset token is:<br/>
            <strong style="font-size: 16px; letter-spacing: 2px;">{reset_token}</strong>
          </p>
          <p style="color: #888; font-size: 13px; margin-top: 16px;">
            Enter this token on the reset page to complete your password change.
          </p>
          <p style="color: #888; font-size: 13px;">
            If you did not request a password reset, please ignore this email.
            Your password will not be changed.
          </p>
        </div>
      </body>
    </html>
    """
    send_resend_email(to_email, subject, body, "password reset email")
