import logging
import os
import json
import urllib.request
from html import escape
from urllib.parse import quote
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
# Resend requires verified domains for production. 
# "onboarding@resend.dev" only works for sending to your own email.
# You can add SENDER_EMAIL to your Render env vars once you verify your custom domain.
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "onboarding@resend.dev")

def send_resend_email(to_email: str, subject: str, html: str, email_label: str):
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set. Cannot send %s.", email_label)
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
            logger.info("%s successfully sent via Resend to %s.", email_label, to_email)
    except Exception as e:
        logger.exception("Error sending %s via Resend: %s", email_label, e)
        if hasattr(e, 'read'):
            logger.error("Resend error details: %s", e.read().decode('utf-8'))


def _html(value) -> str:
    return escape(str(value), quote=True)


def _build_qr_code_url(value: str, size: int = 320) -> str:
    encoded_value = quote(str(value), safe='')
    return f"https://api.qrserver.com/v1/create-qr-code/?size={size}x{size}&data={encoded_value}&margin=2&ecc=M&format=png&bgcolor=ffffff&color=000000"


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


def send_password_reset_email(to_email: str, reset_link: str):
    subject = "Reset Your KBCA Account Password"
    body = f"""
    <html>
      <body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #c9a763;">কোন্ডাপুর বাঙালি সাংস্কৃতিক সংঘ</h2>
          <p>We received a request to reset the password for your KBCA account.</p>
          <p>Click the button below to go to the password reset page. This reset token will expire in <strong>15 minutes</strong>.</p>
          <div style="text-align: center; margin: 32px 0;">
            <a href="{_html(reset_link)}"
               style="background-color: #c9a763; color: #0a0a0a; padding: 14px 32px;
                      text-decoration: none; font-weight: bold; font-size: 14px;
                      letter-spacing: 1px; display: inline-block;">
              RESET PASSWORD
            </a>
          </div>
          <p style="color: #888; font-size: 13px; margin-top: 16px;">
            Use the button above to continue with the password reset process.
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


def send_registration_confirmation_email(
    to_email: str,
    full_name: str,
    adults: int,
    children_6_12: int,
    children_under_6: int,
    amount_paid: float,
    muhurat_code: str | None = None,
):
    subject = "KBCA Meetup Registration Confirmation"
    qr_block = ""
    if muhurat_code:
        qr_url = _build_qr_code_url(muhurat_code)
        qr_block = f"""
          <div style="margin: 28px 0; text-align: center;">
            <p style="font-weight: 600; margin-bottom: 12px;">Your registration QR code</p>
            <img src="{_html(qr_url)}" alt="Registration QR Code" style="max-width: 220px; width: 100%; border: 1px solid #e2c27d; border-radius: 12px; padding: 10px; background: #fff;" />
          </div>
        """

    body = f"""
    <html>
      <body>
        <div style="font-family: Arial, sans-serif; max-width: 650px; margin: 0 auto; color: #111;">
          <h2 style="color: #c9a763;">কোন্ডাপুর বাঙালি সাংস্কৃতিক সংঘ</h2>
          <h2 style="color: #0a0a0a;">KBCA Meetup Registration Confirmation</h2>
          <p>Dear {_html(full_name or 'Participant')},</p>
          <p>Thank you for your registration for the upcoming KBCA meetup. This is a formal confirmation of the details associated with your registration and payment.</p>
          <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
            <tr>
              <td style="padding: 10px; border: 1px solid #ccc; font-weight: bold;">Registration Status</td>
              <td style="padding: 10px; border: 1px solid #ccc;">Confirmed</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ccc; font-weight: bold;">Adults</td>
              <td style="padding: 10px; border: 1px solid #ccc;">{_html(adults)}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ccc; font-weight: bold;">Children (6–12 years)</td>
              <td style="padding: 10px; border: 1px solid #ccc;">{_html(children_6_12)}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ccc; font-weight: bold;">Children (Below 6 years)</td>
              <td style="padding: 10px; border: 1px solid #ccc;">{_html(children_under_6)}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ccc; font-weight: bold;">Amount Paid</td>
              <td style="padding: 10px; border: 1px solid #ccc;">₹{amount_paid:.2f}</td>
            </tr>
          </table>
          {qr_block}
          <p style="margin-top: 24px;">We look forward to welcoming you to the event.</p>
          <p>Sincerely,</p>
          <p><strong>KBCA Event Coordination Team</strong></p>
          <p style="color: #555; font-size: 13px;">If you have any questions, please reply to this email or visit the KBCA website.</p>
        </div>
      </body>
    </html>
    """
    send_resend_email(to_email, subject, body, "registration confirmation email")
