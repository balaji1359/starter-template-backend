# Add this to your existing email.py file

import resend
import logging
from app.core.config import settings
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

def send_email(
    to_email: str,
    subject: str,
    html_content: str,
    from_email: Optional[str] = None,
    from_name: Optional[str] = None
) -> bool:
    """
    Send an email using Resend API.
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        html_content: HTML content of the email
        from_email: Optional sender email (defaults to settings.EMAILS_FROM_EMAIL)
        from_name: Optional sender name (defaults to settings.EMAILS_FROM_NAME)
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    if not settings.EMAIL_ENABLED:
        logger.info("Email sending is disabled")
        return False

    try:
        # Configure Resend API key
        resend.api_key = settings.RESEND_API_KEY
        
        # Set up sender info
        from_email = from_email or settings.EMAILS_FROM_EMAIL
        from_name = from_name or settings.EMAILS_FROM_NAME
        sender = f"{from_name} <{from_email}>"

        # In development/test mode, always use Resend's test email
        original_to_email = to_email
        if settings.ENVIRONMENT != "production":
            logger.info(f"Using test email address for {to_email}")
            to_email = "delivered@resend.dev"

        # Prepare email parameters
        params: Dict[str, Any] = {
            "from": sender,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
        }

        logger.info("Attempting to send email via Resend API...")
        email = resend.Emails.send(params)
        
        if email and email.get("id"):
            logger.info(f"✅ Email sent successfully via Resend API. ID: {email['id']}")
            if settings.ENVIRONMENT != "production":
                logger.info(f"Test mode: Email would have been sent to {original_to_email}")
            return True
        else:
            logger.error("❌ Failed to send email via Resend API - no email ID returned")
            return False
            
    except Exception as e:
        logger.error(f"❌ Resend API error: {str(e)}")
        return False

def send_verification_email(email_to: str, username: str, verification_link: str) -> bool:
    """Send email verification link."""
    subject = "Verify your email address"
    html_content = f"""
    <html>
        <body>
            <h2>Email Verification</h2>
            <p>Hi {username},</p>
            <p>Please click the link below to verify your email address:</p>
            <p><a href="{verification_link}">Verify Email</a></p>
            <p>If you didn't create an account, you can safely ignore this email.</p>
            <p>This link will expire in 7 days.</p>
        </body>
    </html>
    """
    return send_email(email_to, subject, html_content)

def send_password_reset_email(email_to: str, username: str, reset_link: str) -> bool:
    """Send password reset link."""
    subject = "Reset your password"
    html_content = f"""
    <html>
        <body>
            <h2>Password Reset</h2>
            <p>Hi {username},</p>
            <p>You requested to reset your password. Click the link below to set a new password:</p>
            <p><a href="{reset_link}">Reset Password</a></p>
            <p>If you didn't request this, please ignore this email or contact support if you're concerned.</p>
            <p>This link will expire in 30 minutes.</p>
        </body>
    </html>
    """
    return send_email(email_to, subject, html_content)