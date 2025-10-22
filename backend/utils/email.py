"""
Email service with multiple provider support
- EmailProvider: Abstract base class for email providers
- ConsoleEmailProvider: Prints emails to console (development)
- SMTPEmailProvider: Sends emails via SMTP server (production)
- DisabledEmailProvider: Silent mode (no email sending)
- get_email_provider(): Factory function based on config
- send_password_reset_email(): Pre-built password reset email template
- Support for plain text and HTML emails
- Configurable from EMAIL_PROVIDER environment variable
"""
from abc import ABC, abstractmethod
from typing import Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

from config import config

logger = logging.getLogger(__name__)


class EmailProvider(ABC):
    """Abstract base class for email providers"""

    @abstractmethod
    def send_email(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None
    ) -> bool:
        """Send an email

        Args:
            to_email: Recipient email address
            subject: Email subject
            body_text: Plain text email body
            body_html: Optional HTML email body

        Returns:
            True if email was sent successfully
        """
        pass


class ConsoleEmailProvider(EmailProvider):
    """Email provider that prints emails to console (for development)"""

    def send_email(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None
    ) -> bool:
        """Print email to console

        Args:
            to_email: Recipient email address
            subject: Email subject
            body_text: Plain text email body
            body_html: Optional HTML email body

        Returns:
            Always returns True
        """
        logger.info("=" * 80)
        logger.info("CONSOLE EMAIL PROVIDER - Email Details:")
        logger.info(f"To: {to_email}")
        logger.info(f"From: {config.EMAIL_FROM_NAME} <{config.EMAIL_FROM}>")
        logger.info(f"Subject: {subject}")
        logger.info("-" * 80)
        logger.info("Body (Plain Text):")
        logger.info(body_text)
        if body_html:
            logger.info("-" * 80)
            logger.info("Body (HTML):")
            logger.info(body_html)
        logger.info("=" * 80)
        return True


class SMTPEmailProvider(EmailProvider):
    """Email provider that sends emails via SMTP server"""

    def send_email(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None
    ) -> bool:
        """Send email via SMTP

        Args:
            to_email: Recipient email address
            subject: Email subject
            body_text: Plain text email body
            body_html: Optional HTML email body

        Returns:
            True if email was sent successfully
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{config.EMAIL_FROM_NAME} <{config.EMAIL_FROM}>"
            msg['To'] = to_email

            # Attach plain text body
            part_text = MIMEText(body_text, 'plain')
            msg.attach(part_text)

            # Attach HTML body if provided
            if body_html:
                part_html = MIMEText(body_html, 'html')
                msg.attach(part_html)

            # Connect to SMTP server
            if config.SMTP_USE_TLS:
                server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                server.starttls()
            else:
                server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)

            # Login if credentials provided
            if config.SMTP_USERNAME and config.SMTP_PASSWORD:
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)

            # Send email
            server.send_message(msg)
            server.quit()

            logger.info(f"Email sent successfully to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False


class DisabledEmailProvider(EmailProvider):
    """Email provider that does nothing (silent mode)"""

    def send_email(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None
    ) -> bool:
        """Do nothing (emails disabled)

        Args:
            to_email: Recipient email address
            subject: Email subject
            body_text: Plain text email body
            body_html: Optional HTML email body

        Returns:
            Always returns True
        """
        logger.debug(f"Email sending is disabled. Would have sent email to {to_email} with subject: {subject}")
        return True


def get_email_provider() -> EmailProvider:
    """Get the configured email provider

    Returns:
        EmailProvider instance based on configuration
    """
    provider = config.EMAIL_PROVIDER.lower()

    if provider == 'console':
        return ConsoleEmailProvider()
    elif provider == 'smtp':
        return SMTPEmailProvider()
    elif provider == 'disabled':
        return DisabledEmailProvider()
    else:
        logger.warning(f"Unknown email provider '{provider}', falling back to console")
        return ConsoleEmailProvider()


def send_password_reset_email(
    to_email: str,
    username: str,
    reset_token: str
) -> bool:
    """Send password reset email to user

    Args:
        to_email: User's email address
        username: User's username
        reset_token: Password reset token

    Returns:
        True if email was sent successfully
    """
    # Construct reset URL
    reset_url = f"{config.PASSWORD_RESET_URL_BASE}/password-reset/{reset_token}"

    # Email subject
    subject = "Password Reset Request - Topologix"

    # Plain text body
    body_text = f"""Hello {username},

You have requested to reset your password for your Topologix account.

Please click the link below to reset your password:
{reset_url}

This link will expire in {config.PASSWORD_RESET_TOKEN_EXPIRY // 60} minutes.

If you did not request this password reset, please ignore this email.

Best regards,
The Topologix Team
"""

    # HTML body
    body_html = f"""
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .button {{
            display: inline-block;
            padding: 12px 24px;
            background-color: #0066cc;
            color: #ffffff !important;
            text-decoration: none;
            border-radius: 4px;
            margin: 20px 0;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 12px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Password Reset Request</h2>
        <p>Hello {username},</p>
        <p>You have requested to reset your password for your Topologix account.</p>
        <p>Please click the button below to reset your password:</p>
        <a href="{reset_url}" class="button">Reset Password</a>
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all;">{reset_url}</p>
        <p><strong>This link will expire in {config.PASSWORD_RESET_TOKEN_EXPIRY // 60} minutes.</strong></p>
        <p>If you did not request this password reset, please ignore this email.</p>
        <div class="footer">
            <p>Best regards,<br>The Topologix Team</p>
        </div>
    </div>
</body>
</html>
"""

    # Get email provider and send
    provider = get_email_provider()
    return provider.send_email(to_email, subject, body_text, body_html)
