"""
Email service for Aviation Intelligence Hub
Supports Gmail, Outlook, SendGrid with HTML templates
"""
import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List
from datetime import datetime

log = logging.getLogger(__name__)

# Email provider configurations
EMAIL_PROVIDERS = {
    'gmail': {
        'host': 'smtp.gmail.com',
        'port': 587,
        'tls': True
    },
    'outlook': {
        'host': 'smtp-mail.outlook.com',
        'port': 587,
        'tls': True
    },
    'sendgrid': {
        'host': 'smtp.sendgrid.net',
        'port': 587,
        'tls': True
    }
}


class EmailService:
    """Email service supporting multiple providers"""

    def __init__(self, app=None):
        self.app = app
        self.provider = None
        self.smtp_host = None
        self.smtp_port = None
        self.smtp_user = None
        self.smtp_password = None
        self.from_email = None
        self.from_name = None
        self.use_tls = True

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app config"""
        self.app = app

        # Get provider from env
        provider = os.getenv('EMAIL_PROVIDER', 'gmail').lower()
        self.provider = provider

        # Get credentials
        self.smtp_user = os.getenv('EMAIL_USER')
        self.smtp_password = os.getenv('EMAIL_PASSWORD')
        self.from_email = os.getenv('EMAIL_FROM', self.smtp_user)
        self.from_name = os.getenv('EMAIL_FROM_NAME', 'Aviation Intelligence Hub')

        # Get provider config or custom SMTP
        if provider in EMAIL_PROVIDERS:
            config = EMAIL_PROVIDERS[provider]
            self.smtp_host = config['host']
            self.smtp_port = config['port']
            self.use_tls = config['tls']
        else:
            # Custom SMTP server
            self.smtp_host = os.getenv('SMTP_HOST', 'localhost')
            self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
            self.use_tls = os.getenv('SMTP_TLS', 'true').lower() == 'true'

        log.info(f"Email service initialized with provider: {provider}")

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None
    ) -> bool:
        """
        Send email with HTML and plain text versions
        Returns: True if sent successfully
        """
        if not self.smtp_user or not self.smtp_password:
            log.warning("Email not configured - skipping email send")
            if self.app and self.app.debug:
                log.info(f"[DEV] Would send email to {to_email}: {subject}")
                log.info(f"[DEV] Body: {text_body or html_body[:200]}...")
            return False

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = to_email
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')

            # Add plain text version
            if text_body:
                msg.attach(MIMEText(text_body, 'plain'))
            else:
                # Strip HTML tags for plain text
                import re
                text = re.sub('<[^<]+?>', '', html_body)
                msg.attach(MIMEText(text, 'plain'))

            # Add HTML version
            msg.attach(MIMEText(html_body, 'html'))

            # Send via SMTP
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()

                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            log.info(f"Email sent successfully to {to_email}: {subject}")
            return True

        except Exception as e:
            log.error(f"Failed to send email to {to_email}: {e}")
            return False

    def send_verification_email(self, to_email: str, name: str, token: str, base_url: str) -> bool:
        """Send email verification link"""
        verification_url = f"{base_url}/verify/{token}"

        subject = "Verify your Aviation Intelligence Hub account"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #0066FF, #FF6B35); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
                .button {{ display: inline-block; background: #0066FF; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✈️ Welcome to Aviation Intelligence Hub!</h1>
                </div>
                <div class="content">
                    <h2>Hi {name}!</h2>
                    <p>Thanks for signing up! Please verify your email address to activate your account.</p>
                    <p>Click the button below to verify your email (link expires in 12 hours):</p>
                    <p style="text-align: center;">
                        <a href="{verification_url}" class="button">Verify Email Address</a>
                    </p>
                    <p>Or copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #0066FF;">{verification_url}</p>
                    <p><strong>Note:</strong> Your account will be automatically deleted if not verified within 12 hours.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Aviation Intelligence Hub. All rights reserved.</p>
                    <p>You received this email because you signed up for an account.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
        Welcome to Aviation Intelligence Hub!

        Hi {name}!

        Thanks for signing up! Please verify your email address to activate your account.

        Verify your email by visiting this link (expires in 12 hours):
        {verification_url}

        Note: Your account will be automatically deleted if not verified within 12 hours.

        ---
        © 2025 Aviation Intelligence Hub. All rights reserved.
        You received this email because you signed up for an account.
        """

        return self.send_email(to_email, subject, html_body, text_body)

    def send_welcome_email(self, to_email: str, name: str) -> bool:
        """Send welcome email after verification"""
        subject = "Welcome to Aviation Intelligence Hub! 🎉"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #0066FF, #FF6B35); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
                .feature {{ background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #0066FF; }}
                .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✈️ You're all set!</h1>
                </div>
                <div class="content">
                    <h2>Welcome aboard, {name}!</h2>
                    <p>Your email has been verified and your account is now active.</p>

                    <h3>What you can do now:</h3>

                    <div class="feature">
                        <strong>📰 Browse Aviation News</strong><br>
                        Access real-time aviation news from multiple sources
                    </div>

                    <div class="feature">
                        <strong>🤖 AI-Powered Summaries</strong><br>
                        Get intelligent summaries of complex aviation articles
                    </div>

                    <div class="feature">
                        <strong>📧 Email Alerts</strong><br>
                        Receive daily digests and breaking news notifications
                    </div>

                    <div class="feature">
                        <strong>⚙️ Customize Preferences</strong><br>
                        Manage your email settings and content preferences
                    </div>

                    <p style="margin-top: 30px;">Happy reading! 🚀</p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Aviation Intelligence Hub. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
        You're all set!

        Welcome aboard, {name}!

        Your email has been verified and your account is now active.

        What you can do now:
        • Browse Aviation News - Access real-time aviation news from multiple sources
        • AI-Powered Summaries - Get intelligent summaries of complex aviation articles
        • Email Alerts - Receive daily digests and breaking news notifications
        • Customize Preferences - Manage your email settings and content preferences

        Happy reading! 🚀

        ---
        © 2025 Aviation Intelligence Hub. All rights reserved.
        """

        return self.send_email(to_email, subject, html_body, text_body)


# Global email service instance
email_service = EmailService()
