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

    def send_password_reset_email(self, to_email: str, name: str, token: str, base_url: str) -> bool:
        """Send password reset email with token"""
        reset_url = f"{base_url}/reset-password/{token}"

        subject = "Reset your Aviation Intelligence Hub password"

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
                .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Password Reset Request</h1>
                </div>
                <div class="content">
                    <h2>Hi {name}!</h2>
                    <p>We received a request to reset your password for your Aviation Intelligence Hub account.</p>
                    <p>Click the button below to reset your password (link expires in 1 hour):</p>
                    <p style="text-align: center;">
                        <a href="{reset_url}" class="button">Reset Password</a>
                    </p>
                    <p>Or copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #0066FF;">{reset_url}</p>

                    <div class="warning">
                        <strong>⚠️ Security Notice:</strong><br>
                        • If you didn't request this, you can safely ignore this email<br>
                        • Your password will not change unless you click the link and set a new one<br>
                        • Never share this link with anyone<br>
                        • This link can only be used once
                    </div>

                    <p><strong>Link expires in 1 hour</strong></p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Aviation Intelligence Hub. All rights reserved.</p>
                    <p>You received this email because a password reset was requested for your account.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
        Password Reset Request

        Hi {name}!

        We received a request to reset your password for your Aviation Intelligence Hub account.

        Reset your password by visiting this link (expires in 1 hour):
        {reset_url}

        Security Notice:
        • If you didn't request this, you can safely ignore this email
        • Your password will not change unless you click the link and set a new one
        • Never share this link with anyone
        • This link can only be used once

        Link expires in 1 hour

        ---
        © 2025 Aviation Intelligence Hub. All rights reserved.
        You received this email because a password reset was requested for your account.
        """

        return self.send_email(to_email, subject, html_body, text_body)

    def send_daily_digest_email(self, to_email: str, name: str, articles: List[dict],
                                unsubscribe_token: str, base_url: str) -> bool:
        """
        Send daily digest email with news summary
        articles: List of dicts with keys: title, url, source, ai_summary, sentiment, published_date
        """
        unsubscribe_url = f"{base_url}/unsubscribe/{unsubscribe_token}"

        subject = f"Aviation Daily Digest - {datetime.utcnow().strftime('%B %d, %Y')}"

        # Build article sections for HTML
        articles_html = ""
        for article in articles:
            sentiment_emoji = "🔴" if article.get('sentiment', 0) < -0.3 else "🟡" if article.get('sentiment', 0) < 0 else "🟢"
            sentiment_text = "Negative" if article.get('sentiment', 0) < -0.3 else "Neutral" if article.get('sentiment', 0) < 0.3 else "Positive"

            articles_html += f"""
            <div style="background: white; padding: 20px; margin: 15px 0; border-left: 4px solid #0066FF; border-radius: 4px;">
                <h3 style="margin-top: 0; color: #0066FF;">
                    <a href="{article['url']}" style="color: #0066FF; text-decoration: none;">{article['title']}</a>
                </h3>
                <p style="color: #666; font-size: 12px; margin: 5px 0;">
                    {sentiment_emoji} {sentiment_text} | 📰 {article['source']} | 📅 {article.get('published_date', 'Recent')}
                </p>
                <p style="color: #333; line-height: 1.6;">
                    {article.get('ai_summary', 'No summary available')}
                </p>
                <a href="{article['url']}" style="color: #0066FF; text-decoration: none; font-weight: bold;">Read full article →</a>
            </div>
            """

        # Build article sections for plain text
        articles_text = ""
        for i, article in enumerate(articles, 1):
            sentiment_text = "Negative" if article.get('sentiment', 0) < -0.3 else "Neutral" if article.get('sentiment', 0) < 0.3 else "Positive"
            articles_text += f"""
{i}. {article['title']}
   Sentiment: {sentiment_text} | Source: {article['source']} | Date: {article.get('published_date', 'Recent')}
   Summary: {article.get('ai_summary', 'No summary available')}
   Link: {article['url']}

"""

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
                .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #0066FF, #FF6B35); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; }}
                .footer {{ background: #333; color: white; padding: 20px; text-align: center; border-radius: 0 0 8px 8px; }}
                .footer a {{ color: #FF6B35; text-decoration: none; }}
                .stats {{ background: white; padding: 15px; margin: 20px 0; border-radius: 4px; text-align: center; }}
                .stat {{ display: inline-block; margin: 0 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✈️ Aviation Daily Digest</h1>
                    <p>{datetime.utcnow().strftime('%A, %B %d, %Y')}</p>
                </div>
                <div class="content">
                    <h2>Hi {name}!</h2>
                    <p>Here's your daily summary of aviation news from the past 24 hours.</p>

                    <div class="stats">
                        <div class="stat">
                            <strong style="font-size: 24px; color: #0066FF;">{len(articles)}</strong><br>
                            <span style="color: #666;">Articles</span>
                        </div>
                        <div class="stat">
                            <strong style="font-size: 24px; color: #FF6B35;">{len([a for a in articles if a.get('sentiment', 0) < -0.3])}</strong><br>
                            <span style="color: #666;">Breaking News</span>
                        </div>
                    </div>

                    <h3 style="color: #0066FF; border-bottom: 2px solid #0066FF; padding-bottom: 10px;">Today's Top Stories</h3>
                    {articles_html}

                    <p style="margin-top: 30px; padding: 20px; background: #e3f2fd; border-radius: 4px;">
                        <strong>💡 Tip:</strong> Want real-time alerts for breaking news?
                        Make sure breaking news notifications are enabled in your preferences!
                    </p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Aviation Intelligence Hub. All rights reserved.</p>
                    <p style="font-size: 12px; margin-top: 15px;">
                        <a href="{unsubscribe_url}">Unsubscribe from daily digests</a>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
Aviation Daily Digest
{datetime.utcnow().strftime('%A, %B %d, %Y')}

Hi {name}!

Here's your daily summary of aviation news from the past 24 hours.

📊 Summary:
- {len(articles)} Articles
- {len([a for a in articles if a.get('sentiment', 0) < -0.3])} Breaking News Alerts

Today's Top Stories:
{articles_text}

💡 Tip: Want real-time alerts for breaking news? Make sure breaking news notifications are enabled in your preferences!

---
© 2025 Aviation Intelligence Hub. All rights reserved.

Unsubscribe from daily digests: {unsubscribe_url}
        """

        return self.send_email(to_email, subject, html_body, text_body)

    def send_breaking_news_alert(self, to_email: str, name: str, article: dict,
                                  unsubscribe_token: str, base_url: str) -> bool:
        """
        Send breaking news alert for high-negative sentiment articles
        article: Dict with keys: title, url, source, ai_summary, sentiment, published_date
        """
        unsubscribe_url = f"{base_url}/unsubscribe/{unsubscribe_token}"

        subject = f"🚨 Breaking Aviation News: {article['title'][:60]}..."

        # Determine severity
        sentiment = article.get('sentiment', 0)
        if sentiment < -0.5:
            severity = "CRITICAL"
            severity_color = "#d32f2f"
            severity_emoji = "🔴"
        elif sentiment < -0.3:
            severity = "HIGH"
            severity_color = "#f57c00"
            severity_emoji = "🟠"
        else:
            severity = "MODERATE"
            severity_color = "#fbc02d"
            severity_emoji = "🟡"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: {severity_color}; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; }}
                .alert-box {{ background: #fff3cd; border-left: 4px solid {severity_color}; padding: 15px; margin: 20px 0; }}
                .article-box {{ background: white; padding: 20px; margin: 20px 0; border-radius: 4px; border: 1px solid #ddd; }}
                .button {{ display: inline-block; background: {severity_color}; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{severity_emoji} BREAKING NEWS ALERT</h1>
                    <p style="font-size: 18px; margin: 0;">Severity: {severity}</p>
                </div>
                <div class="content">
                    <h2>Hi {name}!</h2>
                    <p>Our AI has detected a significant aviation news event that requires your attention.</p>

                    <div class="alert-box">
                        <strong>⚠️ Alert Triggered:</strong><br>
                        High-negative sentiment detected (Score: {sentiment:.2f})<br>
                        Published: {article.get('published_date', 'Recently')}
                    </div>

                    <div class="article-box">
                        <h3 style="margin-top: 0; color: #0066FF;">{article['title']}</h3>
                        <p style="color: #666; font-size: 12px;">
                            📰 {article['source']} | 📅 {article.get('published_date', 'Recent')}
                        </p>
                        <p style="color: #333; line-height: 1.8;">
                            {article.get('ai_summary', 'No summary available')}
                        </p>
                        <p style="text-align: center;">
                            <a href="{article['url']}" class="button">Read Full Article</a>
                        </p>
                    </div>

                    <p style="color: #666; font-size: 14px;">
                        <strong>Why you're receiving this:</strong> This article was flagged due to high-negative sentiment
                        indicating a potentially significant safety, regulatory, or operational issue in aviation.
                    </p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Aviation Intelligence Hub. All rights reserved.</p>
                    <p style="margin-top: 15px;">
                        <a href="{unsubscribe_url}" style="color: #0066FF;">Manage alert preferences</a>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
🚨 BREAKING NEWS ALERT
Severity: {severity}

Hi {name}!

Our AI has detected a significant aviation news event that requires your attention.

⚠️ Alert Triggered:
- High-negative sentiment detected (Score: {sentiment:.2f})
- Published: {article.get('published_date', 'Recently')}

{article['title']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Source: {article['source']}
Date: {article.get('published_date', 'Recent')}

Summary:
{article.get('ai_summary', 'No summary available')}

Read full article: {article['url']}

Why you're receiving this: This article was flagged due to high-negative sentiment indicating a potentially significant safety, regulatory, or operational issue in aviation.

---
© 2025 Aviation Intelligence Hub. All rights reserved.

Manage alert preferences: {unsubscribe_url}
        """

        return self.send_email(to_email, subject, html_body, text_body)


# Global email service instance
email_service = EmailService()
