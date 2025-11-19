"""
Input sanitization for Aviation Intelligence Hub
XSS prevention, HTML cleaning, malicious input detection
"""
import bleach
import re
from typing import Optional

# Allowed HTML tags for user-generated content (none for auth fields)
ALLOWED_TAGS = []
ALLOWED_ATTRIBUTES = {}
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

# Suspicious patterns (SQL injection, XSS attempts, path traversal)
SUSPICIOUS_PATTERNS = [
    r'<script',
    r'javascript:',
    r'onerror=',
    r'onload=',
    r'onclick=',
    r'onfocus=',
    r'onmouseover=',
    r'<iframe',
    r'<embed',
    r'<object',
    r'eval\(',
    r'expression\(',
    r'vbscript:',
    r'data:text/html',
    r'\.\./\.\.',  # Path traversal
    r'UNION\s+SELECT',
    r'DROP\s+TABLE',
    r'INSERT\s+INTO',
    r'DELETE\s+FROM',
    r'UPDATE\s+\w+\s+SET',
    r'--\s*$',  # SQL comment
    r'/\*.*\*/',  # SQL block comment
]


class InputSanitizer:
    """Sanitize and validate user inputs"""

    @staticmethod
    def clean_text(text: str, max_length: Optional[int] = None) -> str:
        """
        Clean plain text input
        Removes HTML, scripts, and malicious content
        """
        if not text:
            return ""

        # Strip all HTML tags
        cleaned = bleach.clean(
            text,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            protocols=ALLOWED_PROTOCOLS,
            strip=True
        )

        # Remove extra whitespace
        cleaned = ' '.join(cleaned.split())

        # Truncate if needed
        if max_length and len(cleaned) > max_length:
            cleaned = cleaned[:max_length]

        return cleaned.strip()

    @staticmethod
    def clean_email(email: str) -> str:
        """
        Sanitize email address
        Returns lowercase, stripped email or empty string if invalid
        """
        if not email:
            return ""

        email = email.lower().strip()

        # Remove any HTML
        email = bleach.clean(email, tags=[], strip=True)

        # Basic email validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return ""

        # Length check
        if len(email) > 254:  # RFC 5321
            return ""

        return email

    @staticmethod
    def clean_name(name: str) -> str:
        """
        Sanitize name field
        Allows letters, spaces, hyphens, apostrophes
        """
        if not name:
            return ""

        # Strip HTML
        cleaned = bleach.clean(name, tags=[], strip=True)

        # Remove suspicious characters
        cleaned = re.sub(r'[^a-zA-Z\s\'\-]', '', cleaned)

        # Remove extra whitespace
        cleaned = ' '.join(cleaned.split())

        # Max length for name
        if len(cleaned) > 100:
            cleaned = cleaned[:100]

        return cleaned.strip()

    @staticmethod
    def detect_malicious_input(text: str) -> tuple[bool, Optional[str]]:
        """
        Detect potentially malicious input patterns
        Returns: (is_suspicious, matched_pattern)
        """
        if not text:
            return False, None

        text_lower = text.lower()

        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True, pattern

        return False, None

    @staticmethod
    def sanitize_signup_data(name: str, email: str) -> dict:
        """
        Sanitize signup form data
        Returns: dict with cleaned data and validation errors
        """
        errors = []

        # Clean name
        clean_name = InputSanitizer.clean_name(name)
        if not clean_name:
            errors.append("Name contains invalid characters")
        elif len(clean_name) < 2:
            errors.append("Name must be at least 2 characters")

        # Check for malicious name
        is_suspicious, pattern = InputSanitizer.detect_malicious_input(name)
        if is_suspicious:
            errors.append(f"Name contains suspicious pattern: {pattern}")

        # Clean email
        clean_email = InputSanitizer.clean_email(email)
        if not clean_email:
            errors.append("Invalid email address")

        # Check for malicious email
        is_suspicious, pattern = InputSanitizer.detect_malicious_input(email)
        if is_suspicious:
            errors.append(f"Email contains suspicious pattern: {pattern}")

        return {
            'name': clean_name,
            'email': clean_email,
            'errors': errors
        }

    @staticmethod
    def check_honeypot(value: str) -> bool:
        """
        Check honeypot field (should be empty)
        Returns: True if bot detected
        """
        return bool(value and value.strip())


def sanitize_html_content(html: str, allow_links: bool = False) -> str:
    """
    Sanitize HTML content for display
    Used for news content, comments, etc.
    """
    allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li']
    allowed_attrs = {}

    if allow_links:
        allowed_tags.extend(['a'])
        allowed_attrs['a'] = ['href', 'title']

    cleaned = bleach.clean(
        html,
        tags=allowed_tags,
        attributes=allowed_attrs,
        protocols=ALLOWED_PROTOCOLS,
        strip=True
    )

    # Linkify URLs if allowed
    if allow_links:
        cleaned = bleach.linkify(
            cleaned,
            callbacks=[bleach.callbacks.nofollow, bleach.callbacks.target_blank]
        )

    return cleaned


# Create global sanitizer instance
sanitizer = InputSanitizer()
