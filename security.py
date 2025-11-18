"""
Security Module for Aviation Intelligence Hub
Provides input validation, SSRF protection, and security utilities
"""
import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional, List, Set
import logging

log = logging.getLogger(__name__)

# Private IP ranges to block (SSRF protection)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local
    ipaddress.ip_network('::1/128'),  # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),  # IPv6 private
    ipaddress.ip_network('fe80::/10'),  # IPv6 link-local
]

# Dangerous hostnames to block
BLOCKED_HOSTNAMES = {
    'localhost',
    '0.0.0.0',
    'metadata.google.internal',  # GCP metadata
    '169.254.169.254',  # AWS/Azure metadata
}


class SecurityError(Exception):
    """Raised when a security validation fails"""
    pass


class URLValidator:
    """Validates URLs to prevent SSRF and other attacks"""

    def __init__(self, allowed_domains: Optional[List[str]] = None,
                 blocked_domains: Optional[List[str]] = None):
        """
        Initialize URL validator

        Args:
            allowed_domains: Whitelist of allowed domains (None = allow all)
            blocked_domains: Blacklist of blocked domains
        """
        self.allowed_domains: Optional[Set[str]] = set(allowed_domains) if allowed_domains else None
        self.blocked_domains: Set[str] = set(blocked_domains) if blocked_domains else set()
        self.blocked_domains.update(BLOCKED_HOSTNAMES)

    def validate_url(self, url: str) -> str:
        """
        Validate a URL for security issues

        Args:
            url: URL to validate

        Returns:
            The validated URL

        Raises:
            SecurityError: If URL fails validation
        """
        if not url or not isinstance(url, str):
            raise SecurityError("URL must be a non-empty string")

        url = url.strip()

        # Length check
        if len(url) > 2048:
            raise SecurityError("URL too long (max 2048 characters)")

        # Must be HTTP or HTTPS
        if not re.match(r'^https?://', url, re.IGNORECASE):
            raise SecurityError("URL must start with http:// or https://")

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise SecurityError(f"Invalid URL format: {e}")

        if not parsed.netloc:
            raise SecurityError("URL must have a valid hostname")

        # Extract hostname (remove port if present)
        hostname = parsed.hostname
        if not hostname:
            raise SecurityError("Unable to extract hostname from URL")

        hostname_lower = hostname.lower()

        # Check blocked domains
        if hostname_lower in self.blocked_domains:
            raise SecurityError(f"Domain '{hostname}' is blocked")

        # Check against blocked patterns
        if any(blocked in hostname_lower for blocked in ['metadata', 'internal', '169.254']):
            raise SecurityError(f"Domain '{hostname}' matches blocked pattern")

        # Check if it's an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            # Block private IPs (SSRF protection)
            if any(ip in network for network in PRIVATE_IP_RANGES):
                raise SecurityError(f"Private IP addresses are not allowed: {hostname}")
        except ValueError:
            # Not an IP address, continue with domain validation
            pass

        # Check allowed domains whitelist
        if self.allowed_domains:
            domain_allowed = False
            for allowed in self.allowed_domains:
                if hostname_lower == allowed.lower() or hostname_lower.endswith(f'.{allowed.lower()}'):
                    domain_allowed = True
                    break

            if not domain_allowed:
                raise SecurityError(f"Domain '{hostname}' is not in the allowed list")

        # Validate port if specified
        if parsed.port:
            if parsed.port < 1 or parsed.port > 65535:
                raise SecurityError(f"Invalid port number: {parsed.port}")
            # Block commonly dangerous ports
            dangerous_ports = {22, 23, 3389, 5900, 5432, 3306, 1433, 27017}
            if parsed.port in dangerous_ports:
                raise SecurityError(f"Port {parsed.port} is not allowed")

        log.info(f"URL validated successfully: {hostname}")
        return url


class InputValidator:
    """Validates and sanitizes user inputs"""

    @staticmethod
    def validate_integer(value: any, min_val: Optional[int] = None,
                        max_val: Optional[int] = None, default: Optional[int] = None) -> int:
        """
        Validate and convert an integer input

        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            default: Default value if validation fails

        Returns:
            Validated integer

        Raises:
            ValueError: If validation fails and no default provided
        """
        try:
            result = int(value)
            if min_val is not None and result < min_val:
                if default is not None:
                    return default
                raise ValueError(f"Value must be at least {min_val}")
            if max_val is not None and result > max_val:
                if default is not None:
                    return default
                raise ValueError(f"Value must be at most {max_val}")
            return result
        except (TypeError, ValueError) as e:
            if default is not None:
                return default
            raise ValueError(f"Invalid integer value: {e}")

    @staticmethod
    def validate_string(value: any, max_length: Optional[int] = None,
                       pattern: Optional[str] = None, default: str = "") -> str:
        """
        Validate a string input

        Args:
            value: Value to validate
            max_length: Maximum allowed length
            pattern: Regex pattern to match
            default: Default value if validation fails

        Returns:
            Validated string
        """
        if value is None:
            return default

        try:
            result = str(value).strip()

            if max_length and len(result) > max_length:
                result = result[:max_length]

            if pattern and result and not re.match(pattern, result):
                return default

            return result
        except Exception:
            return default

    @staticmethod
    def validate_sentiment_filter(value: str) -> str:
        """Validate sentiment filter value"""
        valid_filters = {'all', 'positive', 'neutral', 'negative'}
        value = value.lower().strip()
        return value if value in valid_filters else 'all'


def get_client_ip(request) -> str:
    """
    Safely extract client IP from request
    Handles X-Forwarded-For header for reverse proxy setups
    """
    if request.headers.get('X-Forwarded-For'):
        # Take the first IP in the chain (client)
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr or 'unknown'


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize a filename to prevent directory traversal and other attacks

    Args:
        filename: Original filename
        max_length: Maximum allowed length

    Returns:
        Sanitized filename
    """
    # Remove path components
    filename = filename.replace('\\', '/').split('/')[-1]

    # Remove dangerous characters
    filename = re.sub(r'[^\w\s\-\.]', '', filename)

    # Limit length
    if len(filename) > max_length:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:max_length - len(ext) - 1] + '.' + ext if ext else name[:max_length]

    return filename or 'unnamed'
