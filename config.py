"""
Configuration Module for Aviation Intelligence Hub
Centralized configuration management with validation
"""
import os
import secrets
from typing import Optional, List


class Config:
    """Application configuration with environment variable loading and validation"""

    # Database Configuration
    DATABASE: str = os.environ.get("AIH_DB", "emails.db")

    # HTTP Request Settings
    REQUEST_TIMEOUT: float = float(os.environ.get("AIH_REQ_TIMEOUT", "30"))

    # Auto-refresh Settings (in seconds)
    AUTO_REFRESH_INTERVAL: int = int(os.environ.get("AUTO_REFRESH_INTERVAL", "300"))

    # Cloudflare Worker Configuration
    CF_WORKER_URL: str = os.environ.get(
        "CF_WORKER_URL",
        "https://fragrant-heart-8e59.pnwpokemonelite.workers.dev"
    )
    CF_WORKER_TOKEN: str = os.environ.get("CF_WORKER_TOKEN", "super-secret-123!")

    # AI Content Settings
    MAX_CONTENT_CHARS_TO_WORKER: int = int(os.environ.get("MAX_CONTENT_CHARS_TO_WORKER", "2500"))  # Reduced for faster processing
    WORKER_BATCH_SIZE: int = int(os.environ.get("WORKER_BATCH_SIZE", "8"))  # Smaller batches process faster
    WORKER_PARALLEL_BATCHES: int = int(os.environ.get("WORKER_PARALLEL_BATCHES", "3"))  # Process 3 batches in parallel
    MAX_ITEM_TOASTS: int = int(os.environ.get("MAX_ITEM_TOASTS", "5"))
    WORKER_TIMEOUT: float = float(os.environ.get("WORKER_TIMEOUT", "90"))  # Reduced timeout

    # Feed Processing Settings
    MAX_FEED_WORKERS: int = int(os.environ.get("MAX_FEED_WORKERS", "10"))

    # Server Configuration
    PORT: int = int(os.environ.get("PORT", "5001"))
    HOST: str = os.environ.get("HOST", "localhost")
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")

    # Flask Secret Key (required for sessions, CSRF, etc.)
    SECRET_KEY: str = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    # Security Settings
    RATE_LIMIT_ENABLED: bool = os.environ.get("RATE_LIMIT_ENABLED", "True").lower() in ("true", "1", "yes")
    RATE_LIMIT_DEFAULT: str = os.environ.get("RATE_LIMIT_DEFAULT", "60 per minute")

    # URL Validation Settings
    @property
    def ALLOWED_DOMAINS(self) -> Optional[List[str]]:
        """Parse comma-separated allowed domains"""
        domains = os.environ.get("ALLOWED_DOMAINS", "").strip()
        if domains:
            return [d.strip() for d in domains.split(",") if d.strip()]
        return None

    @property
    def BLOCKED_DOMAINS(self) -> List[str]:
        """Parse comma-separated blocked domains with secure defaults"""
        default_blocked = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",
            "metadata.google.internal"
        ]
        domains = os.environ.get("BLOCKED_DOMAINS", "").strip()
        if domains:
            custom_blocked = [d.strip() for d in domains.split(",") if d.strip()]
            return list(set(default_blocked + custom_blocked))
        return default_blocked

    # Logging Configuration
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO").upper()
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Queue Configuration
    SSE_QUEUE_MAXSIZE: int = int(os.environ.get("SSE_QUEUE_MAXSIZE", "100"))

    @classmethod
    def validate(cls) -> None:
        """
        Validate critical configuration values
        Raises ValueError if configuration is invalid
        """
        errors = []

        # Validate numeric ranges
        if cls.REQUEST_TIMEOUT <= 0:
            errors.append("REQUEST_TIMEOUT must be positive")

        if cls.AUTO_REFRESH_INTERVAL < 60:
            errors.append("AUTO_REFRESH_INTERVAL should be at least 60 seconds")

        if cls.MAX_FEED_WORKERS < 1 or cls.MAX_FEED_WORKERS > 20:
            errors.append("MAX_FEED_WORKERS must be between 1 and 20")

        if cls.WORKER_BATCH_SIZE < 1 or cls.WORKER_BATCH_SIZE > 50:
            errors.append("WORKER_BATCH_SIZE must be between 1 and 50")

        if cls.WORKER_PARALLEL_BATCHES < 1 or cls.WORKER_PARALLEL_BATCHES > 10:
            errors.append("WORKER_PARALLEL_BATCHES must be between 1 and 10")

        if cls.PORT < 1 or cls.PORT > 65535:
            errors.append("PORT must be between 1 and 65535")

        # Validate Cloudflare Worker settings if configured
        if cls.CF_WORKER_URL and not cls.CF_WORKER_URL.startswith(("http://", "https://")):
            errors.append("CF_WORKER_URL must be a valid HTTP(S) URL")

        # Warn about insecure defaults (don't fail, just warn)
        if cls.CF_WORKER_TOKEN == "super-secret-123!":
            import logging
            logging.warning(
                "⚠️  SECURITY WARNING: Using default CF_WORKER_TOKEN! "
                "Set CF_WORKER_TOKEN environment variable to a secure value!"
            )

        if cls.SECRET_KEY and len(cls.SECRET_KEY) < 32:
            import logging
            logging.warning(
                "⚠️  SECURITY WARNING: SECRET_KEY is too short! "
                "Should be at least 32 characters (64 hex characters)."
            )

        if errors:
            raise ValueError("Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors))

    @classmethod
    def get_summary(cls) -> dict:
        """Get a summary of current configuration (safe for logging)"""
        return {
            "database": cls.DATABASE,
            "host": cls.HOST,
            "port": cls.PORT,
            "debug": cls.DEBUG,
            "request_timeout": cls.REQUEST_TIMEOUT,
            "auto_refresh_interval": cls.AUTO_REFRESH_INTERVAL,
            "max_feed_workers": cls.MAX_FEED_WORKERS,
            "worker_batch_size": cls.WORKER_BATCH_SIZE,
            "worker_parallel_batches": cls.WORKER_PARALLEL_BATCHES,
            "rate_limit_enabled": cls.RATE_LIMIT_ENABLED,
            "cf_worker_configured": bool(cls.CF_WORKER_URL and cls.CF_WORKER_TOKEN),
            "allowed_domains": cls().ALLOWED_DOMAINS or "all",
            "blocked_domains_count": len(cls().BLOCKED_DOMAINS),
        }


# Create a singleton instance
config = Config()
