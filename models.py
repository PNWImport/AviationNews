"""
Database models for Aviation Intelligence Hub
User authentication, preferences, and email management
"""
import sqlite3
from datetime import datetime, timedelta
import secrets
import bcrypt
from flask_login import UserMixin
from typing import Optional, Dict, Any

# Password validation rules (redteam safe)
PASSWORD_MIN_LENGTH = 15
PASSWORD_REQUIREMENTS = {
    'uppercase': r'[A-Z]',
    'lowercase': r'[a-z]',
    'digit': r'[0-9]',
    'special': r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]'
}


class User(UserMixin):
    """User model with Flask-Login integration"""

    def __init__(self, user_data: Dict[str, Any]):
        self.id = user_data['id']
        self.email = user_data['email']
        self.name = user_data['name']
        self.password_hash = user_data['password_hash']
        self.is_verified = bool(user_data['is_verified'])
        self.verification_token = user_data.get('verification_token')
        self.verification_token_expires = user_data.get('verification_token_expires')
        self.created_at = user_data['created_at']
        self.last_login = user_data.get('last_login')
        self._is_active = bool(user_data.get('is_active', 1))

        # Email preferences
        self.email_daily_digest = bool(user_data.get('email_daily_digest', 1))
        self.email_breaking_news = bool(user_data.get('email_breaking_news', 1))
        self.unsubscribe_token = user_data.get('unsubscribe_token')

    def get_id(self):
        """Required by Flask-Login"""
        return str(self.id)

    @property
    def is_active(self):
        """Required by Flask-Login - user account is active"""
        return self._is_active

    @property
    def is_authenticated(self):
        """Required by Flask-Login"""
        return True

    @property
    def is_anonymous(self):
        """Required by Flask-Login"""
        return False

    def check_password(self, password: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        """
        Validate password meets security requirements
        Returns: (is_valid, error_message)
        """
        import re

        if len(password) < PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters"

        if not re.search(PASSWORD_REQUIREMENTS['uppercase'], password):
            return False, "Password must contain at least one uppercase letter"

        if not re.search(PASSWORD_REQUIREMENTS['lowercase'], password):
            return False, "Password must contain at least one lowercase letter"

        if not re.search(PASSWORD_REQUIREMENTS['digit'], password):
            return False, "Password must contain at least one number"

        if not re.search(PASSWORD_REQUIREMENTS['special'], password):
            return False, "Password must contain at least one special character"

        return True, ""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt (HIPAA compliant)"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def generate_token() -> str:
        """Generate secure random token"""
        return secrets.token_urlsafe(32)


def init_user_tables(db):
    """Initialize user-related database tables"""
    cursor = db.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT UNIQUE,
            verification_token_expires TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT,
            is_active INTEGER DEFAULT 1,
            email_daily_digest INTEGER DEFAULT 1,
            email_breaking_news INTEGER DEFAULT 1,
            unsubscribe_token TEXT UNIQUE,
            CONSTRAINT email_format CHECK (email LIKE '%@%.%')
        )
    """)

    # Password history table (prevent reuse)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Password reset tokens table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Create indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(verification_token)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token)")

    db.commit()


def get_user_by_id(db, user_id: int) -> Optional[User]:
    """Load user by ID"""
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()

    if row:
        return User(dict(row))
    return None


def get_user_by_email(db, email: str) -> Optional[User]:
    """Load user by email"""
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
    row = cursor.fetchone()

    if row:
        return User(dict(row))
    return None


def create_user(db, email: str, name: str, password: str) -> tuple[Optional[User], str]:
    """
    Create new user with email verification
    Returns: (user, error_message)
    """
    email = email.lower().strip()
    name = name.strip()

    # Validate password
    is_valid, error = User.validate_password(password)
    if not is_valid:
        return None, error

    # Check if email already exists
    if get_user_by_email(db, email):
        return None, "Email already registered"

    # Hash password
    password_hash = User.hash_password(password)

    # Generate verification token
    verification_token = User.generate_token()
    verification_expires = (datetime.utcnow() + timedelta(hours=12)).isoformat()

    # Generate unsubscribe token
    unsubscribe_token = User.generate_token()

    cursor = db.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (
                email, name, password_hash, verification_token,
                verification_token_expires, created_at, unsubscribe_token
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            email, name, password_hash, verification_token,
            verification_expires, datetime.utcnow().isoformat(), unsubscribe_token
        ))

        # Store password in history
        user_id = cursor.lastrowid
        cursor.execute("""
            INSERT INTO password_history (user_id, password_hash, created_at)
            VALUES (?, ?, ?)
        """, (user_id, password_hash, datetime.utcnow().isoformat()))

        db.commit()

        return get_user_by_id(db, user_id), ""
    except sqlite3.IntegrityError as e:
        db.rollback()
        return None, f"Error creating user: {str(e)}"


def verify_user_email(db, token: str) -> tuple[bool, str]:
    """
    Verify user email with token
    Returns: (success, message)
    """
    cursor = db.cursor()
    cursor.execute("""
        SELECT * FROM users
        WHERE verification_token = ?
        AND is_verified = 0
    """, (token,))
    row = cursor.fetchone()

    if not row:
        return False, "Invalid or expired verification link"

    user_data = dict(row)

    # Check if token expired
    expires = datetime.fromisoformat(user_data['verification_token_expires'])
    if datetime.utcnow() > expires:
        return False, "Verification link has expired (12 hours)"

    # Verify user
    cursor.execute("""
        UPDATE users
        SET is_verified = 1, verification_token = NULL, verification_token_expires = NULL
        WHERE id = ?
    """, (user_data['id'],))
    db.commit()

    return True, "Email verified successfully! You can now login."


def check_password_reuse(db, user_id: int, new_password: str) -> bool:
    """
    Check if password was previously used
    Returns: True if password was used before
    """
    cursor = db.cursor()
    cursor.execute("""
        SELECT password_hash FROM password_history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 5
    """, (user_id,))

    for row in cursor.fetchall():
        if bcrypt.checkpw(new_password.encode('utf-8'), row['password_hash'].encode('utf-8')):
            return True

    return False


def update_last_login(db, user_id: int):
    """Update user's last login timestamp"""
    cursor = db.cursor()
    cursor.execute("""
        UPDATE users SET last_login = ? WHERE id = ?
    """, (datetime.utcnow().isoformat(), user_id))
    db.commit()


def cleanup_unverified_users(db) -> int:
    """
    Delete unverified users older than 12 hours
    Returns: number of users deleted
    """
    cursor = db.cursor()
    cutoff = (datetime.utcnow() - timedelta(hours=12)).isoformat()

    cursor.execute("""
        DELETE FROM users
        WHERE is_verified = 0
        AND created_at < ?
    """, (cutoff,))

    deleted = cursor.rowcount
    db.commit()
    return deleted


# =============== Password Reset Functions ===============

def create_password_reset_token(db, email: str) -> tuple[bool, str]:
    """
    Create password reset token for user
    Returns: (success, message)
    """
    cursor = db.cursor()

    # Check if user exists and is verified
    cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
    row = cursor.fetchone()

    if not row:
        # Don't reveal if email exists or not (security)
        return True, "If that email exists, a password reset link has been sent"

    user_data = dict(row)

    if not user_data['is_verified']:
        return False, "Please verify your email address first"

    # Generate secure token
    token = User.generate_token()
    expires_at = (datetime.utcnow() + timedelta(hours=1)).isoformat()

    # Delete any existing reset tokens for this user
    cursor.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_data['id'],))

    # Insert new reset token
    cursor.execute("""
        INSERT INTO password_reset_tokens (user_id, token, expires_at, used, created_at)
        VALUES (?, ?, ?, 0, ?)
    """, (user_data['id'], token, expires_at, datetime.utcnow().isoformat()))

    db.commit()

    return True, token


def verify_password_reset_token(db, token: str) -> tuple[bool, Optional[int], str]:
    """
    Verify password reset token
    Returns: (is_valid, user_id, message)
    """
    cursor = db.cursor()

    cursor.execute("""
        SELECT * FROM password_reset_tokens
        WHERE token = ? AND used = 0
    """, (token,))
    row = cursor.fetchone()

    if not row:
        return False, None, "Invalid or expired reset link"

    token_data = dict(row)

    # Check if token expired (1 hour)
    expires = datetime.fromisoformat(token_data['expires_at'])
    if datetime.utcnow() > expires:
        return False, None, "Reset link has expired (1 hour). Please request a new one"

    return True, token_data['user_id'], "Token is valid"


def reset_user_password(db, user_id: int, token: str, new_password: str) -> tuple[bool, str]:
    """
    Reset user password with token
    Checks password history and marks token as used
    Returns: (success, message)
    """
    cursor = db.cursor()

    # Verify token is still valid and not used
    is_valid, token_user_id, message = verify_password_reset_token(db, token)
    if not is_valid:
        return False, message

    if token_user_id != user_id:
        return False, "Invalid reset token"

    # Validate password strength
    is_valid_pw, error_msg = User.validate_password(new_password)
    if not is_valid_pw:
        return False, error_msg

    # Check password history (can't reuse last 5 passwords)
    if check_password_reuse(db, user_id, new_password):
        return False, "You cannot reuse any of your last 5 passwords"

    # Get current password hash for history
    cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if row:
        old_password_hash = row['password_hash']

        # Add old password to history
        cursor.execute("""
            INSERT INTO password_history (user_id, password_hash, created_at)
            VALUES (?, ?, ?)
        """, (user_id, old_password_hash, datetime.utcnow().isoformat()))

    # Hash new password
    new_password_hash = User.hash_password(new_password)

    # Update user password
    cursor.execute("""
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
    """, (new_password_hash, user_id))

    # Mark token as used
    cursor.execute("""
        UPDATE password_reset_tokens
        SET used = 1
        WHERE token = ?
    """, (token,))

    db.commit()

    return True, "Password reset successfully"
