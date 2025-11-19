"""
Database models for Aviation Intelligence Hub
User authentication, preferences, email management, and gamification
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

        # Subscription
        self.subscription_tier = user_data.get('subscription_tier', 'free')
        self.subscription_status = user_data.get('subscription_status', 'inactive')
        self.subscription_start = user_data.get('subscription_start')
        self.subscription_end = user_data.get('subscription_end')
        self.revenuecat_user_id = user_data.get('revenuecat_user_id')

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
            subscription_tier TEXT DEFAULT 'free',
            subscription_status TEXT DEFAULT 'inactive',
            subscription_start TEXT,
            subscription_end TEXT,
            revenuecat_user_id TEXT UNIQUE,
            CONSTRAINT email_format CHECK (email LIKE '%@%.%'),
            CONSTRAINT subscription_tier_check CHECK (subscription_tier IN ('free', 'pro')),
            CONSTRAINT subscription_status_check CHECK (subscription_status IN ('inactive', 'active', 'canceled', 'expired', 'trial'))
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

    # Sessions table (track active sessions)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            device_info TEXT,
            remember_me INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_activity TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Login history table (audit trail)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            device_info TEXT,
            login_time TEXT NOT NULL,
            success INTEGER NOT NULL,
            failure_reason TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        )
    """)

    # Gamification: User stats table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_gamification (
            user_id INTEGER PRIMARY KEY,
            points INTEGER DEFAULT 0,
            level INTEGER DEFAULT 1,
            current_streak INTEGER DEFAULT 0,
            best_streak INTEGER DEFAULT 0,
            total_logins INTEGER DEFAULT 0,
            articles_read INTEGER DEFAULT 0,
            last_login_date TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Gamification: Badges/Achievements master table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS badges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL,
            icon TEXT NOT NULL,
            requirement_type TEXT NOT NULL,
            requirement_value INTEGER NOT NULL,
            tier TEXT DEFAULT 'free',
            created_at TEXT NOT NULL,
            CONSTRAINT requirement_type_check CHECK (requirement_type IN ('logins', 'streak', 'articles', 'points', 'early_adopter', 'pro_upgrade')),
            CONSTRAINT tier_check CHECK (tier IN ('free', 'pro'))
        )
    """)

    # Gamification: User badges (earned achievements)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_badges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            badge_id INTEGER NOT NULL,
            earned_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (badge_id) REFERENCES badges (id) ON DELETE CASCADE,
            UNIQUE(user_id, badge_id)
        )
    """)

    # Gamification: Activity history (points log)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS gamification_activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            activity_type TEXT NOT NULL,
            points_earned INTEGER NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            CONSTRAINT activity_type_check CHECK (activity_type IN ('login', 'streak', 'article_read', 'badge_earned', 'level_up', 'pro_upgrade'))
        )
    """)

    # Subscription: Event log from RevenueCat webhooks
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS subscription_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            revenuecat_user_id TEXT NOT NULL,
            product_id TEXT,
            purchased_at TEXT,
            expiration_at TEXT,
            is_trial INTEGER DEFAULT 0,
            raw_data TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL,
            CONSTRAINT event_type_check CHECK (event_type IN ('initial_purchase', 'renewal', 'cancellation', 'billing_issue', 'refund', 'trial_started', 'trial_converted', 'trial_cancelled'))
        )
    """)

    # Create indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(verification_token)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_revenuecat_user_id ON users(revenuecat_user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_session_id ON user_sessions(session_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_history_user_id ON login_history(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_badges_user_id ON user_badges(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_gamification_activities_user_id ON gamification_activities(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscription_events_user_id ON subscription_events(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_subscription_events_revenuecat_user_id ON subscription_events(revenuecat_user_id)")

    db.commit()

    # Initialize default badges
    from gamification import _init_default_badges
    _init_default_badges(db)


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

        # Initialize gamification for new user
        from gamification import init_user_gamification
        init_user_gamification(db, user_id)

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


# =============== User Preferences Functions ===============

def get_user_preferences(db, user_id: int) -> Optional[Dict[str, Any]]:
    """
    Get user email preferences
    Returns: dict with preference settings or None if user not found
    """
    cursor = db.cursor()

    cursor.execute("""
        SELECT email_daily_digest, email_breaking_news, email, name
        FROM users
        WHERE id = ?
    """, (user_id,))

    row = cursor.fetchone()

    if not row:
        return None

    return {
        'email_daily_digest': bool(row['email_daily_digest']),
        'email_breaking_news': bool(row['email_breaking_news']),
        'email': row['email'],
        'name': row['name']
    }


def update_user_preferences(db, user_id: int, preferences: Dict[str, Any]) -> tuple[bool, str]:
    """
    Update user email preferences
    preferences: dict with keys: email_daily_digest, email_breaking_news (booleans)
    Returns: (success, message)
    """
    cursor = db.cursor()

    # Verify user exists
    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        return False, "User not found"

    # Build update query based on provided preferences
    updates = []
    values = []

    if 'email_daily_digest' in preferences:
        updates.append("email_daily_digest = ?")
        values.append(1 if preferences['email_daily_digest'] else 0)

    if 'email_breaking_news' in preferences:
        updates.append("email_breaking_news = ?")
        values.append(1 if preferences['email_breaking_news'] else 0)

    if not updates:
        return False, "No preferences provided"

    # Add user_id to values for WHERE clause
    values.append(user_id)

    # Execute update
    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
    cursor.execute(query, tuple(values))

    db.commit()

    return True, "Preferences updated successfully"


def unsubscribe_user_by_token(db, unsubscribe_token: str, email_type: str = 'all') -> tuple[bool, str, Optional[str]]:
    """
    Unsubscribe user using unsubscribe token
    email_type: 'all', 'digest', or 'breaking_news'
    Returns: (success, message, email)
    """
    cursor = db.cursor()

    # Find user by unsubscribe token
    cursor.execute("""
        SELECT id, email, name, email_daily_digest, email_breaking_news
        FROM users
        WHERE unsubscribe_token = ?
    """, (unsubscribe_token,))

    row = cursor.fetchone()

    if not row:
        return False, "Invalid unsubscribe link", None

    user_id = row['id']
    user_email = row['email']

    # Update preferences based on type
    if email_type == 'all':
        cursor.execute("""
            UPDATE users
            SET email_daily_digest = 0, email_breaking_news = 0
            WHERE id = ?
        """, (user_id,))
        message = "You have been unsubscribed from all emails"
    elif email_type == 'digest':
        cursor.execute("""
            UPDATE users
            SET email_daily_digest = 0
            WHERE id = ?
        """, (user_id,))
        message = "You have been unsubscribed from daily digests"
    elif email_type == 'breaking_news':
        cursor.execute("""
            UPDATE users
            SET email_breaking_news = 0
            WHERE id = ?
        """, (user_id,))
        message = "You have been unsubscribed from breaking news alerts"
    else:
        return False, "Invalid email type", None

    db.commit()

    return True, message, user_email


def update_user_profile(db, user_id: int, name: Optional[str] = None) -> tuple[bool, str]:
    """
    Update user profile information
    Returns: (success, message)
    """
    cursor = db.cursor()

    # Verify user exists
    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        return False, "User not found"

    updates = []
    values = []

    if name is not None and name.strip():
        updates.append("name = ?")
        values.append(name.strip())

    if not updates:
        return False, "No changes provided"

    values.append(user_id)

    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
    cursor.execute(query, tuple(values))

    db.commit()

    return True, "Profile updated successfully"


# =============== Session Management Functions ===============

def parse_user_agent(user_agent: str) -> str:
    """Parse user agent string to extract device/browser info"""
    if not user_agent:
        return "Unknown Device"

    # Simple parsing - in production, use a library like user-agents
    ua = user_agent.lower()

    if 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        if 'android' in ua:
            return "Android Mobile"
        elif 'iphone' in ua or 'ipad' in ua:
            return "iOS Device"
        else:
            return "Mobile Device"
    elif 'windows' in ua:
        return "Windows PC"
    elif 'mac' in ua:
        return "Mac"
    elif 'linux' in ua:
        return "Linux"
    else:
        return "Unknown Device"


def create_session(db, user_id: int, session_id: str, ip_address: str,
                   user_agent: str, remember_me: bool = False) -> bool:
    """
    Create new session record
    Returns: True if created successfully
    """
    cursor = db.cursor()

    device_info = parse_user_agent(user_agent)
    now = datetime.utcnow().isoformat()

    # Set expiration based on remember_me
    if remember_me:
        expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()
    else:
        expires_at = (datetime.utcnow() + timedelta(days=1)).isoformat()

    try:
        cursor.execute("""
            INSERT INTO user_sessions
            (user_id, session_id, ip_address, user_agent, device_info, remember_me, created_at, last_activity, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, session_id, ip_address, user_agent, device_info, 1 if remember_me else 0, now, now, expires_at))

        db.commit()
        return True
    except Exception:
        return False


def update_session_activity(db, session_id: str) -> bool:
    """Update last_activity timestamp for a session"""
    cursor = db.cursor()

    now = datetime.utcnow().isoformat()

    cursor.execute("""
        UPDATE user_sessions
        SET last_activity = ?
        WHERE session_id = ?
    """, (now, session_id))

    db.commit()
    return cursor.rowcount > 0


def get_active_sessions(db, user_id: int) -> list[Dict[str, Any]]:
    """
    Get all active (non-expired) sessions for a user
    Returns: List of session dictionaries
    """
    cursor = db.cursor()

    now = datetime.utcnow().isoformat()

    cursor.execute("""
        SELECT id, session_id, ip_address, device_info, created_at, last_activity, remember_me
        FROM user_sessions
        WHERE user_id = ?
        AND (expires_at IS NULL OR expires_at > ?)
        ORDER BY last_activity DESC
    """, (user_id, now))

    sessions = []
    for row in cursor.fetchall():
        sessions.append({
            'id': row['id'],
            'session_id': row['session_id'],
            'ip_address': row['ip_address'],
            'device_info': row['device_info'],
            'created_at': row['created_at'],
            'last_activity': row['last_activity'],
            'remember_me': bool(row['remember_me'])
        })

    return sessions


def revoke_session(db, user_id: int, session_id: str) -> tuple[bool, str]:
    """
    Revoke a specific session
    Returns: (success, message)
    """
    cursor = db.cursor()

    # Verify session belongs to user
    cursor.execute("""
        SELECT id FROM user_sessions
        WHERE session_id = ? AND user_id = ?
    """, (session_id, user_id))

    if not cursor.fetchone():
        return False, "Session not found"

    # Delete the session
    cursor.execute("""
        DELETE FROM user_sessions
        WHERE session_id = ? AND user_id = ?
    """, (session_id, user_id))

    db.commit()
    return True, "Session revoked successfully"


def revoke_all_sessions_except(db, user_id: int, current_session_id: str) -> tuple[bool, str]:
    """
    Revoke all sessions for a user except the current one
    Returns: (success, message)
    """
    cursor = db.cursor()

    cursor.execute("""
        DELETE FROM user_sessions
        WHERE user_id = ? AND session_id != ?
    """, (user_id, current_session_id))

    revoked_count = cursor.rowcount
    db.commit()

    return True, f"Revoked {revoked_count} session(s)"


def cleanup_expired_sessions(db) -> int:
    """
    Remove expired sessions from database
    Returns: Number of sessions removed
    """
    cursor = db.cursor()

    now = datetime.utcnow().isoformat()

    cursor.execute("""
        DELETE FROM user_sessions
        WHERE expires_at IS NOT NULL AND expires_at < ?
    """, (now,))

    removed_count = cursor.rowcount
    db.commit()

    return removed_count


def log_login_attempt(db, email: str, user_id: Optional[int], ip_address: str,
                      user_agent: str, success: bool, failure_reason: Optional[str] = None) -> bool:
    """
    Log login attempt to login_history table
    Returns: True if logged successfully
    """
    cursor = db.cursor()

    device_info = parse_user_agent(user_agent)
    now = datetime.utcnow().isoformat()

    try:
        cursor.execute("""
            INSERT INTO login_history
            (user_id, email, ip_address, user_agent, device_info, login_time, success, failure_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, email, ip_address, user_agent, device_info, now, 1 if success else 0, failure_reason))

        db.commit()
        return True
    except Exception:
        return False


def get_login_history(db, user_id: int, limit: int = 20) -> list[Dict[str, Any]]:
    """
    Get login history for a user
    Returns: List of login attempt dictionaries
    """
    cursor = db.cursor()

    cursor.execute("""
        SELECT ip_address, device_info, login_time, success, failure_reason
        FROM login_history
        WHERE user_id = ?
        ORDER BY login_time DESC
        LIMIT ?
    """, (user_id, limit))

    history = []
    for row in cursor.fetchall():
        history.append({
            'ip_address': row['ip_address'],
            'device_info': row['device_info'],
            'login_time': row['login_time'],
            'success': bool(row['success']),
            'failure_reason': row['failure_reason']
        })

    return history


def detect_suspicious_login(db, user_id: int, ip_address: str, device_info: str) -> tuple[bool, str]:
    """
    Detect if login is from a new/suspicious location or device
    Returns: (is_suspicious, reason)
    """
    cursor = db.cursor()

    # Check if this IP has been used before by this user
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM login_history
        WHERE user_id = ? AND ip_address = ? AND success = 1
    """, (user_id, ip_address))

    ip_used_before = cursor.fetchone()['count'] > 0

    # Check if this device has been used before
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM login_history
        WHERE user_id = ? AND device_info = ? AND success = 1
    """, (user_id, device_info))

    device_used_before = cursor.fetchone()['count'] > 0

    if not ip_used_before and not device_used_before:
        return True, "New device and location"
    elif not ip_used_before:
        return True, "New location"
    elif not device_used_before:
        return True, "New device"
    else:
        return False, ""
