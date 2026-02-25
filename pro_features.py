"""
Pro Feature Gating for Aviation Intelligence Hub
Decorators and helpers to enforce Free vs Pro tier limits
"""
from functools import wraps
from flask import redirect, url_for, flash, request, jsonify
from flask_login import current_user
from datetime import datetime, date
import logging

log = logging.getLogger("aih")


def pro_required(f):
    """
    Decorator to require Pro subscription for a route or function
    Redirects to upgrade page if user is not Pro
    Works with both regular routes and API endpoints
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({"error": "Authentication required", "upgrade_required": True}), 401
            flash('Please log in to access this feature', 'error')
            return redirect(url_for('auth.login'))

        # Check if user has Pro subscription
        from gamification import is_pro_user
        from app import get_db

        db = get_db()
        if not is_pro_user(db, current_user.id):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({
                    "error": "Pro subscription required",
                    "upgrade_required": True,
                    "message": "Upgrade to Pro to access unlimited features"
                }), 403
            flash('⚡ This feature requires a Pro subscription. Upgrade now to unlock!', 'warning')
            return redirect(url_for('upgrade'))

        return f(*args, **kwargs)
    return decorated_function


def check_ai_summary_limit(db, user_id: int) -> tuple[bool, int, int]:
    """
    Check if user has reached their daily AI summary limit
    Returns: (can_generate, used_today, limit)
    Free: 10/day, Pro: unlimited
    """
    from gamification import is_pro_user

    # Pro users have unlimited
    if is_pro_user(db, user_id):
        return True, 0, -1  # -1 indicates unlimited

    # Free users: 10 per day
    today = date.today().isoformat()
    cursor = db.cursor()

    cursor.execute("""
        SELECT COUNT(*) as count
        FROM ai_summary_usage
        WHERE user_id = ? AND date = ?
    """, (user_id, today))

    result = cursor.fetchone()
    used_today = result['count'] if result else 0
    limit = 10

    can_generate = used_today < limit
    return can_generate, used_today, limit


def record_ai_summary_usage(db, user_id: int, news_item_id: int):
    """Record that user generated an AI summary"""
    today = date.today().isoformat()
    now = datetime.utcnow().isoformat()

    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO ai_summary_usage (user_id, news_item_id, date, created_at)
        VALUES (?, ?, ?, ?)
    """, (user_id, news_item_id, today, now))
    db.commit()


def check_saved_articles_limit(db, user_id: int) -> tuple[bool, int, int]:
    """
    Check if user has reached their saved articles limit
    Returns: (can_save, current_count, limit)
    Free: 5, Pro: unlimited
    """
    from gamification import is_pro_user

    # Pro users have unlimited
    if is_pro_user(db, user_id):
        return True, 0, -1  # -1 indicates unlimited

    # Free users: 5 saved articles
    cursor = db.cursor()
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM saved_articles
        WHERE user_id = ? AND is_deleted = 0
    """, (user_id,))

    result = cursor.fetchone()
    current_count = result['count'] if result else 0
    limit = 5

    can_save = current_count < limit
    return can_save, current_count, limit


def save_article(db, user_id: int, news_item_id: int) -> tuple[bool, str]:
    """
    Save an article for a user
    Returns: (success, message)
    """
    # Check if already saved
    cursor = db.cursor()
    cursor.execute("""
        SELECT id, is_deleted FROM saved_articles
        WHERE user_id = ? AND news_item_id = ?
    """, (user_id, news_item_id))

    existing = cursor.fetchone()
    if existing and not existing['is_deleted']:
        return False, "Article already saved"

    # Check limit
    can_save, current_count, limit = check_saved_articles_limit(db, user_id)
    if not can_save:
        return False, f"Free users can save up to {limit} articles. Upgrade to Pro for unlimited saves!"

    now = datetime.utcnow().isoformat()

    if existing:
        # Undelete existing save
        cursor.execute("""
            UPDATE saved_articles
            SET is_deleted = 0, saved_at = ?
            WHERE id = ?
        """, (now, existing['id']))
    else:
        # Create new save
        cursor.execute("""
            INSERT INTO saved_articles (user_id, news_item_id, saved_at, is_deleted)
            VALUES (?, ?, ?, 0)
        """, (user_id, news_item_id, now))

    db.commit()
    return True, "Article saved successfully"


def unsave_article(db, user_id: int, news_item_id: int) -> tuple[bool, str]:
    """
    Unsave an article for a user (soft delete)
    Returns: (success, message)
    """
    cursor = db.cursor()
    cursor.execute("""
        UPDATE saved_articles
        SET is_deleted = 1
        WHERE user_id = ? AND news_item_id = ?
    """, (user_id, news_item_id))

    if cursor.rowcount > 0:
        db.commit()
        return True, "Article removed from saved"

    return False, "Article was not saved"


def get_saved_articles(db, user_id: int, limit: int = 50, offset: int = 0):
    """Get user's saved articles with pagination"""
    cursor = db.cursor()
    cursor.execute("""
        SELECT
            n.id, n.airline, n.content, n.sentiment, n.sentiment_label,
            n.source, n.date, n.ai_summary,
            sa.saved_at
        FROM saved_articles sa
        JOIN news_items n ON sa.news_item_id = n.id
        WHERE sa.user_id = ? AND sa.is_deleted = 0
        ORDER BY sa.saved_at DESC
        LIMIT ? OFFSET ?
    """, (user_id, limit, offset))

    return [dict(row) for row in cursor.fetchall()]


def is_article_saved(db, user_id: int, news_item_id: int) -> bool:
    """Check if article is saved by user"""
    cursor = db.cursor()
    cursor.execute("""
        SELECT id FROM saved_articles
        WHERE user_id = ? AND news_item_id = ? AND is_deleted = 0
    """, (user_id, news_item_id))

    return cursor.fetchone() is not None


def can_receive_breaking_news(db, user_id: int) -> bool:
    """
    Check if user can receive breaking news alerts
    Breaking news is Pro-only feature
    """
    from gamification import is_pro_user

    # Check if user has breaking news enabled AND is Pro
    cursor = db.cursor()
    cursor.execute("""
        SELECT email_breaking_news FROM users WHERE id = ?
    """, (user_id,))

    result = cursor.fetchone()
    if not result or not result['email_breaking_news']:
        return False

    # Must be Pro user
    return is_pro_user(db, user_id)


def get_digest_frequency(db, user_id: int) -> str:
    """
    Get email digest frequency for user
    Free: weekly (Sunday), Pro: daily
    Returns: 'daily' or 'weekly'
    """
    from gamification import is_pro_user

    if is_pro_user(db, user_id):
        return 'daily'
    return 'weekly'


def should_send_digest_today(db, user_id: int, current_day: str) -> bool:
    """
    Check if user should receive digest today based on their tier
    current_day: day of week (e.g., 'Monday', 'Sunday')
    Free: weekly on Sunday, Pro: daily
    """
    frequency = get_digest_frequency(db, user_id)

    if frequency == 'daily':
        return True
    elif frequency == 'weekly':
        # Free users get digest on Sunday only
        return current_day == 'Sunday'

    return False
