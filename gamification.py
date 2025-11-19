"""
Gamification and Subscription Management
Points, badges, levels, streaks, and Pro tier management
"""
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import logging

log = logging.getLogger(__name__)

# Gamification constants
POINTS_CONFIG = {
    'login': 10,
    'streak_bonus': 25,  # Bonus for maintaining streak
    'article_read': 5,
    'badge_earned': 50,
    'level_up': 100,
    'pro_upgrade': 500
}

LEVEL_THRESHOLDS = [
    0,      # Level 1
    100,    # Level 2
    250,    # Level 3
    500,    # Level 4
    1000,   # Level 5
    2000,   # Level 6
    4000,   # Level 7
    8000,   # Level 8
    15000,  # Level 9
    30000   # Level 10
]


def _init_default_badges(db):
    """Initialize default badge achievements"""
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()

    badges = [
        # Free tier badges
        ('First Steps', 'Complete your first login', '🚶', 'logins', 1, 'free'),
        ('News Enthusiast', 'Read 10 articles', '📰', 'articles', 10, 'free'),
        ('Dedicated Reader', 'Read 50 articles', '📚', 'articles', 50, 'free'),
        ('News Addict', 'Read 100 articles', '🔥', 'articles', 100, 'free'),
        ('Week Warrior', 'Login 7 days in a row', '⭐', 'streak', 7, 'free'),
        ('Streak Master', 'Login 30 days in a row', '🏆', 'streak', 30, 'free'),
        ('Streak Legend', 'Login 100 days in a row', '👑', 'streak', 100, 'free'),
        ('Early Adopter', 'Among first 100 users', '🎖️', 'early_adopter', 100, 'free'),
        ('Point Collector', 'Earn 500 points', '💰', 'points', 500, 'free'),
        ('Point Master', 'Earn 2000 points', '💎', 'points', 2000, 'free'),

        # Pro tier badges
        ('Pro Member', 'Upgrade to Pro subscription', '⚡', 'pro_upgrade', 1, 'pro'),
        ('Pro Veteran', 'Maintain Pro for 6 months', '🌟', 'pro_upgrade', 180, 'pro'),
    ]

    for name, description, icon, req_type, req_value, tier in badges:
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO badges (name, description, icon, requirement_type, requirement_value, tier, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, description, icon, req_type, req_value, tier, now))
        except Exception as e:
            log.warning(f"Could not insert badge {name}: {e}")

    db.commit()


def init_user_gamification(db, user_id: int) -> bool:
    """
    Initialize gamification record for new user
    Called when user creates account
    """
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()

    try:
        cursor.execute("""
            INSERT INTO user_gamification (user_id, points, level, created_at, updated_at)
            VALUES (?, 0, 1, ?, ?)
        """, (user_id, now, now))

        db.commit()
        return True
    except Exception as e:
        log.error(f"Error initializing gamification for user {user_id}: {e}")
        return False


def get_user_gamification(db, user_id: int) -> Optional[Dict[str, Any]]:
    """Get user's gamification stats"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT * FROM user_gamification WHERE user_id = ?
    """, (user_id,))

    row = cursor.fetchone()
    if not row:
        # Initialize if doesn't exist
        init_user_gamification(db, user_id)
        return get_user_gamification(db, user_id)

    return dict(row)


def award_points(db, user_id: int, activity_type: str, description: str = None) -> tuple[int, bool]:
    """
    Award points for an activity and check for level ups
    Returns: (points_earned, leveled_up)
    """
    if activity_type not in POINTS_CONFIG:
        log.warning(f"Unknown activity type: {activity_type}")
        return 0, False

    points = POINTS_CONFIG[activity_type]
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()

    # Get current stats
    stats = get_user_gamification(db, user_id)
    old_points = stats['points']
    old_level = stats['level']
    new_points = old_points + points

    # Calculate new level
    new_level = old_level
    for level, threshold in enumerate(LEVEL_THRESHOLDS, start=1):
        if new_points >= threshold:
            new_level = level

    leveled_up = new_level > old_level

    # Update points and level
    cursor.execute("""
        UPDATE user_gamification
        SET points = ?, level = ?, updated_at = ?
        WHERE user_id = ?
    """, (new_points, new_level, now, user_id))

    # Log activity
    cursor.execute("""
        INSERT INTO gamification_activities (user_id, activity_type, points_earned, description, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, activity_type, points, description, now))

    db.commit()

    # If leveled up, award bonus points
    if leveled_up:
        log.info(f"User {user_id} leveled up to level {new_level}")
        award_points(db, user_id, 'level_up', f"Reached level {new_level}")

    return points, leveled_up


def check_and_award_badges(db, user_id: int) -> List[Dict[str, Any]]:
    """
    Check if user has earned any new badges
    Returns: List of newly earned badges
    """
    cursor = db.cursor()
    stats = get_user_gamification(db, user_id)
    newly_earned = []

    # Get all badges user hasn't earned yet
    cursor.execute("""
        SELECT b.* FROM badges b
        WHERE b.id NOT IN (
            SELECT badge_id FROM user_badges WHERE user_id = ?
        )
    """, (user_id,))

    available_badges = [dict(row) for row in cursor.fetchall()]

    for badge in available_badges:
        earned = False

        if badge['requirement_type'] == 'logins':
            earned = stats['total_logins'] >= badge['requirement_value']
        elif badge['requirement_type'] == 'streak':
            earned = stats['current_streak'] >= badge['requirement_value'] or stats['best_streak'] >= badge['requirement_value']
        elif badge['requirement_type'] == 'articles':
            earned = stats['articles_read'] >= badge['requirement_value']
        elif badge['requirement_type'] == 'points':
            earned = stats['points'] >= badge['requirement_value']
        elif badge['requirement_type'] == 'early_adopter':
            # Check if user is among first N users
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE id <= ?", (user_id,))
            user_position = cursor.fetchone()['count']
            earned = user_position <= badge['requirement_value']
        elif badge['requirement_type'] == 'pro_upgrade':
            # Check if user is pro
            earned = is_pro_user(db, user_id)

        if earned:
            # Award badge
            now = datetime.utcnow().isoformat()
            try:
                cursor.execute("""
                    INSERT INTO user_badges (user_id, badge_id, earned_at)
                    VALUES (?, ?, ?)
                """, (user_id, badge['id'], now))

                # Award points for earning badge
                award_points(db, user_id, 'badge_earned', f"Earned: {badge['name']}")

                newly_earned.append(badge)
                log.info(f"User {user_id} earned badge: {badge['name']}")
            except Exception as e:
                log.error(f"Error awarding badge {badge['name']} to user {user_id}: {e}")

    db.commit()
    return newly_earned


def get_user_badges(db, user_id: int) -> List[Dict[str, Any]]:
    """Get all badges earned by user"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT b.*, ub.earned_at
        FROM badges b
        JOIN user_badges ub ON b.id = ub.badge_id
        WHERE ub.user_id = ?
        ORDER BY ub.earned_at DESC
    """, (user_id,))

    return [dict(row) for row in cursor.fetchall()]


def track_login(db, user_id: int) -> Dict[str, Any]:
    """
    Track daily login for streak calculation
    Returns: dict with streak info and points earned
    """
    cursor = db.cursor()
    stats = get_user_gamification(db, user_id)
    now = datetime.utcnow()
    today = now.date().isoformat()

    last_login_date = stats.get('last_login_date')

    # Update total logins
    total_logins = stats['total_logins'] + 1

    # Calculate streak
    current_streak = stats['current_streak']
    best_streak = stats['best_streak']
    streak_bonus_points = 0

    if last_login_date:
        last_date = datetime.fromisoformat(last_login_date).date()
        today_date = now.date()

        if last_date == today_date:
            # Already logged in today, no streak update
            return {'streak_continued': False, 'current_streak': current_streak, 'points_earned': 0}
        elif last_date == today_date - timedelta(days=1):
            # Logged in yesterday, continue streak
            current_streak += 1

            # Award streak bonus every 7 days
            if current_streak % 7 == 0:
                streak_bonus_points = POINTS_CONFIG['streak_bonus']
        else:
            # Streak broken, reset to 1
            current_streak = 1
    else:
        # First login
        current_streak = 1

    # Update best streak
    if current_streak > best_streak:
        best_streak = current_streak

    # Update database
    cursor.execute("""
        UPDATE user_gamification
        SET total_logins = ?, current_streak = ?, best_streak = ?, last_login_date = ?, updated_at = ?
        WHERE user_id = ?
    """, (total_logins, current_streak, best_streak, today, now.isoformat(), user_id))

    db.commit()

    # Award points
    points_earned, leveled_up = award_points(db, user_id, 'login', f"Daily login #{total_logins}")

    if streak_bonus_points > 0:
        bonus_points, _ = award_points(db, user_id, 'streak_bonus', f"Streak bonus: {current_streak} days")
        points_earned += bonus_points

    # Check for new badges
    check_and_award_badges(db, user_id)

    return {
        'streak_continued': True,
        'current_streak': current_streak,
        'best_streak': best_streak,
        'points_earned': points_earned,
        'leveled_up': leveled_up
    }


def track_article_read(db, user_id: int, article_title: str = None) -> int:
    """
    Track article reading
    Returns: points earned
    """
    cursor = db.cursor()
    stats = get_user_gamification(db, user_id)

    articles_read = stats['articles_read'] + 1

    cursor.execute("""
        UPDATE user_gamification
        SET articles_read = ?, updated_at = ?
        WHERE user_id = ?
    """, (articles_read, datetime.utcnow().isoformat(), user_id))

    db.commit()

    # Award points
    points_earned, _ = award_points(db, user_id, 'article_read', f"Read article: {article_title or 'Unknown'}")

    # Check for new badges
    check_and_award_badges(db, user_id)

    return points_earned


def get_leaderboard(db, limit: int = 10) -> List[Dict[str, Any]]:
    """Get top users by points"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT u.id, u.name, u.email, ug.points, ug.level, ug.current_streak
        FROM users u
        JOIN user_gamification ug ON u.id = ug.user_id
        ORDER BY ug.points DESC
        LIMIT ?
    """, (limit,))

    return [dict(row) for row in cursor.fetchall()]


# ============================================================================
# SUBSCRIPTION MANAGEMENT
# ============================================================================

def is_pro_user(db, user_id: int) -> bool:
    """Check if user has active Pro subscription"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT subscription_tier, subscription_status, subscription_end
        FROM users
        WHERE id = ?
    """, (user_id,))

    row = cursor.fetchone()
    if not row:
        return False

    row_dict = dict(row)

    # Check tier and status
    if row_dict['subscription_tier'] != 'pro':
        return False

    if row_dict['subscription_status'] not in ('active', 'trial'):
        return False

    # Check expiration
    if row_dict['subscription_end']:
        expiration = datetime.fromisoformat(row_dict['subscription_end'])
        if datetime.utcnow() > expiration:
            # Expired, update status
            cursor.execute("""
                UPDATE users
                SET subscription_status = 'expired', subscription_tier = 'free'
                WHERE id = ?
            """, (user_id,))
            db.commit()
            return False

    return True


def get_subscription_info(db, user_id: int) -> Dict[str, Any]:
    """Get user's subscription information"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT subscription_tier, subscription_status, subscription_start, subscription_end, revenuecat_user_id
        FROM users
        WHERE id = ?
    """, (user_id,))

    row = cursor.fetchone()
    if not row:
        return None

    info = dict(row)
    info['is_pro'] = is_pro_user(db, user_id)

    # Calculate days remaining if pro
    if info['is_pro'] and info['subscription_end']:
        expiration = datetime.fromisoformat(info['subscription_end'])
        days_remaining = (expiration - datetime.utcnow()).days
        info['days_remaining'] = max(0, days_remaining)
    else:
        info['days_remaining'] = 0

    return info


def upgrade_to_pro(db, user_id: int, revenuecat_user_id: str, is_trial: bool = False,
                   subscription_end: datetime = None) -> bool:
    """
    Upgrade user to Pro subscription
    Called from RevenueCat webhook or manual upgrade
    """
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()

    # Default to 1 month from now if not specified
    if not subscription_end:
        subscription_end = datetime.utcnow() + timedelta(days=30)

    subscription_end_iso = subscription_end.isoformat()
    status = 'trial' if is_trial else 'active'

    try:
        cursor.execute("""
            UPDATE users
            SET subscription_tier = 'pro',
                subscription_status = ?,
                subscription_start = ?,
                subscription_end = ?,
                revenuecat_user_id = ?
            WHERE id = ?
        """, (status, now, subscription_end_iso, revenuecat_user_id, user_id))

        db.commit()

        # Award gamification points
        award_points(db, user_id, 'pro_upgrade', 'Upgraded to Pro')
        check_and_award_badges(db, user_id)

        log.info(f"User {user_id} upgraded to Pro (RevenueCat: {revenuecat_user_id})")
        return True
    except Exception as e:
        log.error(f"Error upgrading user {user_id} to Pro: {e}")
        return False


def downgrade_to_free(db, user_id: int) -> bool:
    """Downgrade user to Free tier"""
    cursor = db.cursor()

    try:
        cursor.execute("""
            UPDATE users
            SET subscription_tier = 'free',
                subscription_status = 'inactive'
            WHERE id = ?
        """, (user_id,))

        db.commit()
        log.info(f"User {user_id} downgraded to Free")
        return True
    except Exception as e:
        log.error(f"Error downgrading user {user_id}: {e}")
        return False


def log_subscription_event(db, user_id: Optional[int], event_type: str, revenuecat_user_id: str,
                           product_id: str = None, purchased_at: datetime = None,
                           expiration_at: datetime = None, is_trial: bool = False,
                           raw_data: str = None) -> bool:
    """Log subscription event from RevenueCat webhook"""
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()

    purchased_at_iso = purchased_at.isoformat() if purchased_at else None
    expiration_at_iso = expiration_at.isoformat() if expiration_at else None

    try:
        cursor.execute("""
            INSERT INTO subscription_events
            (user_id, event_type, revenuecat_user_id, product_id, purchased_at, expiration_at, is_trial, raw_data, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, event_type, revenuecat_user_id, product_id, purchased_at_iso, expiration_at_iso,
              1 if is_trial else 0, raw_data, now))

        db.commit()
        return True
    except Exception as e:
        log.error(f"Error logging subscription event: {e}")
        return False


def get_user_by_revenuecat_id(db, revenuecat_user_id: str) -> Optional[int]:
    """Get user ID by RevenueCat user ID"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT id FROM users WHERE revenuecat_user_id = ?
    """, (revenuecat_user_id,))

    row = cursor.fetchone()
    return row['id'] if row else None
