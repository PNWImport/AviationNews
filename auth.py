"""
Authentication routes for Aviation Intelligence Hub
Signup, Login, Logout, Email Verification
REDTEAM SECURE: Aggressive rate limiting, input sanitization, brute force protection
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, g, session
from flask_login import login_user, logout_user, login_required, current_user
from models import (
    get_user_by_email, create_user, verify_user_email,
    update_last_login, get_user_by_id,
    create_password_reset_token, verify_password_reset_token, reset_user_password,
    get_user_preferences, update_user_preferences, unsubscribe_user_by_token, update_user_profile,
    create_session, get_active_sessions, revoke_session, revoke_all_sessions_except,
    log_login_attempt, get_login_history, detect_suspicious_login, parse_user_agent
)
from email_service import email_service
from sanitizer import sanitizer
from functools import wraps
import logging
import time
import hashlib
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__)

# Brute force protection: Track failed login attempts
failed_login_attempts = {}  # IP -> (count, lockout_until)
FAILED_LOGIN_THRESHOLD = 5
LOCKOUT_DURATION = 900  # 15 minutes


def get_client_ip():
    """Get real client IP (behind proxy support)"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr or 'unknown'


def check_rate_limit(key: str, max_attempts: int, window: int) -> bool:
    """
    Check if rate limit exceeded
    key: unique identifier (IP, email, etc.)
    max_attempts: max attempts in window
    window: time window in seconds
    Returns: True if rate limit exceeded
    """
    # This is a simple in-memory implementation
    # For production, use Redis or similar
    cache_key = f"ratelimit_{key}"

    if not hasattr(g, 'rate_limits'):
        g.rate_limits = {}

    now = time.time()

    if cache_key in g.rate_limits:
        attempts, first_attempt = g.rate_limits[cache_key]

        # Reset if window expired
        if now - first_attempt > window:
            g.rate_limits[cache_key] = (1, now)
            return False

        # Check if exceeded
        if attempts >= max_attempts:
            return True

        # Increment
        g.rate_limits[cache_key] = (attempts + 1, first_attempt)
    else:
        g.rate_limits[cache_key] = (1, now)

    return False


def check_brute_force(ip: str) -> tuple[bool, int]:
    """
    Check if IP is locked out due to brute force
    Returns: (is_locked, seconds_until_unlock)
    """
    if ip in failed_login_attempts:
        count, lockout_until = failed_login_attempts[ip]

        if lockout_until and datetime.utcnow() < lockout_until:
            remaining = int((lockout_until - datetime.utcnow()).total_seconds())
            return True, remaining

        # Lockout expired, reset
        if lockout_until and datetime.utcnow() >= lockout_until:
            del failed_login_attempts[ip]

    return False, 0


def record_failed_login(ip: str):
    """Record failed login attempt"""
    if ip not in failed_login_attempts:
        failed_login_attempts[ip] = [1, None]
    else:
        count, lockout = failed_login_attempts[ip]
        count += 1
        failed_login_attempts[ip][0] = count

        # Trigger lockout
        if count >= FAILED_LOGIN_THRESHOLD:
            lockout_until = datetime.utcnow() + timedelta(seconds=LOCKOUT_DURATION)
            failed_login_attempts[ip][1] = lockout_until
            log.warning(f"IP {ip} locked out until {lockout_until} (failed attempts: {count})")


def clear_failed_login(ip: str):
    """Clear failed login attempts on successful login"""
    if ip in failed_login_attempts:
        del failed_login_attempts[ip]


@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """User signup with email verification - REDTEAM SECURE"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        client_ip = get_client_ip()

        # SECURITY: Rate limiting - 3 signups per hour per IP
        if check_rate_limit(f"signup_{client_ip}", max_attempts=3, window=3600):
            log.warning(f"Signup rate limit exceeded for IP: {client_ip}")
            flash('Too many signup attempts. Please try again later.', 'error')
            return render_template('signup.html'), 429

        # SECURITY: Honeypot field check (bot detection)
        honeypot = request.form.get('website', '')  # Should be empty
        if sanitizer.check_honeypot(honeypot):
            log.warning(f"Bot detected in signup (honeypot): {client_ip}")
            # Silently fail - don't tell bots they're detected
            time.sleep(2)  # Slow down bots
            flash('Account created! Check your email to verify.', 'success')
            return redirect(url_for('auth.login'))

        # Get form data
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')

        # SECURITY: Sanitize inputs
        sanitized = sanitizer.sanitize_signup_data(name, email)

        if sanitized['errors']:
            for error in sanitized['errors']:
                flash(error, 'error')
            log.warning(f"Signup validation failed: {sanitized['errors']} - IP: {client_ip}")
            return render_template('signup.html')

        name = sanitized['name']
        email = sanitized['email']

        # Validation
        if not name or not email or not password:
            flash('All fields are required', 'error')
            return render_template('signup.html')

        if password != password_confirm:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')

        # Create user
        from app import get_db
        db = get_db()

        user, error = create_user(db, email, name, password)

        if error:
            flash(error, 'error')
            log.info(f"Signup failed: {error} - Email: {email} - IP: {client_ip}")
            return render_template('signup.html')

        # Send verification email
        base_url = request.url_root.rstrip('/')
        email_sent = email_service.send_verification_email(
            user.email,
            user.name,
            user.verification_token,
            base_url
        )

        log.info(f"New user signup: {email} - IP: {client_ip}")

        if email_sent:
            flash(
                f'Account created! Check your email ({email}) to verify your account. '
                'Link expires in 12 hours.',
                'success'
            )
        else:
            flash(
                'Account created, but verification email failed to send. '
                'Please contact support.',
                'warning'
            )

        return redirect(url_for('auth.login'))

    return render_template('signup.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login - REDTEAM SECURE with brute force protection"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        client_ip = get_client_ip()

        # SECURITY: Check if IP is locked out
        is_locked, remaining_time = check_brute_force(client_ip)
        if is_locked:
            minutes = remaining_time // 60
            flash(
                f'Too many failed login attempts. Account locked for {minutes} more minutes.',
                'error'
            )
            log.warning(f"Locked IP attempted login: {client_ip}")
            return render_template('login.html'), 429

        # SECURITY: Rate limiting - 10 login attempts per 5 minutes
        if check_rate_limit(f"login_{client_ip}", max_attempts=10, window=300):
            log.warning(f"Login rate limit exceeded for IP: {client_ip}")
            flash('Too many login attempts. Please try again in a few minutes.', 'error')
            return render_template('login.html'), 429

        # Timing attack prevention - start timer
        request_start = time.time()

        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        # SECURITY: Sanitize email
        email = sanitizer.clean_email(email)

        if not email or not password:
            # Constant-time response
            time.sleep(max(0, 0.5 - (time.time() - request_start)))
            flash('Email and password are required', 'error')
            return render_template('login.html')

        # Get user
        from app import get_db
        db = get_db()
        user = get_user_by_email(db, email)

        # SECURITY: Constant-time password check
        # Always check password even if user doesn't exist (timing attack prevention)
        password_valid = False
        if user:
            password_valid = user.check_password(password)
        else:
            # Dummy check to maintain constant time
            import bcrypt
            bcrypt.checkpw(b'dummy', bcrypt.hashpw(b'dummy', bcrypt.gensalt()))

        if not user or not password_valid:
            # Record failed attempt
            record_failed_login(client_ip)

            # Log failed login attempt to database
            user_agent = request.headers.get('User-Agent', 'Unknown')
            user_id = user.id if user else None
            log_login_attempt(db, email, user_id, client_ip, user_agent, success=False, failure_reason='Invalid credentials')

            # Constant-time response
            elapsed = time.time() - request_start
            time.sleep(max(0, 0.5 - elapsed))

            flash('Invalid email or password', 'error')
            log.warning(f"Failed login attempt: {email} - IP: {client_ip}")
            return render_template('login.html')

        # Check if verified
        if not user.is_verified:
            elapsed = time.time() - request_start
            time.sleep(max(0, 0.5 - elapsed))

            flash(
                'Please verify your email address first. Check your inbox for the verification link.',
                'error'
            )
            return render_template('login.html')

        # Check if active
        if not user.is_active:
            elapsed = time.time() - request_start
            time.sleep(max(0, 0.5 - elapsed))

            flash('Your account has been deactivated. Please contact support.', 'error')
            log.warning(f"Inactive account login attempt: {email} - IP: {client_ip}")
            return render_template('login.html')

        # SECURITY: Clear failed attempts on successful login
        clear_failed_login(client_ip)

        # Login user
        login_user(user, remember=remember)
        update_last_login(db, user.id)

        # PHASE 6: Session Management
        # Get session ID and user agent
        user_agent = request.headers.get('User-Agent', 'Unknown')
        session_id = session.get('_id')

        # If session doesn't have an ID yet, create one
        if not session_id:
            import secrets
            session_id = secrets.token_urlsafe(32)
            session['_id'] = session_id

        # Create session record
        create_session(db, user.id, session_id, client_ip, user_agent, remember_me=remember)

        # Log successful login attempt
        log_login_attempt(db, email, user.id, client_ip, user_agent, success=True)

        # Detect suspicious login (new device/location)
        is_suspicious, reason = detect_suspicious_login(db, user.id, client_ip, parse_user_agent(user_agent))
        if is_suspicious:
            flash(f'Security Notice: {reason}. If this wasn\'t you, please change your password immediately.', 'warning')
            log.warning(f"Suspicious login detected for {user.email}: {reason} - IP: {client_ip}")

        # Gamification: Track login for streaks and points
        from gamification import track_login, check_and_award_badges
        streak_info = track_login(db, user.id)
        if streak_info['streak_continued'] and streak_info['current_streak'] > 1:
            flash(f"🔥 {streak_info['current_streak']}-day streak! +{streak_info['points_earned']} points", 'success')
        elif streak_info.get('points_earned', 0) > 0:
            flash(f"✨ +{streak_info['points_earned']} points for logging in!", 'success')

        # Check for new badges
        new_badges = check_and_award_badges(db, user.id)
        if new_badges:
            for badge in new_badges:
                flash(f"🏆 New badge unlocked: {badge['icon']} {badge['name']}!", 'success')

        log.info(f"User logged in: {user.email} - IP: {client_ip}")

        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)

        flash(f'Welcome back, {user.name}!', 'success')
        return redirect(url_for('index'))

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout - PHASE 6: Revoke session"""
    # Get current session ID
    from app import get_db
    db = get_db()
    session_id = session.get('_id')

    # Revoke session if it exists
    if session_id:
        revoke_session(db, current_user.id, session_id)
        log.info(f"Session revoked for user: {current_user.email} - session: {session_id}")

    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))


@auth_bp.route('/verify/<token>')
def verify_email(token):
    """Verify email address with token"""
    from app import get_db
    db = get_db()

    success, message = verify_user_email(db, token)

    if success:
        flash(message, 'success')

        # Send welcome email to the verified user
        # After verification, token is set to NULL, so find most recently verified user
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE verification_token IS NULL ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            user_data = dict(row)
            email_service.send_welcome_email(user_data['email'], user_data['name'])

        return redirect(url_for('auth.login'))
    else:
        flash(message, 'error')
        return redirect(url_for('auth.signup'))


@auth_bp.route('/account')
@login_required
def account():
    """User account settings"""
    return render_template('account.html', user=current_user)


@auth_bp.route('/account/update', methods=['POST'])
@login_required
def update_account():
    """Update account settings"""
    from app import get_db
    db = get_db()
    cursor = db.cursor()

    # Update email preferences
    email_daily = 1 if request.form.get('email_daily_digest') == 'on' else 0
    email_breaking = 1 if request.form.get('email_breaking_news') == 'on' else 0

    cursor.execute("""
        UPDATE users
        SET email_daily_digest = ?, email_breaking_news = ?
        WHERE id = ?
    """, (email_daily, email_breaking, current_user.id))
    db.commit()

    flash('Preferences updated successfully', 'success')
    return redirect(url_for('auth.account'))


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset request - REDTEAM SECURE"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        client_ip = get_client_ip()

        # SECURITY: Rate limiting - 3 reset requests per hour per IP
        if check_rate_limit(f"reset_{client_ip}", max_attempts=3, window=3600):
            log.warning(f"Password reset rate limit exceeded for IP: {client_ip}")
            flash('Too many reset requests. Please try again later.', 'error')
            return render_template('forgot_password.html'), 429

        email = request.form.get('email', '').strip()

        # SECURITY: Sanitize email
        email = sanitizer.clean_email(email)

        if not email:
            flash('Email address is required', 'error')
            return render_template('forgot_password.html')

        from app import get_db
        db = get_db()

        # Create reset token (always returns success to prevent email enumeration)
        success, token_or_message = create_password_reset_token(db, email)

        if success and token_or_message != "If that email exists, a password reset link has been sent":
            # Token was created, send email
            user = get_user_by_email(db, email)
            if user:
                base_url = request.url_root.rstrip('/')
                email_sent = email_service.send_password_reset_email(
                    user.email,
                    user.name,
                    token_or_message,
                    base_url
                )

                if email_sent:
                    log.info(f"Password reset email sent to: {email} - IP: {client_ip}")
                else:
                    log.warning(f"Failed to send password reset email to: {email}")

        # Always show same message (prevent email enumeration)
        flash(
            'If that email address is registered, you will receive a password reset link shortly. '
            'Check your inbox and spam folder.',
            'success'
        )
        return redirect(url_for('auth.login'))

    return render_template('forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token - REDTEAM SECURE"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    from app import get_db
    db = get_db()

    # Verify token on GET request
    if request.method == 'GET':
        is_valid, user_id, message = verify_password_reset_token(db, token)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('auth.forgot_password'))

        return render_template('reset_password.html', token=token)

    # POST request - reset password
    if request.method == 'POST':
        client_ip = get_client_ip()

        # Verify token is still valid
        is_valid, user_id, message = verify_password_reset_token(db, token)
        if not is_valid:
            flash(message, 'error')
            log.warning(f"Invalid password reset attempt - IP: {client_ip}")
            return redirect(url_for('auth.forgot_password'))

        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')

        # Validation
        if not password or not password_confirm:
            flash('All fields are required', 'error')
            return render_template('reset_password.html', token=token)

        if password != password_confirm:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)

        # Reset password (includes history check)
        success, result_message = reset_user_password(db, user_id, token, password)

        if success:
            flash(
                'Password reset successfully! You can now login with your new password.',
                'success'
            )
            log.info(f"Password reset successful for user_id: {user_id} - IP: {client_ip}")
            return redirect(url_for('auth.login'))
        else:
            flash(result_message, 'error')
            return render_template('reset_password.html', token=token)


@auth_bp.route('/preferences', methods=['GET', 'POST'])
@login_required
def preferences():
    """User preferences page - email settings and profile"""
    from app import get_db
    db = get_db()

    if request.method == 'POST':
        # Handle preference updates
        action = request.form.get('action')

        if action == 'update_email_preferences':
            # Get checkbox values (unchecked = not in form data)
            email_daily_digest = request.form.get('email_daily_digest') == 'on'
            email_breaking_news = request.form.get('email_breaking_news') == 'on'

            preferences = {
                'email_daily_digest': email_daily_digest,
                'email_breaking_news': email_breaking_news
            }

            success, message = update_user_preferences(db, current_user.id, preferences)

            if success:
                flash(message, 'success')
                log.info(f"Preferences updated for user: {current_user.email}")
            else:
                flash(message, 'error')

            return redirect(url_for('auth.preferences'))

        elif action == 'update_profile':
            # Update profile information
            name = request.form.get('name', '').strip()

            if not name:
                flash('Name is required', 'error')
                return redirect(url_for('auth.preferences'))

            success, message = update_user_profile(db, current_user.id, name=name)

            if success:
                flash(message, 'success')
                log.info(f"Profile updated for user: {current_user.email}")
            else:
                flash(message, 'error')

            return redirect(url_for('auth.preferences'))

    # GET request - show preferences
    prefs = get_user_preferences(db, current_user.id)

    if not prefs:
        flash('Error loading preferences', 'error')
        return redirect(url_for('index'))

    return render_template('preferences.html', preferences=prefs)


@auth_bp.route('/sessions', methods=['GET', 'POST'])
@login_required
def sessions():
    """Active sessions viewer - PHASE 6"""
    from app import get_db
    db = get_db()

    if request.method == 'POST':
        action = request.form.get('action')
        client_ip = get_client_ip()

        if action == 'revoke_session':
            # Revoke specific session
            target_session_id = request.form.get('session_id')
            if target_session_id:
                success, message = revoke_session(db, current_user.id, target_session_id)
                if success:
                    flash(message, 'success')
                    log.info(f"User {current_user.email} revoked session: {target_session_id} - IP: {client_ip}")
                else:
                    flash(message, 'error')

        elif action == 'revoke_all_others':
            # Logout all other devices
            current_session_id = session.get('_id')
            if current_session_id:
                success, message = revoke_all_sessions_except(db, current_user.id, current_session_id)
                if success:
                    flash(message, 'success')
                    log.info(f"User {current_user.email} revoked all other sessions - IP: {client_ip}")
                else:
                    flash(message, 'error')
            else:
                flash('Could not identify current session', 'error')

        return redirect(url_for('auth.sessions'))

    # GET request - show sessions and login history
    active_sessions = get_active_sessions(db, current_user.id)
    login_history = get_login_history(db, current_user.id, limit=10)
    current_session_id = session.get('_id')

    return render_template(
        'sessions.html',
        active_sessions=active_sessions,
        login_history=login_history,
        current_session_id=current_session_id
    )


@auth_bp.route('/unsubscribe/<token>')
def unsubscribe(token):
    """Unsubscribe from emails using token"""
    from app import get_db
    db = get_db()

    # Get email type from query param (default: all)
    email_type = request.args.get('type', 'all')

    success, message, user_email = unsubscribe_user_by_token(db, token, email_type)

    if success:
        flash(message, 'success')
        log.info(f"User unsubscribed: {user_email} - type: {email_type}")
    else:
        flash(message, 'error')

    return render_template('unsubscribe.html', success=success, message=message, email_type=email_type)
