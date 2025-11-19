"""
Authentication routes for Aviation Intelligence Hub
Signup, Login, Logout, Email Verification
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from models import (
    get_user_by_email, create_user, verify_user_email,
    update_last_login, get_user_by_id
)
from email_service import email_service
import logging

log = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """User signup with email verification"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')

        # Validation
        if not name or not email or not password:
            flash('All fields are required', 'error')
            return render_template('signup.html')

        if len(name) < 2:
            flash('Name must be at least 2 characters', 'error')
            return render_template('signup.html')

        if '@' not in email or '.' not in email:
            flash('Invalid email address', 'error')
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
            return render_template('signup.html')

        # Send verification email
        base_url = request.url_root.rstrip('/')
        email_sent = email_service.send_verification_email(
            user.email,
            user.name,
            user.verification_token,
            base_url
        )

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
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('login.html')

        # Get user
        from app import get_db
        db = get_db()
        user = get_user_by_email(db, email)

        if not user or not user.check_password(password):
            flash('Invalid email or password', 'error')
            return render_template('login.html')

        # Check if verified
        if not user.is_verified:
            flash(
                'Please verify your email address first. Check your inbox for the verification link.',
                'error'
            )
            return render_template('login.html')

        # Check if active
        if not user.is_active:
            flash('Your account has been deactivated. Please contact support.', 'error')
            return render_template('login.html')

        # Login user
        login_user(user, remember=remember)
        update_last_login(db, user.id)

        log.info(f"User logged in: {user.email}")

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
    """User logout"""
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

        # Send welcome email
        user = get_user_by_email(db, None)  # Get user by token
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
