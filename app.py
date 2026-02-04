from flask import Flask, render_template, redirect, url_for, request, jsonify, flash, session, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import math
import os
import re
import secrets
import bleach
import bcrypt
import smtplib
import requests
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
from functools import wraps
import random

load_dotenv()

# Default motivational business quotes (used if no custom quotes in database)
DEFAULT_MOTIVATIONAL_QUOTES = [
    ("Success is not final, failure is not fatal: it is the courage to continue that counts.", "Business Leader"),
    ("The best investment you can make is in yourself.", "Entrepreneur"),
    ("Opportunities don't happen, you create them.", "Success Coach"),
    ("Don't wait for opportunity. Create it.", "Business Mentor"),
    ("Success usually comes to those who are too busy to be looking for it.", "Industry Expert"),
    ("The road to success is always under construction.", "Venture Capitalist"),
    ("Winners focus on winning. Losers focus on winners.", "Performance Coach"),
    ("Your limitation is only your imagination.", "Innovation Expert"),
    ("Great things never come from comfort zones.", "Business Strategist"),
    ("Dream it. Believe it. Build it.", "Startup Founder"),
    ("Success is walking from failure to failure with no loss of enthusiasm.", "Business Advisor"),
    ("The harder you work, the luckier you get.", "Industry Leader"),
    ("Don't stop when you're tired. Stop when you're done.", "Executive Coach"),
    ("Wake up with determination. Go to bed with satisfaction.", "Business Consultant"),
    ("Do something today that your future self will thank you for.", "Success Mentor"),
    ("The key to success is to focus on goals, not obstacles.", "Business Expert")
]

# Color scheme presets
COLOR_SCHEMES = {
    'default': {
        'name': 'Professional Blue',
        'primary': '#667eea',
        'secondary': '#764ba2',
        'accent': '#3498db',
        'navbar': '#2c3e50',
        'success': '#27ae60',
        'warning': '#f39c12',
        'danger': '#e74c3c'
    },
    'ocean': {
        'name': 'Ocean Breeze',
        'primary': '#0077b6',
        'secondary': '#00b4d8',
        'accent': '#90e0ef',
        'navbar': '#03045e',
        'success': '#2a9d8f',
        'warning': '#e9c46a',
        'danger': '#e76f51'
    },
    'forest': {
        'name': 'Forest Green',
        'primary': '#2d6a4f',
        'secondary': '#40916c',
        'accent': '#74c69d',
        'navbar': '#1b4332',
        'success': '#52b788',
        'warning': '#f4a261',
        'danger': '#d62828'
    },
    'sunset': {
        'name': 'Sunset Glow',
        'primary': '#f72585',
        'secondary': '#7209b7',
        'accent': '#4cc9f0',
        'navbar': '#3a0ca3',
        'success': '#4895ef',
        'warning': '#fca311',
        'danger': '#d00000'
    },
    'corporate': {
        'name': 'Corporate Gray',
        'primary': '#495057',
        'secondary': '#6c757d',
        'accent': '#007bff',
        'navbar': '#212529',
        'success': '#28a745',
        'warning': '#ffc107',
        'danger': '#dc3545'
    },
    'midnight': {
        'name': 'Midnight Purple',
        'primary': '#7b2cbf',
        'secondary': '#9d4edd',
        'accent': '#c77dff',
        'navbar': '#240046',
        'success': '#06d6a0',
        'warning': '#ffd166',
        'danger': '#ef476f'
    }
}

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Production configuration
app.config['ENV'] = os.getenv('FLASK_ENV', 'production')
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
app.config['TESTING'] = False

csrf = CSRFProtect(app)

# Configure Flask-Limiter with Redis backend
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["50 per minute"],
    storage_uri=redis_url,
    storage_options={"socket_connect_timeout": 30}
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Database configuration - PostgreSQL for production, SQLite for local dev
database_url = os.getenv("DATABASE_URL", "sqlite:///quote_calculator.db")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

app.config['UPLOAD_FOLDER'] = 'static/uploads/profiles'
app.config['LOGO_FOLDER'] = 'static/uploads/logos'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

# =============================================================================
# DATABASE MODELS
# =============================================================================

class SiteSettings(db.Model):
    """Store site-wide settings like branding, colors, etc."""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def get(key, default=None):
        """Get a setting value by key"""
        setting = SiteSettings.query.filter_by(key=key).first()
        return setting.value if setting else default

    @staticmethod
    def set(key, value):
        """Set a setting value"""
        setting = SiteSettings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = SiteSettings(key=key, value=value)
            db.session.add(setting)
        db.session.commit()
        return setting


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_locked = db.Column(db.Boolean, default=False)
    locked_until = db.Column(db.DateTime)
    failed_login_count = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    profile_picture = db.Column(db.String(255), default=None)
    can_manage_users = db.Column(db.Boolean, default=False)
    can_view_analytics = db.Column(db.Boolean, default=False)
    can_view_logs = db.Column(db.Boolean, default=False)
    quotes = db.relationship('Quote', backref='user', lazy=True)

    def is_account_locked(self):
        if self.is_locked and self.locked_until:
            if datetime.utcnow() < self.locked_until:
                return True
            else:
                self.is_locked = False
                self.locked_until = None
                self.failed_login_count = 0
                db.session.commit()
        return False

    def increment_failed_login(self):
        self.failed_login_count += 1
        if self.failed_login_count >= 5:
            self.is_locked = True
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()

    def reset_failed_login(self):
        self.failed_login_count = 0
        self.is_locked = False
        self.locked_until = None
        db.session.commit()


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)


class MotivationalQuote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quote_text = db.Column(db.String(500), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    selected_elements = db.Column(db.JSON, nullable=False)
    form_data = db.Column(db.JSON, nullable=False)
    estimated_days = db.Column(db.Float, nullable=False)
    category_breakdown = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    location = db.Column(db.String(200), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='audit_logs', lazy=True)


class LocationCache(db.Model):
    """Cache IP location lookups to avoid repeated API calls"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    location = db.Column(db.String(200), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    region = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def get_site_settings():
    """Get all site settings as a dictionary"""
    return {
        'company_name': SiteSettings.get('company_name', 'Quote Calculator'),
        'company_logo': SiteSettings.get('company_logo', None),
        'color_scheme': SiteSettings.get('color_scheme', 'default'),
        'allowed_email_domain': os.getenv('ALLOWED_EMAIL_DOMAIN', SiteSettings.get('allowed_email_domain', ''))
    }


def get_color_scheme():
    """Get the current color scheme"""
    scheme_key = SiteSettings.get('color_scheme', 'default')
    return COLOR_SCHEMES.get(scheme_key, COLOR_SCHEMES['default'])


@app.before_request
def before_request():
    """Load site settings before each request"""
    g.site_settings = get_site_settings()
    g.color_scheme = get_color_scheme()
    g.color_schemes = COLOR_SCHEMES


@app.context_processor
def inject_site_settings():
    """Make site settings available to all templates"""
    return {
        'site_settings': getattr(g, 'site_settings', get_site_settings()),
        'color_scheme': getattr(g, 'color_scheme', get_color_scheme()),
        'color_schemes': COLOR_SCHEMES
    }


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You must be an administrator to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def user_management_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (current_user.is_admin or current_user.can_manage_users):
            flash("You don't have permission to access user management.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def analytics_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (current_user.is_admin or current_user.can_view_analytics):
            flash("You don't have permission to view analytics.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def logs_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (current_user.is_admin or current_user.can_view_logs):
            flash("You don't have permission to view audit logs.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_real_ip():
    """Get the real IP address, accounting for proxies and load balancers"""
    if not request:
        return 'Unknown'

    headers_to_check = [
        'X-Forwarded-For',
        'X-Real-IP',
        'CF-Connecting-IP',
        'X-Forwarded',
        'Forwarded-For',
        'Forwarded'
    ]

    for header in headers_to_check:
        ip = request.headers.get(header)
        if ip:
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            if ip and ip != 'unknown':
                return ip

    return request.remote_addr


def get_location_from_ip(ip_address):
    """Get location information from IP address using ipinfo.io"""
    if not ip_address or ip_address in ['127.0.0.1', 'localhost', 'Unknown']:
        return 'Local/Unknown'

    try:
        cached_location = LocationCache.query.filter_by(ip_address=ip_address).first()
        if cached_location:
            return cached_location.location

        # Use ipinfo.io API (with optional token)
        ipinfo_token = os.getenv('IPINFO_TOKEN', '')
        url = f'http://ipinfo.io/{ip_address}/json'
        if ipinfo_token:
            url += f'?token={ipinfo_token}'

        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()

            city = data.get('city', '')
            region = data.get('region', '')
            country = data.get('country', '')

            location_parts = []
            if city:
                location_parts.append(city)
            if region and region != city:
                location_parts.append(region)
            if country:
                location_parts.append(country)

            location = ', '.join(location_parts) if location_parts else 'Unknown'

            cached_entry = LocationCache(
                ip_address=ip_address,
                location=location,
                city=city,
                region=region,
                country=country
            )
            db.session.add(cached_entry)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"Error caching location for {ip_address}: {e}")

            return location
        else:
            return 'Unknown'

    except requests.exceptions.RequestException as e:
        print(f"Error getting location for IP {ip_address}: {e}")
        return 'Unknown'
    except Exception as e:
        print(f"Unexpected error getting location for IP {ip_address}: {e}")
        return 'Unknown'


def log_user_action(action, details=None, user=None, ip_address=None, user_agent=None, get_location=False):
    """Log user actions for audit purposes"""
    try:
        if not ip_address:
            ip_address = get_real_ip()
        if not user_agent:
            user_agent = request.headers.get('User-Agent', 'Unknown') if request else 'Unknown'

        if not user and current_user and current_user.is_authenticated:
            user = current_user

        location = None
        if get_location:
            location = get_location_from_ip(ip_address)

        audit_log = AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else 'Anonymous',
            action=action,
            details=details,
            ip_address=ip_address[:45],
            location=location[:200] if location else None,
            user_agent=user_agent[:500] if user_agent else None,
            timestamp=datetime.utcnow()
        )

        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        print(f"Audit logging error: {e}")
        try:
            db.session.rollback()
        except:
            pass


def sanitize_input(input_string):
    if not input_string:
        return ""
    return bleach.clean(input_string.strip(), tags=[], attributes={}, strip=True)


def validate_email_domain(email):
    """Validate email and optionally check domain restriction"""
    try:
        if not email:
            return False
        email = sanitize_input(email)
        validate_email(email)

        # Check domain restriction from environment or settings
        allowed_domain = os.getenv('ALLOWED_EMAIL_DOMAIN', '')
        if not allowed_domain:
            allowed_domain = SiteSettings.get('allowed_email_domain', '')

        # If no domain restriction, allow any valid email
        if not allowed_domain:
            return True

        # Ensure domain starts with @
        if not allowed_domain.startswith('@'):
            allowed_domain = '@' + allowed_domain

        return email.lower().endswith(allowed_domain.lower())
    except EmailNotValidError:
        return False


def get_email_domain_display():
    """Get the email domain restriction for display purposes"""
    allowed_domain = os.getenv('ALLOWED_EMAIL_DOMAIN', '')
    if not allowed_domain:
        allowed_domain = SiteSettings.get('allowed_email_domain', '')
    return allowed_domain if allowed_domain else None


def validate_password_strength(password):
    if not password or len(password) < 12:
        return False, "Password must be at least 12 characters long"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"

    return True, "Password is strong"


def validate_username(username):
    if not username:
        return False, "Username is required"

    username = sanitize_input(username)
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters"

    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"

    return True, username


def log_login_attempt(ip_address, username, success):
    attempt = LoginAttempt(
        ip_address=ip_address,
        username=sanitize_input(username),
        success=success
    )
    db.session.add(attempt)
    db.session.commit()


def check_ip_brute_force(ip_address):
    cutoff_time = datetime.utcnow() - timedelta(minutes=15)
    failed_attempts = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.success == False,
        LoginAttempt.timestamp > cutoff_time
    ).count()
    return failed_attempts >= 10


def generate_reset_token():
    return secrets.token_urlsafe(32)


def send_password_reset_email(email, reset_token):
    try:
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        sender_email = os.getenv('SENDER_EMAIL')
        sender_password = os.getenv('SENDER_PASSWORD')
        mail_encryption = os.getenv('MAIL_ENCRYPTION', 'tls').lower()

        if not sender_email or not sender_password:
            print("Warning: Email not configured. SENDER_EMAIL and SENDER_PASSWORD must be set.")
            return False

        # Get site settings for branding
        company_name = SiteSettings.get('company_name', 'Quote Calculator')

        try:
            base_url = request.url_root
        except RuntimeError:
            base_url = os.getenv('BASE_URL', 'http://localhost/')

        reset_url = f"{base_url}reset-password/{reset_token}"

        msg = MIMEMultipart('alternative')
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = f"Password Reset - {company_name}"

        html_body = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7fa;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">

                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 600;">Password Reset</h1>
                    <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0; font-size: 16px;">{company_name}</p>
                </div>

                <div style="padding: 40px 30px;">
                    <h2 style="color: #2d3748; margin: 0 0 20px 0; font-size: 22px; font-weight: 600;">Reset Your Password</h2>

                    <p style="color: #4a5568; line-height: 1.6; margin: 0 0 25px 0; font-size: 16px;">
                        We received a request to reset your password for your {company_name} account.
                        Click the button below to create a new password.
                    </p>

                    <div style="text-align: center; margin: 35px 0;">
                        <a href="{reset_url}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; padding: 16px 32px; border-radius: 8px; font-weight: 600; font-size: 16px;">
                            Reset My Password
                        </a>
                    </div>

                    <p style="color: #718096; font-size: 14px; margin: 25px 0; text-align: center;">
                        Or copy and paste this link into your browser:<br>
                        <span style="word-break: break-all; color: #667eea;">{reset_url}</span>
                    </p>

                    <div style="background-color: #f7fafc; border-left: 4px solid #667eea; padding: 20px; margin: 30px 0; border-radius: 0 8px 8px 0;">
                        <h3 style="color: #2d3748; margin: 0 0 15px 0; font-size: 18px; font-weight: 600;">Security Requirements</h3>
                        <p style="color: #4a5568; margin: 0 0 10px 0; font-size: 14px;">Your new password must include:</p>
                        <ul style="color: #4a5568; margin: 0; padding-left: 20px; font-size: 14px;">
                            <li>At least 12 characters</li>
                            <li>One uppercase letter (A-Z)</li>
                            <li>One lowercase letter (a-z)</li>
                            <li>One number (0-9)</li>
                            <li>One special character (!@#$%^&*)</li>
                        </ul>
                    </div>

                    <div style="background-color: #fef5e7; border: 1px solid #f6e05e; border-radius: 8px; padding: 16px; margin: 25px 0;">
                        <p style="color: #744210; margin: 0; font-size: 14px; font-weight: 500;">
                            This link will expire in 1 hour for your security.
                        </p>
                    </div>

                    <p style="color: #718096; font-size: 14px; margin: 25px 0 0 0; line-height: 1.5;">
                        If you didn't request this password reset, please ignore this email.
                    </p>
                </div>

                <div style="background-color: #f7fafc; padding: 25px 30px; text-align: center; border-top: 1px solid #e2e8f0;">
                    <p style="color: #718096; margin: 0; font-size: 12px;">
                        {company_name}
                    </p>
                    <p style="color: #a0aec0; margin: 5px 0 0 0; font-size: 11px;">
                        This is an automated message, please do not reply to this email.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
        Password Reset - {company_name}

        We received a request to reset your password for your {company_name} account.

        Click this link to reset your password:
        {reset_url}

        This link will expire in 1 hour.

        Password Requirements:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character

        If you didn't request this reset, please ignore this email.

        {company_name}
        """

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        if mail_encryption == 'ssl':
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            if mail_encryption == 'tls':
                server.starttls()

        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, email, text)
        server.quit()
        return True
    except Exception as e:
        import logging
        logging.error(f"Email sending failed: {e}")
        print(f"Email sending failed: {e}")
        return False


def calculate_category_breakdown(selected_elements, form_data):
    breakdown = {}

    if "webApp" in selected_elements:
        days = 2
        days += (int(form_data.get("webAppRoles", 0)) * 0.5)
        days += (int(form_data.get("webAppInputFields", 0)) * 0.10)
        days += (int(form_data.get("webAppStatic", 0)) * 0.05)
        days += (int(form_data.get("webAppDynamic", 0)) * 0.10)
        if form_data.get("webAppUpload", "no") == "yes":
            days += 1
        breakdown["Web App"] = math.ceil(days)

    if "externalInfra" in selected_elements:
        ips = int(form_data.get("externalInfraIPs", 0))
        days = ips // 14
        if ips % 14 > 0:
            days += 1
        breakdown["Ext Inf"] = max(days, 1)

    if "internalInfra" in selected_elements:
        days = 2
        days += (int(form_data.get("internalInfraIPs", 0)) * 0.01)
        days += (int(form_data.get("internalInfraEndUserDevices", 0)) * 0.001)
        days += (int(form_data.get("internalInfraOtherDevices", 0)) * 0.1)
        days += (int(form_data.get("internalInfraServers", 0)) * 0.2)
        days += (int(form_data.get("internalInfraVLANs", 0)) * 0.5)
        breakdown["Int Inf"] = math.ceil(days)

    if "api" in selected_elements:
        days = 1
        days += (int(form_data.get("apiEndpoints", 0)) * 0.5)
        days += (int(form_data.get("apiParameters", 0)) * 0.05)
        breakdown["API"] = math.ceil(days)

    if "mobileApp" in selected_elements:
        platform_multiplier = 1 if form_data.get("mobilePlatforms") in ["android", "ios"] else 2
        days = platform_multiplier
        days += (int(form_data.get("mobileJourneys", 0)) * 0.25)
        breakdown["Mobile App"] = math.ceil(days)

    if "cloud" in selected_elements:
        days = 2
        days += (int(form_data.get("cloudAccounts", 0)) * 0.5)
        days += (int(form_data.get("virtualMachines", 0)) * 0.10)
        days += (int(form_data.get("storageAccounts", 0)) * 0.10)
        days += (int(form_data.get("virtualDatabses", 0)) * 0.10)
        breakdown["Cloud"] = math.ceil(days)

    if "kubernetes" in selected_elements:
        days = 2
        days += (int(form_data.get("kubernetesPods", 0)) * 0.1)
        breakdown["Kubernetes"] = math.ceil(days)

    if "docker" in selected_elements:
        days = 1
        days += (int(form_data.get("dockerContainers", 0)) * 0.25)
        if form_data.get("dockerCompose") == "true":
            days += 0.5
        breakdown["Docker"] = math.ceil(days)

    if "office365" in selected_elements:
        days = 1
        office365_features = form_data.get("office365Features", [])
        if isinstance(office365_features, list):
            for feature in office365_features:
                if feature in ["exchange", "sharepoint", "teams"]:
                    days += 0.5
                elif feature in ["onedrive", "azuread", "defender"]:
                    days += 0.3
                elif feature in ["purview", "powerautomate", "intune", "yammer"]:
                    days += 0.2
        days += (int(form_data.get("office365Subscriptions", 0)) * 0.5)
        breakdown["Office365"] = math.ceil(days)

    if "wifiAssessment" in selected_elements:
        breakdown["Wi-Fi Assessment"] = 1

    if "redTeaming" in selected_elements:
        breakdown["Red Teaming"] = 5

    return breakdown


# =============================================================================
# ROUTES
# =============================================================================

@app.route("/health")
def health_check():
    """Health check endpoint for Docker/load balancers"""
    try:
        # Check database connection
        db.session.execute(db.text('SELECT 1'))
        return jsonify({"status": "healthy", "database": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    email_domain = get_email_domain_display()

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        full_name = request.form.get("full_name")

        if not all([username, email, password, confirm_password, full_name]):
            flash("All fields are required", "error")
            return render_template("register.html", email_domain=email_domain)

        username_valid, username_result = validate_username(username)
        if not username_valid:
            flash(username_result, "error")
            return render_template("register.html", email_domain=email_domain)
        username = username_result

        email = sanitize_input(email)
        full_name = sanitize_input(full_name)

        if len(full_name) < 2 or len(full_name) > 100:
            flash("Full name must be between 2 and 100 characters", "error")
            return render_template("register.html", email_domain=email_domain)

        if not validate_email_domain(email):
            if email_domain:
                flash(f"Registration is restricted to {email_domain} email addresses", "error")
            else:
                flash("Invalid email address", "error")
            return render_template("register.html", email_domain=email_domain)

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("register.html", email_domain=email_domain)

        password_valid, password_message = validate_password_strength(password)
        if not password_valid:
            flash(password_message, "error")
            return render_template("register.html", email_domain=email_domain)

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            flash("Account with these credentials already exists", "error")
            return render_template("register.html", email_domain=email_domain)

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # First user becomes admin
        is_first_user = User.query.count() == 0

        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash.decode('utf-8'),
            full_name=full_name,
            is_admin=is_first_user
        )

        db.session.add(new_user)
        db.session.commit()

        if is_first_user:
            flash("Registration successful! You are the first user and have been granted admin privileges.", "success")
        else:
            flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", email_domain=email_domain)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        ip_address = get_real_ip()
        username_or_email = request.form.get("username")
        password = request.form.get("password")

        if not username_or_email or not password:
            flash("Username/Email and password are required", "error")
            return render_template("login.html")

        username_or_email = sanitize_input(username_or_email)

        if check_ip_brute_force(ip_address):
            flash("Too many failed attempts. Please try again later.", "error")
            return render_template("login.html")

        if '@' in username_or_email:
            user = User.query.filter_by(email=username_or_email).first()
        else:
            user = User.query.filter_by(username=username_or_email).first()

        if user and user.is_account_locked():
            flash("Account is temporarily locked due to too many failed attempts.", "error")
            log_login_attempt(ip_address, username_or_email, False)
            return render_template("login.html")

        if user and not user.is_active:
            flash("Your account has been disabled. Please contact an administrator.", "error")
            log_login_attempt(ip_address, username_or_email, False)
            return render_template("login.html")

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            user.reset_failed_login()
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=False)
            session.permanent = True

            # Select a random motivational quote for this session
            db_quotes = MotivationalQuote.query.filter_by(is_active=True).all()
            if db_quotes:
                selected_quote = random.choice(db_quotes)
                session['motivational_quote'] = selected_quote.quote_text
                session['quote_author'] = selected_quote.author
            else:
                quote, author = random.choice(DEFAULT_MOTIVATIONAL_QUOTES)
                session['motivational_quote'] = quote
                session['quote_author'] = author

            log_login_attempt(ip_address, username_or_email, True)
            log_user_action("LOGIN", f"User logged in successfully", user, ip_address, get_location=True)
            return redirect(url_for("dashboard"))

        if user:
            user.increment_failed_login()

        log_login_attempt(ip_address, username_or_email, False)
        flash("Invalid credentials", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_user_action("LOGOUT", "User logged out")
    logout_user()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        if not email:
            flash("Email address is required", "error")
            return render_template("forgot_password.html")

        email = sanitize_input(email)

        try:
            validate_email(email)
        except EmailNotValidError:
            flash("If there is an account with that email a password reset link will be sent", "info")
            return render_template("forgot_password.html")

        user = User.query.filter_by(email=email).first()

        if user:
            existing_token = PasswordResetToken.query.filter_by(
                user_id=user.id, used=False
            ).filter(PasswordResetToken.expires_at > datetime.utcnow()).first()

            if existing_token:
                flash("If there is an account with that email a password reset link will be sent", "info")
                return render_template("forgot_password.html")

            reset_token = generate_reset_token()
            expires_at = datetime.utcnow() + timedelta(hours=1)

            password_reset = PasswordResetToken(
                user_id=user.id,
                token=reset_token,
                expires_at=expires_at
            )

            db.session.add(password_reset)
            db.session.commit()

            email_sent = send_password_reset_email(email, reset_token)
            if not email_sent:
                flash("There was an error sending the password reset email. Please try again later.", "error")
                return render_template("forgot_password.html")

        flash("If there is an account with that email a password reset link will be sent", "info")
        return render_template("forgot_password.html")

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(
        token=token, used=False
    ).filter(PasswordResetToken.expires_at > datetime.utcnow()).first()

    if not reset_token:
        flash("Invalid or expired reset link", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not password or not confirm_password:
            flash("Both password fields are required", "error")
            return render_template("reset_password.html", token=token)

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("reset_password.html", token=token)

        password_valid, password_message = validate_password_strength(password)
        if not password_valid:
            flash(password_message, "error")
            return render_template("reset_password.html", token=token)

        user = User.query.get(reset_token.user_id)
        if not user:
            flash("Invalid reset link", "error")
            return redirect(url_for("login"))

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user.password_hash = password_hash.decode('utf-8')
        user.reset_failed_login()

        reset_token.used = True

        db.session.commit()

        flash("Password reset successful! Please login with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


@app.route("/dashboard")
@login_required
def dashboard():
    if 'motivational_quote' not in session:
        db_quotes = MotivationalQuote.query.filter_by(is_active=True).all()
        if db_quotes:
            selected_quote = random.choice(db_quotes)
            session['motivational_quote'] = selected_quote.quote_text
            session['quote_author'] = selected_quote.author
        else:
            quote, author = random.choice(DEFAULT_MOTIVATIONAL_QUOTES)
            session['motivational_quote'] = quote
            session['quote_author'] = author

    return render_template("dashboard.html",
                         user=current_user,
                         motivational_quote=session.get('motivational_quote'),
                         quote_author=session.get('quote_author'))


@app.route('/calculate', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
@csrf.exempt
def calculate():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.json
    company_name = sanitize_input(data.get("companyName", ""))
    selected_elements = data.get("selectedElements", [])
    form_data = data.get("formData", {})

    if not company_name or len(company_name) < 2:
        return jsonify({"error": "Company Name is required and must be at least 2 characters!"}), 400

    if len(company_name) > 200:
        return jsonify({"error": "Company Name cannot exceed 200 characters!"}), 400

    if not isinstance(selected_elements, list):
        return jsonify({"error": "Invalid selected elements format!"}), 400

    if not isinstance(form_data, dict):
        return jsonify({"error": "Invalid form data format!"}), 400

    valid_elements = ["webApp", "externalInfra", "internalInfra", "api", "mobileApp", "cloud", "kubernetes", "docker", "office365", "wifiAssessment", "redTeaming"]
    for element in selected_elements:
        if element not in valid_elements:
            return jsonify({"error": f"Invalid element: {element}"}), 400

    sanitized_form_data = {}
    for key, value in form_data.items():
        if isinstance(value, str):
            sanitized_form_data[key] = sanitize_input(value)
        elif isinstance(value, (int, float)):
            if value < 0:
                return jsonify({"error": "Negative values are not allowed"}), 400
            if value > 10000:
                return jsonify({"error": "Values too large"}), 400
            sanitized_form_data[key] = value
        elif isinstance(value, list):
            sanitized_form_data[key] = [sanitize_input(str(item)) for item in value]
        else:
            sanitized_form_data[key] = value

    category_breakdown = calculate_category_breakdown(selected_elements, sanitized_form_data)
    total_days = sum(category_breakdown.values())

    quote = Quote(
        user_id=current_user.id,
        company_name=company_name,
        selected_elements=selected_elements,
        form_data=sanitized_form_data,
        estimated_days=total_days,
        category_breakdown=category_breakdown
    )

    db.session.add(quote)
    db.session.commit()

    log_user_action("QUOTE_CREATED", f"Created quote for {company_name} - {total_days} days estimated")

    return jsonify({
        "estimatedDays": total_days,
        "categoryBreakdown": category_breakdown,
        "timestamp": quote.created_at.strftime("%d/%m/%Y : %H:%M")
    })


@app.route('/quotes/recent', methods=['GET'])
@login_required
@limiter.limit("30 per minute")
def recent_quotes():
    quotes = Quote.query.join(User).order_by(Quote.created_at.desc()).limit(50).all()

    quotes_data = []
    for quote in quotes:
        quotes_data.append({
            "id": quote.id,
            "companyName": quote.company_name,
            "selectedElements": quote.selected_elements,
            "estimatedDays": quote.estimated_days,
            "categoryBreakdown": quote.category_breakdown,
            "formData": quote.form_data,
            "timestamp": quote.created_at.strftime("%d/%m/%Y : %H:%M"),
            "username": quote.user.username,
            "userFullName": quote.user.full_name,
            "userProfilePicture": quote.user.profile_picture
        })

    return jsonify(quotes_data)


@app.route('/admin')
def admin_panel():
    if not current_user.is_authenticated or not (current_user.is_admin or current_user.can_manage_users or current_user.can_view_analytics or current_user.can_view_logs):
        flash("You don't have permission to access the admin panel.", "error")
        return redirect(url_for('dashboard'))

    log_user_action("ADMIN_PANEL_ACCESS", "User accessed admin panel")

    users = []
    quote_stats = []
    login_stats = []
    recent_logs = []

    if current_user.is_admin or current_user.can_manage_users:
        users = User.query.order_by(User.created_at.desc()).all()

    if current_user.is_admin or current_user.can_view_analytics:
        quote_stats = db.session.query(
            User.username,
            User.full_name,
            db.func.count(Quote.id).label('quote_count'),
            db.func.sum(Quote.estimated_days).label('total_days'),
            db.func.max(Quote.created_at).label('last_quote')
        ).outerjoin(Quote, User.id == Quote.user_id).group_by(User.id).order_by(db.desc('quote_count')).all()

        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        login_stats = db.session.query(
            User.username,
            User.full_name,
            db.func.count(AuditLog.id).label('login_count'),
            db.func.max(AuditLog.timestamp).label('last_login')
        ).join(AuditLog, User.id == AuditLog.user_id).filter(
            AuditLog.action == 'LOGIN',
            AuditLog.timestamp >= thirty_days_ago
        ).group_by(User.id).order_by(db.desc('login_count')).all()

    if current_user.is_admin or current_user.can_view_logs:
        recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()

    return render_template('admin_panel.html',
                         users=users,
                         quote_stats=quote_stats,
                         login_stats=login_stats,
                         recent_logs=recent_logs)


@app.route('/admin/users')
def admin_users():
    return redirect(url_for('admin_panel'))


@app.route('/admin/analytics')
def admin_analytics():
    return redirect(url_for('admin_panel'))


@app.route('/admin/logs')
def admin_logs():
    return redirect(url_for('admin_panel'))


@app.route('/admin/logs/<int:days>', methods=['GET'])
@logs_required
def get_filtered_logs(days):
    """API endpoint to get filtered audit logs by date range"""
    try:
        date_threshold = datetime.utcnow() - timedelta(days=days)

        logs = AuditLog.query.filter(
            AuditLog.timestamp >= date_threshold
        ).order_by(AuditLog.timestamp.desc()).all()

        logs_data = []
        for log in logs:
            logs_data.append({
                'id': log.id,
                'username': log.username,
                'action': log.action,
                'details': log.details,
                'ip_address': log.ip_address,
                'location': log.location,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None
            })

        log_user_action('LOGS_FILTERED', f'Filtered logs for {days} days - {len(logs_data)} records')

        return jsonify({
            'success': True,
            'logs': logs_data,
            'count': len(logs_data),
            'days': days
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@user_management_required
@csrf.exempt
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.email == current_user.email:
        return jsonify({"error": "Cannot disable your own account"}), 400

    user.is_active = not user.is_active
    db.session.commit()
    action_text = "enabled" if user.is_active else "disabled"
    log_user_action("USER_STATUS_CHANGED", f"User manager {action_text} user {user.username} ({user.email})")
    return jsonify({"success": True, "is_active": user.is_active})


@app.route('/admin/users/toggle-admin/<int:user_id>', methods=['POST'])
@admin_required
@csrf.exempt
def toggle_admin_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.email == current_user.email:
        return jsonify({"error": "Cannot change your own admin status"}), 400

    user.is_admin = not user.is_admin
    db.session.commit()
    role_text = "granted admin privileges to" if user.is_admin else "removed admin privileges from"
    log_user_action("ADMIN_ROLE_CHANGED", f"Admin {role_text} user {user.username} ({user.email})")
    return jsonify({"success": True, "is_admin": user.is_admin})


@app.route('/admin/users/reset-password/<int:user_id>', methods=['POST'])
@user_management_required
@csrf.exempt
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    data = request.json
    new_password = data.get('password', '')

    password_valid, password_message = validate_password_strength(new_password)
    if not password_valid:
        return jsonify({"error": password_message}), 400

    user.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db.session.commit()
    log_user_action("PASSWORD_RESET", f"User manager reset password for user {user.username} ({user.email})")
    return jsonify({"success": True})


@app.route('/admin/users/toggle-permission/<int:user_id>/<permission>', methods=['POST'])
@admin_required
@csrf.exempt
def toggle_user_permission(user_id, permission):
    user = User.query.get_or_404(user_id)
    if user.email == current_user.email and permission in ['can_manage_users', 'is_admin']:
        return jsonify({"error": "Cannot modify your own admin permissions"}), 400

    valid_permissions = ['can_manage_users', 'can_view_analytics', 'can_view_logs']
    if permission not in valid_permissions:
        return jsonify({"error": "Invalid permission"}), 400

    current_value = getattr(user, permission)
    setattr(user, permission, not current_value)
    db.session.commit()

    action_text = "granted" if not current_value else "removed"
    permission_name = permission.replace('can_', '').replace('_', ' ').title()
    log_user_action("PERMISSION_CHANGED", f"Admin {action_text} {permission_name} permission for user {user.username} ({user.email})")

    return jsonify({"success": True, permission: not current_value})


@app.route('/admin/settings')
@admin_required
def admin_settings():
    """Site branding and settings page"""
    return render_template('admin_settings.html')


@app.route('/admin/settings/branding', methods=['POST'])
@admin_required
@csrf.exempt
def update_branding():
    """Update site branding settings"""
    data = request.json

    if 'company_name' in data:
        company_name = sanitize_input(data['company_name'])
        if len(company_name) > 100:
            return jsonify({"error": "Company name too long (max 100 characters)"}), 400
        SiteSettings.set('company_name', company_name)

    if 'color_scheme' in data:
        scheme = data['color_scheme']
        if scheme not in COLOR_SCHEMES:
            return jsonify({"error": "Invalid color scheme"}), 400
        SiteSettings.set('color_scheme', scheme)

    if 'allowed_email_domain' in data:
        domain = sanitize_input(data['allowed_email_domain'])
        SiteSettings.set('allowed_email_domain', domain)

    log_user_action("BRANDING_UPDATED", f"Admin updated site branding settings")

    return jsonify({"success": True, "message": "Settings updated successfully"})


@app.route('/admin/settings/logo', methods=['POST'])
@admin_required
def upload_logo():
    """Upload company logo"""
    if 'logo' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('admin_settings'))

    file = request.files['logo']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('admin_settings'))

    if file and allowed_file(file.filename):
        # Remove old logo if exists
        old_logo = SiteSettings.get('company_logo')
        if old_logo:
            old_file_path = os.path.join(app.config['LOGO_FOLDER'], old_logo)
            if os.path.exists(old_file_path):
                os.remove(old_file_path)

        # Ensure logo directory exists
        os.makedirs(app.config['LOGO_FOLDER'], exist_ok=True)

        # Save new logo
        filename = secure_filename(f"logo_{secrets.token_hex(8)}.{file.filename.rsplit('.', 1)[1].lower()}")
        file_path = os.path.join(app.config['LOGO_FOLDER'], filename)
        file.save(file_path)

        SiteSettings.set('company_logo', filename)
        log_user_action("LOGO_UPDATED", f"Admin uploaded new company logo: {filename}")
        flash('Logo updated successfully', 'success')
    else:
        flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF files only.', 'error')

    return redirect(url_for('admin_settings'))


@app.route('/admin/settings/logo/remove', methods=['POST'])
@admin_required
@csrf.exempt
def remove_logo():
    """Remove company logo"""
    old_logo = SiteSettings.get('company_logo')
    if old_logo:
        old_file_path = os.path.join(app.config['LOGO_FOLDER'], old_logo)
        if os.path.exists(old_file_path):
            os.remove(old_file_path)
        SiteSettings.set('company_logo', None)
        log_user_action("LOGO_REMOVED", "Admin removed company logo")

    return jsonify({"success": True})


@app.route('/profile')
@login_required
def profile_settings():
    email_domain = get_email_domain_display()
    return render_template('profile_settings.html', user=current_user, email_domain=email_domain)


@app.route('/profile/update', methods=['POST'])
@login_required
@csrf.exempt
def update_profile():
    data = request.json
    action = data.get('action')

    if action == 'update_email':
        new_email = sanitize_input(data.get('email', ''))
        if not validate_email_domain(new_email):
            email_domain = get_email_domain_display()
            if email_domain:
                return jsonify({"error": f"Email must be from {email_domain} domain"}), 400
            return jsonify({"error": "Invalid email address"}), 400

        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user and existing_user.id != current_user.id:
            return jsonify({"error": "Email address already in use"}), 400

        current_user.email = new_email
        db.session.commit()
        log_user_action("EMAIL_UPDATED", f"Email changed to {new_email}")
        return jsonify({"success": True, "message": "Email updated successfully"})

    elif action == 'change_password':
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not bcrypt.checkpw(current_password.encode('utf-8'), current_user.password_hash.encode('utf-8')):
            return jsonify({"error": "Current password is incorrect"}), 400

        password_valid, password_message = validate_password_strength(new_password)
        if not password_valid:
            return jsonify({"error": password_message}), 400

        current_user.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.session.commit()
        log_user_action("PASSWORD_CHANGED", "User changed their password")
        return jsonify({"success": True, "message": "Password changed successfully"})

    return jsonify({"error": "Invalid action"}), 400


@app.route('/profile/upload-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('profile_settings'))

    file = request.files['profile_picture']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('profile_settings'))

    if file and allowed_file(file.filename):
        if current_user.profile_picture:
            old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_picture)
            if os.path.exists(old_file_path):
                os.remove(old_file_path)

        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        filename = secure_filename(f"user_{current_user.id}_{secrets.token_hex(8)}.{file.filename.rsplit('.', 1)[1].lower()}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        current_user.profile_picture = filename
        db.session.commit()
        log_user_action("PROFILE_PICTURE_UPDATED", f"Uploaded new profile picture: {filename}")
        flash('Profile picture updated successfully', 'success')
    else:
        flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF files only.', 'error')

    return redirect(url_for('profile_settings'))


@app.route('/admin/quotes', methods=['GET'])
@admin_required
def admin_quotes():
    """Get all motivational quotes for admin management"""
    quotes = MotivationalQuote.query.all()
    quotes_data = [{
        'id': q.id,
        'quote_text': q.quote_text,
        'author': q.author,
        'is_active': q.is_active,
        'created_at': q.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for q in quotes]
    return jsonify(quotes_data)


@app.route('/admin/quotes/add', methods=['POST'])
@admin_required
@csrf.exempt
def add_quote():
    """Add a new motivational quote"""
    data = request.json
    quote_text = data.get('quote_text', '').strip()
    author = data.get('author', '').strip()

    if not quote_text or not author:
        return jsonify({"error": "Quote text and author are required"}), 400

    if len(quote_text) > 500:
        return jsonify({"error": "Quote text must be less than 500 characters"}), 400

    new_quote = MotivationalQuote(
        quote_text=quote_text,
        author=author,
        is_active=True
    )
    db.session.add(new_quote)
    db.session.commit()

    log_user_action("QUOTE_ADDED", f"Added new quote by {author}")

    return jsonify({
        "success": True,
        "id": new_quote.id,
        "message": "Quote added successfully"
    })


@app.route('/admin/quotes/edit/<int:quote_id>', methods=['POST'])
@admin_required
@csrf.exempt
def edit_quote(quote_id):
    """Edit an existing motivational quote"""
    quote = MotivationalQuote.query.get_or_404(quote_id)
    data = request.json

    quote_text = data.get('quote_text', '').strip()
    author = data.get('author', '').strip()

    if not quote_text or not author:
        return jsonify({"error": "Quote text and author are required"}), 400

    if len(quote_text) > 500:
        return jsonify({"error": "Quote text must be less than 500 characters"}), 400

    quote.quote_text = quote_text
    quote.author = author
    quote.updated_at = datetime.utcnow()
    db.session.commit()

    log_user_action("QUOTE_EDITED", f"Edited quote ID {quote_id}")

    return jsonify({"success": True, "message": "Quote updated successfully"})


@app.route('/admin/quotes/toggle/<int:quote_id>', methods=['POST'])
@admin_required
@csrf.exempt
def toggle_quote_status(quote_id):
    """Toggle the active status of a quote"""
    quote = MotivationalQuote.query.get_or_404(quote_id)
    quote.is_active = not quote.is_active
    quote.updated_at = datetime.utcnow()
    db.session.commit()

    status = "activated" if quote.is_active else "deactivated"
    log_user_action("QUOTE_STATUS_CHANGED", f"Quote ID {quote_id} {status}")

    return jsonify({"success": True, "is_active": quote.is_active})


@app.route('/admin/quotes/delete/<int:quote_id>', methods=['DELETE'])
@admin_required
@csrf.exempt
def delete_quote(quote_id):
    """Delete a motivational quote"""
    quote = MotivationalQuote.query.get_or_404(quote_id)
    db.session.delete(quote)
    db.session.commit()

    log_user_action("QUOTE_DELETED", f"Deleted quote ID {quote_id}")

    return jsonify({"success": True, "message": "Quote deleted successfully"})


@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


# Initialize database
with app.app_context():
    db.create_all()
    # Ensure upload directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['LOGO_FOLDER'], exist_ok=True)


if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
