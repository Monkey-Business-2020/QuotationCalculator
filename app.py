from flask import Flask, render_template, redirect, url_for, request, jsonify, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
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
from datetime import datetime, timedelta
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

csrf = CSRFProtect(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["50 per minute"]
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///quote_calculator_v2.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

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

class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    selected_elements = db.Column(db.JSON, nullable=False)
    form_data = db.Column(db.JSON, nullable=False)
    estimated_days = db.Column(db.Float, nullable=False)
    category_breakdown = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

def sanitize_input(input_string):
    if not input_string:
        return ""
    return bleach.clean(input_string.strip(), tags=[], attributes={}, strip=True)

def validate_email_domain(email):
    try:
        if not email:
            return False
        email = sanitize_input(email)
        validate_email(email)
        return email.endswith('@istormsolutions.co.uk')
    except EmailNotValidError:
        return False

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
    
    return breakdown

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        full_name = request.form.get("full_name")
        
        if not all([username, email, password, confirm_password, full_name]):
            flash("All fields are required", "error")
            return render_template("register.html")
        
        username_valid, username_result = validate_username(username)
        if not username_valid:
            flash(username_result, "error")
            return render_template("register.html")
        username = username_result
        
        email = sanitize_input(email)
        full_name = sanitize_input(full_name)
        
        if len(full_name) < 2 or len(full_name) > 100:
            flash("Full name must be between 2 and 100 characters", "error")
            return render_template("register.html")
        
        if not validate_email_domain(email):
            flash("Registration is restricted to @istormsolutions.co.uk email addresses", "error")
            return render_template("register.html")
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("register.html")
        
        password_valid, password_message = validate_password_strength(password)
        if not password_valid:
            flash(password_message, "error")
            return render_template("register.html")
        
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash("Account with these credentials already exists", "error")
            return render_template("register.html")
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash.decode('utf-8'),
            full_name=full_name
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        ip_address = request.remote_addr
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("login.html")
        
        username = sanitize_input(username)
        
        if check_ip_brute_force(ip_address):
            flash("Too many failed attempts. Please try again later.", "error")
            return render_template("login.html")
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.is_account_locked():
            flash("Account is temporarily locked due to too many failed attempts.", "error")
            log_login_attempt(ip_address, username, False)
            return render_template("login.html")
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            user.reset_failed_login()
            login_user(user, remember=False)
            session.permanent = True
            log_login_attempt(ip_address, username, True)
            return redirect(url_for("dashboard"))
        
        if user:
            user.increment_failed_login()
        
        log_login_attempt(ip_address, username, False)
        flash("Invalid credentials", "error")
    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@app.route('/calculate', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
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
    
    valid_elements = ["webApp", "externalInfra", "internalInfra", "api", "mobileApp", "cloud", "kubernetes", "docker", "office365"]
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
    
    return jsonify({
        "estimatedDays": total_days,
        "categoryBreakdown": category_breakdown,
        "timestamp": quote.created_at.strftime("%d/%m/%Y : %H:%M")
    })

@app.route('/quotes/recent', methods=['GET'])
@login_required
@limiter.limit("30 per minute")
def recent_quotes():
    quotes = Quote.query.filter_by(user_id=current_user.id).order_by(Quote.created_at.desc()).limit(20).all()
    
    quotes_data = []
    for quote in quotes:
        quotes_data.append({
            "id": quote.id,
            "companyName": quote.company_name,
            "selectedElements": quote.selected_elements,
            "estimatedDays": quote.estimated_days,
            "categoryBreakdown": quote.category_breakdown,
            "timestamp": quote.created_at.strftime("%d/%m/%Y : %H:%M"),
            "username": current_user.username,
            "userFullName": current_user.full_name
        })
    
    return jsonify(quotes_data)

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

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=5001, debug=debug_mode)
