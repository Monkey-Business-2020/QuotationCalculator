from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import math
import os
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key-here")

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
    quotes = db.relationship('Quote', backref='user', lazy=True)

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

def validate_email_domain(email):
    return email.endswith('@istormsolutions.co.uk')

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
        
        if not validate_email_domain(email):
            flash("Registration is restricted to @istormsolutions.co.uk email addresses", "error")
            return render_template("register.html")
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("register.html")
        
        if len(password) < 8:
            flash("Password must be at least 8 characters long", "error")
            return render_template("register.html")
        
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            return render_template("register.html")
        
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "error")
            return render_template("register.html")
        
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            full_name=full_name
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        
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
def calculate():
    data = request.json
    company_name = data.get("companyName", "").strip()
    selected_elements = data.get("selectedElements", [])
    form_data = data.get("formData", {})
    
    if not company_name:
        return jsonify({"error": "Company Name is required!"}), 400
    
    category_breakdown = calculate_category_breakdown(selected_elements, form_data)
    total_days = sum(category_breakdown.values())
    
    quote = Quote(
        user_id=current_user.id,
        company_name=company_name,
        selected_elements=selected_elements,
        form_data=form_data,
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
def recent_quotes():
    quotes = Quote.query.order_by(Quote.created_at.desc()).limit(20).all()
    
    quotes_data = []
    for quote in quotes:
        quotes_data.append({
            "id": quote.id,
            "companyName": quote.company_name,
            "selectedElements": quote.selected_elements,
            "estimatedDays": quote.estimated_days,
            "categoryBreakdown": quote.category_breakdown,
            "timestamp": quote.created_at.strftime("%d/%m/%Y : %H:%M"),
            "username": quote.user.username,
            "userFullName": quote.user.full_name
        })
    
    return jsonify(quotes_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
