from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import joblib

# 🛡️ NEW SECURITY & EXPORT MODULES
import re
import csv
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pandas as pd

# Bringing in the heavy lifters: our custom AI and API modules
from core.url_processor import normalize_url, is_valid_url, expand_short_url
from core.feature_extractor import extract_features
from core.threat_intel import query_threat_intelligence
from core.scoring import compute_final_risk
from core.explanation import recommendations_for

# Fire up the Flask application
app = Flask(__name__)

# ==========================================
# 1. APP CONFIGURATION & SECURITY SETTINGS
# ==========================================
app.config['SECRET_KEY'] = 'mmu-fyp-super-secret-key-2026' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded. Please wait a minute before scanning again."
    }), 429

# ==========================================
# LOAD NLP PIPELINE (Loads once on startup)
# ==========================================
try:
    print("Loading Max-NLP Pipeline...")
    model_pipeline = joblib.load("model/phishing_model.pkl")
except Exception as e:
    print(f"Failed to load model: {e}")
    model_pipeline = None

# ==========================================
# 2. DATABASE ARCHITECTURE (THE TABLES)
# ==========================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    scans = db.relationship('ScanHistory', backref='author', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_scanned = db.Column(db.String(500), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

logging.basicConfig(level=logging.INFO)

# ==========================================
# 3. ACCOUNT MANAGEMENT & HISTORY ROUTES
# ==========================================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Oops! That username is already taken. Please try another one.")
            return redirect(url_for('signup'))
            
        password_pattern = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$')
        if not password_pattern.match(password):
            flash("Password must be at least 8 characters long and contain a mix of letters and numbers.")
            return redirect(url_for('signup'))
            
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user) 
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password. Please try again.")
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
@login_required 
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/history')
@login_required
def history():
    user_scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.id.desc()).all()
    
    total_scans = len(user_scans)
    safe_scans = sum(1 for scan in user_scans if 'low' in scan.status.lower() or 'safe' in scan.status.lower())
    malicious_scans = total_scans - safe_scans 
    
    return render_template('history.html', 
                           scans=user_scans, 
                           total=total_scans, 
                           safe=safe_scans, 
                           malicious=malicious_scans)

@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = ScanHistory.query.get(scan_id)
    if scan and scan.user_id == current_user.id:
        db.session.delete(scan)
        db.session.commit()
    return redirect(url_for('history'))

@app.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    # 1. Delete only the current user's scan records
    ScanHistory.query.filter_by(user_id=current_user.id).delete()
    
    # 2. Commit the changes safely without touching the global ID sequence
    db.session.commit()
    
    return redirect(url_for('history'))

@app.route('/export_to_server', methods=['POST'])
@login_required
def export_to_server():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).all()
    filename = f"export_{current_user.username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Scan ID', 'URL', 'Risk Score', 'Verdict'])
            for index, scan in enumerate(scans, start=1):
                writer.writerow([index, scan.url_scanned, scan.risk_score, scan.status])
                
        return jsonify({"success": True, "filename": filename})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    
# ==========================================
# 4. THE CORE CYBERSECURITY ENGINE
# ==========================================
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
@limiter.limit("5 per minute") 
def analyze():
    raw_url = request.form.get("url", "").strip()

    # ==========================================
    # 🛡️ THE PROTOCOL NORMALIZATION PATCH
    # ==========================================
    # Force naked domains into a standard structure for the ML model
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url
    # ==========================================

    url_pattern = re.compile(r'^(https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(:[0-9]+)?(/.*)?$')
    
    if not url_pattern.match(raw_url):
         return jsonify({
             "error": "Invalid format! Please enter a proper web address (e.g., google.com or https://example.com)."
         }), 400

    normalized = normalize_url(raw_url)
    target_url = expand_short_url(normalized)

   # ==========================================
    # 🌟 THE ENTERPRISE WHITELIST PATCH (UPDATED)
    # ==========================================
    from urllib.parse import urlparse
    
    # Extract the core domain (e.g., 'google.com' from 'https://www.google.com/')
    parsed_domain = urlparse(target_url).netloc.lower()
    if parsed_domain.startswith("www."):
        parsed_domain = parsed_domain[4:]
        
    # Top Trusted Global Domains (Bypass ML to prevent False Positives)
    TRUSTED_DOMAINS = {
        "google.com", "youtube.com", "facebook.com", "apple.com", 
        "microsoft.com", "github.com", "linkedin.com", "yahoo.com", 
        "wikipedia.org", "amazon.com", "mmu.edu.my"
    }

    if parsed_domain in TRUSTED_DOMAINS:
        # Run real APIs so the frontend gets the exact data structure it expects!
        intel_results = query_threat_intelligence(target_url)
        
        result = {
            "risk_score": 0.0,
            "risk_category": "Safe",
            "intel_results": [res.__dict__ for res in intel_results],
            "url": target_url,
            "findings": [
                "Domain matched against the Enterprise Trusted Whitelist.",
                "Bypassed Machine Learning and Heuristics to prevent false positives."
            ],
            "recommendations": ["This is a globally trusted and verified domain. Safe to browse."]
        }
        
        # Log the safe scan to the database
        if current_user.is_authenticated:
            new_scan = ScanHistory(
                url_scanned=target_url,
                risk_score=0.0, 
                status="Safe", 
                user_id=current_user.id
            )
            db.session.add(new_scan)
            db.session.commit()
            
        return jsonify(result)
    # ==========================================

    if not is_valid_url(target_url):
        return jsonify({
            "error": "That doesn't look like a valid web address. Please double-check it!"
        }), 400

    try:
        # Extract the mathematical features
        features = extract_features(target_url)
        
        # Assign raw_url properly so the NLP Pipeline can read it
        features["raw_url"] = target_url  
        
        # NLP PIPELINE PREDICTION LOGIC
        # Convert the dictionary to a 1-row Pandas DataFrame required by the pipeline
        df = pd.DataFrame([features])
        
        if model_pipeline:
            # Get the probability of Class 1 (Phishing)
            ml_probability = float(model_pipeline.predict_proba(df)[0][1])
        else:
            ml_probability = 0.5 # Fallback if model fails to load

        # Query APIs using the TRUE destination
        intel_results = query_threat_intelligence(target_url)

        # Compute the final risk score combining ML + Threat Intel
        result = compute_final_risk(features, intel_results, ml_probability)

        result["intel_results"] = [res.__dict__ for res in intel_results]
        result["url"] = target_url
        result["recommendations"] = recommendations_for(result["risk_category"])

        # Save to history if logged in
        if current_user.is_authenticated:
            new_scan = ScanHistory(
                url_scanned=target_url,
                risk_score=result.get("risk_score", ml_probability * 100), 
                status=result.get("risk_category", "Unknown"), 
                user_id=current_user.id
            )
            db.session.add(new_scan)
            db.session.commit()

        return jsonify(result)

    except Exception as e:
        logging.error(f"Engine Crash during URL analysis: {str(e)}")
        import traceback
        traceback.print_exc() # Prints the exact line of the crash to your terminal
        return jsonify({
            "error": "Our detection engine hit a snag while analyzing this URL.",
            "details": str(e)
        }), 500

@app.route("/api/v1/analyze", methods=["POST"])
@limiter.limit("60 per minute")
def api_analyze():
    """Enterprise REST API Endpoint for remote SIEM/Bot integrations."""
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Malformed request. Please provide a JSON body with a 'url' key."}), 400
        
    raw_url = data['url'].strip()

    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    normalized = normalize_url(raw_url)
    target_url = expand_short_url(normalized)
    
    if not is_valid_url(target_url):
        return jsonify({"error": "Invalid URL format."}), 400

    from urllib.parse import urlparse
    parsed_domain = urlparse(target_url).netloc.lower()
    if parsed_domain.startswith("www."):
        parsed_domain = parsed_domain[4:]
        
    TRUSTED_DOMAINS = {"google.com", "youtube.com", "facebook.com", "apple.com", "microsoft.com", "github.com", "mmu.edu.my"}
    
    if parsed_domain in TRUSTED_DOMAINS:
        return jsonify({
            "risk_score": 0.0,
            "risk_category": "Safe",
            "findings": ["Bypassed Machine Learning via Enterprise Trusted Whitelist."],
            "url": target_url
        })

    try:
        features = extract_features(target_url)
        features["raw_url"] = target_url  
        
        df = pd.DataFrame([features])
        ml_probability = float(model_pipeline.predict_proba(df)[0][1]) if model_pipeline else 0.5
        
        intel_results = query_threat_intelligence(target_url)
        result = compute_final_risk(features, intel_results, ml_probability)
        
        result["intel_results"] = [res.__dict__ for res in intel_results]
        result["url"] = target_url
        
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": "Internal Engine Failure", "details": str(e)}), 500

# ==========================================
# 6. SERVER LAUNCH PROTOCOL
# ==========================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        
    print("\n=========================================================")
    print(" 🛡️  HYBRID PHISHING DETECTION ENGINE - ONLINE")
    print(" 👤  Developed by: Amir Qayyuum")
    print(" 🌐  Dashboard live at: http://127.0.0.1:5000/")
    print("=========================================================\n")
    
    app.run(debug=True)