import os
from dotenv import load_dotenv
load_dotenv()  # Safely loads your secret keys from the .env file

import whois
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort, session, make_response, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import joblib
import uuid
import requests
from datetime import datetime, timezone, timedelta
from functools import wraps
from io import StringIO

# 🛡️ SECURITY, EXPORT & AI MODULES
import re
import csv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pandas as pd
from groq import Groq

# 📧 EMAIL VERIFICATION MODULES
from itsdangerous import URLSafeTimedSerializer

from core.url_processor import normalize_url, is_valid_url, expand_short_url
from core.feature_extractor import extract_features
from core.threat_intel import query_threat_intelligence, openphish_engine
from core.scoring import compute_final_risk
from core.explanation import recommendations_for

app = Flask(__name__)

app.config['SECRET_KEY'] = 'mmu-fyp-super-secret-key-2026' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ==========================================
# 📧 BREVO & AI CONFIGURATION (GROQ)
# ==========================================
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "fallback_key_here")
SENDER_EMAIL = "amirqayyuum30@gmail.com"
SENDER_NAME = "ThreatLink"

# Initialize Groq Client safely
groq_api_key = os.environ.get("GROQ_API_KEY")
ai_client = Groq(api_key=groq_api_key) if groq_api_key else None

# ==========================================
# ⏰ TIMEZONE CONFIGURATION (MALAYSIA UTC+8)
# ==========================================
MY_TIMEZONE = timezone(timedelta(hours=8))

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
    return jsonify({"error": "Rate limit exceeded. Please wait a minute before scanning again."}), 429

try:
    print("Loading Max-NLP Pipeline...")
    model_pipeline = joblib.load("model/phishing_model.pkl")
except Exception as e:
    print(f"Failed to load model: {e}")
    model_pipeline = None

# ==========================================
# DATABASE ARCHITECTURE
# ==========================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)  # <-- Enterprise Admin Role
    scans = db.relationship('ScanHistory', backref='author', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_uuid = db.Column(db.String(36), unique=True, nullable=False)
    url_scanned = db.Column(db.String(500), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.String(50), nullable=False)

class FeedbackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_uuid = db.Column(db.String(36), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    feedback_type = db.Column(db.String(50), nullable=False) 
    status = db.Column(db.String(20), default='Pending') # <-- Triage Status
    timestamp = db.Column(db.String(50), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

logging.basicConfig(level=logging.INFO)

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verification-salt')

def confirm_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-verification-salt', max_age=expiration)
    except Exception:
        return False
    return email

def send_verification_email(to_email, username, verify_url):
    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"accept": "application/json", "api-key": BREVO_API_KEY, "content-type": "application/json"},
            json={
                "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
                "to": [{"email": to_email, "name": username}],
                "subject": "Verify Your Email - ThreatLink Phishing Risk Analyzer",
                "htmlContent": f"""
                <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f9f9f9; border-radius: 8px;">
                    <h2 style="color: #0f172a;">Welcome to ThreatLink, {username}!</h2>
                    <p>Thank you for registering. Please click the button below to verify your email address:</p>
                    <a href="{verify_url}" style="display: inline-block; padding: 12px 24px; background-color: #06b6d4; color: #ffffff; text-decoration: none; font-weight: bold; border-radius: 6px;">Verify Email</a>
                </div>
                """
            }
        )
        return response.status_code in [200, 201], response.json().get('message', 'Unknown API error') if response.status_code not in [200, 201] else None
    except Exception as e:
        return False, str(e)

def defang_url(url):
    return url.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")

def analyze_url_anatomy(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.hostname or ''
    
    flags = []
    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', domain):
        flags.append("IP Address used instead of Domain")
    if 'xn--' in domain:
        flags.append("Punycode detected (IDN homograph risk)")
    if len(domain.split('.')) > 4:
        flags.append("Excessive subdomains")
    if len(url) > 75:
        flags.append("Unusually long URL string")
        
    domain_age_str = "Unknown / Hidden"
    if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', domain) and domain:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if creation_date:
                if isinstance(creation_date, list): creation_date = creation_date[0]
                if isinstance(creation_date, datetime):
                    naive_creation = creation_date.replace(tzinfo=None)
                    naive_now = datetime.now().replace(tzinfo=None)
                    age_days = (naive_now - naive_creation).days
                    domain_age_str = f"{age_days} Days"
                    if age_days < 30:
                        flags.append(f"Newly Registered Domain (Only {age_days} days old)")
        except Exception as e:
            domain_age_str = "Lookup Failed/Timeout"
            logging.warning(f"WHOIS lookup failed for {domain}: {e}")
            
    return {
        "protocol": parsed.scheme.upper() or "HTTPS",
        "domain": domain or "N/A",
        "path": parsed.path or "/",
        "query": parsed.query or "None",
        "domain_age": domain_age_str,
        "flags": flags if flags else ["Standard structural pattern"]
    }

def get_top_ml_features(features_dict, ml_probability):
    features_list = [
        {"feature": "URL String Length", "impact": round(min(len(features_dict.get('raw_url', '')) / 100.0, 1.0) * 100, 1), "desc": f"Length: {len(features_dict.get('raw_url', ''))} chars"},
        {"feature": "Lexical Entropy", "impact": round(features_dict.get('entropy', 0.5) * 100, 1), "desc": "Random character distribution metric"},
        {"feature": "Subdomain Count", "impact": round(min(features_dict.get('subdomain_count', 1) * 20, 100.0), 1), "desc": "Subdomain depth level"},
        {"feature": "Suspicious TLD / Keywords", "impact": round(ml_probability * 100, 1), "desc": "Machine learning pattern weight"}
    ]
    features_list.sort(key=lambda x: x['impact'], reverse=True)
    return features_list[:4]

def generate_ai_threat_briefing(url, risk_score, risk_category, anatomy, intel_results):
    if not ai_client:
        return "AI Briefing unavailable: GROQ_API_KEY not configured. Ensure it is set in your environment variables."

    prompt = f"""
    You are an expert Cyber Threat Intelligence Analyst in a Security Operations Center (SOC). 
    Analyze the following URL scan telemetry and write a concise, professional 3-sentence threat briefing for a security analyst:
    
    - Target URL: {url}
    - Risk Score: {risk_score}/100
    - Risk Category: {risk_category}
    - Domain Age: {anatomy.get('domain_age', 'Unknown')}
    - Structural Flags: {', '.join(anatomy.get('flags', []))}
    - Threat Intel Matches: {[res.source for res in intel_results if res.verdict in ['Malicious', 'High Risk']]}
    
    Provide actionable insight and highlight why this link is dangerous or safe. 
    IMPORTANT: Do not use any markdown bold asterisks (**). Start the final recommendation with the exact phrase: "Actionable Insight:".
    """

    try:
        completion = ai_client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )
        briefing_text = completion.choices[0].message.content.strip()
        briefing_text = briefing_text.replace("**", "")
        
        return briefing_text
    except Exception as e:
        logging.warning(f"Groq AI briefing generation failed: {str(e)}")
        return "AI Threat Intelligence Briefing temporarily unavailable."

# ==========================================
# ADMIN ROUTES, CONTROL PANEL & EXPORTS
# ==========================================
@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin') and not (current_user.is_authenticated and getattr(current_user, 'is_admin', False)):
        return redirect(url_for('login'))
    
    total_users = User.query.count()
    total_scans = ScanHistory.query.count()
    threats_detected = ScanHistory.query.filter(ScanHistory.status.in_(['Malicious', 'High Risk'])).count()
    pending_feedback = FeedbackLog.query.filter_by(status='Pending').all()
    all_users = User.query.all()
    recent_scans = ScanHistory.query.order_by(ScanHistory.id.desc()).limit(50).all()
    feedback_entries = FeedbackLog.query.order_by(FeedbackLog.id.desc()).limit(50).all()
    
    return render_template('admin.html', 
                           total_users=total_users, 
                           total_scans=total_scans, 
                           threats_detected=threats_detected,
                           pending_feedback=pending_feedback, 
                           all_users=all_users,
                           recent_scans=recent_scans,
                           feedback_entries=feedback_entries)

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for('login'))

@app.route('/admin/export/scans/csv')
def export_scans_csv():
    if not session.get('is_admin') and not (current_user.is_authenticated and getattr(current_user, 'is_admin', False)):
        return redirect(url_for('login'))
    
    scans = ScanHistory.query.order_by(ScanHistory.id.desc()).all()
    si = StringIO()
    writer = csv.writer(si)
    
    writer.writerow(['Scan UUID', 'Timestamp', 'Target URL', 'Risk Score', 'Status', 'User ID'])
    for s in scans:
        writer.writerow([s.scan_uuid, s.timestamp, s.url_scanned, s.risk_score, s.status, s.user_id or 'Guest'])
    
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatlink_scan_audit_logs.csv"}
    )

@app.route('/admin/export/feedback/csv')
def export_feedback_csv():
    if not session.get('is_admin') and not (current_user.is_authenticated and getattr(current_user, 'is_admin', False)):
        return redirect(url_for('login'))
    
    feedbacks = FeedbackLog.query.order_by(FeedbackLog.id.desc()).all()
    si = StringIO()
    writer = csv.writer(si)
    
    writer.writerow(['Feedback ID', 'Scan UUID', 'Reported URL', 'Feedback Type', 'Status', 'Timestamp'])
    for f in feedbacks:
        writer.writerow([f.id, f.scan_uuid, f.url, f.feedback_type, f.status, f.timestamp])
    
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatlink_user_feedback.csv"}
    )

@app.route('/admin/feedback/resolve/<int:fb_id>', methods=['POST'])
def resolve_feedback(fb_id):
    if not session.get('is_admin') and not (current_user.is_authenticated and getattr(current_user, 'is_admin', False)):
        return redirect(url_for('login'))
    
    feedback = FeedbackLog.query.get(fb_id)
    if feedback:
        feedback.status = 'Resolved'
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

# ==========================================
# PUBLIC & USER ROUTES
# ==========================================
@app.route("/about")
def about():
    return render_template("about.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash("Oops! That username is already taken. Please try another one.")
            return redirect(url_for('signup'))
            
        if User.query.filter_by(email=email).first():
            flash("Oops! That email address is already registered.")
            return redirect(url_for('signup'))
            
        password_pattern = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$')
        if not password_pattern.match(password):
            flash("Password must be at least 8 characters long and contain a mix of letters and numbers.")
            return redirect(url_for('signup'))
            
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        is_first_user = User.query.count() == 0
        new_user = User(username=username, email=email, password_hash=hashed_password, is_verified=False, is_admin=is_first_user)
        db.session.add(new_user)
        db.session.commit()
        
        token = generate_verification_token(email)
        verify_url = url_for('verify_email', token=token, _external=True)
        print(f"\n[DEBUG - VERIFICATION LINK FOR {email}]:\n{verify_url}\n")
        
        success, error_msg = send_verification_email(email, username, verify_url)
        if success:
            flash('Registration successful! Please check your inbox to verify your account before logging in.')
        else:
            flash(f'Account created, but email delivery failed. Check terminal for direct link.')
            print(f"\n[BREVO API ERROR]: {error_msg}\n")
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/verify/<token>')
def verify_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash('The verification link is invalid or has expired.')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('login'))

    if user.is_verified:
        flash('Account already verified. Please log in.')
    else:
        user.is_verified = True
        db.session.commit()
        flash('Email verified successfully! You can now log in.')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        env_admin = os.environ.get("ADMIN_USER", "admin")
        env_pass = os.environ.get("ADMIN_PASS", "securepassword123")
        
        # Check environment admin login
        if username == env_admin and password == env_pass:
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        
        # Check database user login
        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified and not user.is_admin:
                flash("Please verify your email address before logging in. Check your inbox for the link.")
                return redirect(url_for('login'))
            
            login_user(user) 
            
            # If database user is an admin, set admin session and route to admin dashboard
            if getattr(user, 'is_admin', False):
                session['is_admin'] = True
                return redirect(url_for('admin_dashboard'))
            
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password. Please try again.")
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
@login_required 
def logout():
    session.pop('is_admin', None)
    logout_user()
    return redirect(url_for('home'))

@app.route('/history')
@login_required
def history():
    user_scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.id.desc()).all()
    total_scans = len(user_scans)
    safe_scans = sum(1 for scan in user_scans if 'low' in scan.status.lower() or 'safe' in scan.status.lower())
    malicious_scans = total_scans - safe_scans 
    return render_template('history.html', scans=user_scans, total=total_scans, safe=safe_scans, malicious=malicious_scans)

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
    ScanHistory.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return redirect(url_for('history'))

@app.route("/")
def home():
    # Automatically redirect active admins to the control panel
    if session.get('is_admin') or (current_user.is_authenticated and getattr(current_user, 'is_admin', False)):
        return redirect(url_for('admin_dashboard'))

    total_scans = ScanHistory.query.count()
    threats_detected = ScanHistory.query.filter(ScanHistory.status.in_(['Malicious', 'High Risk'])).count()
    return render_template("index.html", total_scans=total_scans, threats_detected=threats_detected,
                           ml_status="LOADED" if model_pipeline else "OFFLINE",
                           api_gateway_status="ONLINE",
                           openphish_status="ACTIVE" if openphish_engine else "STANDBY")

@app.route('/feedback', methods=['POST'])
def submit_feedback():
    data = request.get_json()
    if not data or 'scan_uuid' not in data or 'feedback_type' not in data:
        return jsonify({"success": False, "error": "Invalid feedback data."}), 400
        
    new_fb = FeedbackLog(
        scan_uuid=data['scan_uuid'],
        url=data.get('url', ''),
        feedback_type=data['feedback_type'],
        timestamp=datetime.now(MY_TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')
    )
    db.session.add(new_fb)
    db.session.commit()
    return jsonify({"success": True, "message": "Feedback recorded successfully for model evaluation."})

@app.route('/api/ai_briefing', methods=['POST'])
def api_ai_briefing():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    url = data.get('url', '')
    risk_score = data.get('risk_score', 0)
    risk_category = data.get('risk_category', 'Unknown')
    domain_age = data.get('domain_age', 'Unknown')
    flags = data.get('flags', [])
    intel_sources = data.get('intel_sources', [])
    
    anatomy = {'domain_age': domain_age, 'flags': flags}
    
    class IntelMock:
        def __init__(self, source, verdict):
            self.source = source
            self.verdict = verdict
            
    intel_results = [IntelMock(item.get('source'), item.get('verdict')) for item in intel_sources]
    
    briefing = generate_ai_threat_briefing(url, risk_score, risk_category, anatomy, intel_results)
    return jsonify({"ai_briefing": briefing})

@app.route('/batch_analyze', methods=['POST'])
def batch_analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file part uploaded."}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file."}), 400
    
    if file and file.filename.endswith('.csv'):
        try:
            stream = StringIO(file.stream.read().decode("UTF-8"))
            reader = csv.reader(stream)
            
            si = StringIO()
            writer = csv.writer(si)
            writer.writerow(['Scan UUID', 'Timestamp', 'Target URL', 'Risk Score', 'Status'])

            for row in reader:
                if not row: 
                    continue
                raw_url = row[0].strip()
                if not raw_url or raw_url.lower() == 'url' or raw_url.lower() == 'target url':
                    continue # Skip header row if present
                
                if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
                    raw_url = "https://" + raw_url

                target_url = expand_short_url(normalize_url(raw_url))
                scan_uuid = str(uuid.uuid4())
                timestamp_str = datetime.now(MY_TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')

                # Evaluate risk
                try:
                    features = extract_features(target_url)
                    features["raw_url"] = target_url
                    df = pd.DataFrame([features])
                    ml_probability = float(model_pipeline.predict_proba(df)[0][1]) if model_pipeline else 0.5
                    intel_results = query_threat_intelligence(target_url)
                    result = compute_final_risk(features, intel_results, ml_probability)
                    
                    risk_score = result.get("risk_score", ml_probability * 100)
                    status = result.get("risk_category", "Unknown")
                except Exception:
                    risk_score = 50.0
                    status = "Suspicious"

                # Save to ScanHistory if user is logged in
                new_scan = ScanHistory(
                    scan_uuid=scan_uuid, url_scanned=target_url, risk_score=risk_score, 
                    status=status, user_id=current_user.id if current_user.is_authenticated else None,
                    timestamp=timestamp_str
                )
                db.session.add(new_scan)
                writer.writerow([scan_uuid[:8].upper(), timestamp_str, target_url, round(risk_score, 1), status])

            db.session.commit()
            
            output = si.getvalue()
            return Response(
                output,
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=threatlink_batch_threat_report.csv"}
            )
        except Exception as e:
            logging.error(f"Batch processing error: {str(e)}")
            return jsonify({"error": f"Failed to process CSV batch: {str(e)}"}), 500

    return jsonify({"error": "Invalid file format. Please upload a .csv file."}), 400

@app.route("/analyze", methods=["POST"])
@limiter.limit("5 per minute") 
def analyze():
    raw_url = request.form.get("url", "").strip()
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    url_pattern = re.compile(r'^(https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(:[0-9]+)?(/.*)?$')
    if not url_pattern.match(raw_url):
         return jsonify({"error": "Invalid format! Please enter a proper web address."}), 400

    normalized = normalize_url(raw_url)
    
    redirect_chain = [raw_url]
    if normalized != raw_url:
        redirect_chain.append(normalized)
    
    target_url = expand_short_url(normalized)
    if target_url != redirect_chain[-1]:
        redirect_chain.append(target_url)

    from urllib.parse import urlparse
    parsed_domain = urlparse(target_url).netloc.lower()
    if parsed_domain.startswith("www."):
        parsed_domain = parsed_domain[4:]
        
    TRUSTED_DOMAINS = {"google.com", "youtube.com", "facebook.com", "apple.com", "microsoft.com", "github.com", "mmu.edu.my"}

    scan_uuid = str(uuid.uuid4())
    timestamp_str = datetime.now(MY_TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')

    if parsed_domain in TRUSTED_DOMAINS:
        intel_results = query_threat_intelligence(target_url)
        anatomy_data = analyze_url_anatomy(target_url)
        
        new_scan = ScanHistory(
            scan_uuid=scan_uuid, url_scanned=target_url, risk_score=0.0, status="Safe", 
            user_id=current_user.id if current_user.is_authenticated else None, timestamp=timestamp_str
        )
        db.session.add(new_scan)
        db.session.commit()
            
        total_scans = ScanHistory.query.count()
        threats_detected = ScanHistory.query.filter(ScanHistory.status.in_(['Malicious', 'High Risk'])).count()

        return jsonify({
            "scan_id": scan_uuid[:8].upper(),
            "timestamp": timestamp_str,
            "risk_score": 0.0,
            "risk_category": "Safe",
            "score_breakdown": {
                "ml_probability": 0.0,
                "heuristic_score": 0.0,
                "threat_intel_match": 0,
                "safety_override": "Applied Enterprise Whitelist Override (Risk set to 0.0)"
            },
            "top_features": [{"feature": "Enterprise Whitelist Match", "impact": 0.0, "desc": "Domain verified in trusted enterprise registry"}],
            "redirect_chain": redirect_chain,
            "anatomy": anatomy_data,
            "defanged_url": defang_url(target_url),
            "intel_results": [res.__dict__ for res in intel_results],
            "url": target_url,
            "findings": [
                "Domain matched against the Enterprise Trusted Whitelist.",
                "Bypassed Machine Learning and Heuristics to prevent false positives."
            ],
            "recommendations": ["This is a globally trusted and verified domain. Safe to browse."],
            "total_scans": total_scans,
            "threats_detected": threats_detected
        })

    try:
        features = extract_features(target_url)
        features["raw_url"] = target_url  
        df = pd.DataFrame([features])
        
        ml_probability = float(model_pipeline.predict_proba(df)[0][1]) if model_pipeline else 0.5
        intel_results = query_threat_intelligence(target_url)
        result = compute_final_risk(features, intel_results, ml_probability)

        score_breakdown = {
            "ml_probability": round(ml_probability * 100, 1),
            "heuristic_score": round(result.get('risk_score', 50) * 0.4, 1),
            "threat_intel_match": sum(1 for r in intel_results if r.verdict in ['Malicious', 'High Risk']),
            "safety_override": "None required (Computed via weighted ensemble model)"
        }
        
        anatomy_data = analyze_url_anatomy(target_url)

        result["scan_id"] = scan_uuid[:8].upper()
        result["timestamp"] = timestamp_str
        result["score_breakdown"] = score_breakdown
        result["top_features"] = get_top_ml_features(features, ml_probability)
        result["redirect_chain"] = redirect_chain
        result["anatomy"] = anatomy_data
        result["defanged_url"] = defang_url(target_url)
        result["intel_results"] = [res.__dict__ for res in intel_results]
        result["url"] = target_url
        result["recommendations"] = recommendations_for(result["risk_category"])

        new_scan = ScanHistory(
            scan_uuid=scan_uuid, url_scanned=target_url, risk_score=result.get("risk_score", ml_probability * 100), 
            status=result.get("risk_category", "Unknown"), user_id=current_user.id if current_user.is_authenticated else None,
            timestamp=timestamp_str
        )
        db.session.add(new_scan)
        db.session.commit()

        total_scans = ScanHistory.query.count()
        threats_detected = ScanHistory.query.filter(ScanHistory.status.in_(['Malicious', 'High Risk'])).count()

        result["total_scans"] = total_scans
        result["threats_detected"] = threats_detected

        return jsonify(result)

    except Exception as e:
        logging.error(f"Engine Crash during URL analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Our detection engine hit a snag while analyzing this URL.", "details": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
        except Exception:
            pass
        
    print("\n=========================================================")
    print(" 🛡️  HYBRID PHISHING DETECTION ENGINE - ONLINE")
    print(" 👤  Developed by: Amir Qayyuum")
    print(" 🌐  Dashboard live at: http://127.0.0.1:5000/")
    print("=========================================================\n")
    
    app.run(debug=True)