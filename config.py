import os
from dotenv import load_dotenv

# The override=True forces Python to ignore cached system variables 
# and strictly use what is currently written in the .env file.
load_dotenv(override=True)

# Threat-intelligence API keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

# Scoring weights (Mathematically tuned for our FYP2 Weighted Evidence Fusion Framework)
WEIGHTS = {
    "heuristics_max": 40,      # Structural rule engine contributes up to 40 points
    "threat_intel_max": 35,    # Multi-engine API telemetry contributes up to 35 points
    "ml_max": 25               # Random Forest probability contributes up to 25 points
}

# Risk thresholds (0–100 scale used by the frontend dashboard)
RISK_THRESHOLDS = {
    "low_max": 29,
    "suspicious_max": 59
}

# API connection limits (Prevents the Flask app from freezing if an external server goes offline)
TIMEOUT_SECONDS = 5