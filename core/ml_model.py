import os
import json
import joblib
import pandas as pd
import logging

# Set up basic logging for terminal tracking
logging.basicConfig(level=logging.INFO)

MODEL_PATH = "model/phishing_model.pkl"
FEATURE_ORDER_PATH = "model/feature_order.json"

class MLResult:
    def __init__(self, probability: float, verdict: str):
        self.probability = probability
        self.verdict = verdict

# =================================================================
# 1) SINGLETON LOADING & FAULT TOLERANCE
# Load the model once on server startup, not on every request.
# =================================================================
global_model = None
global_feature_order = None

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(FEATURE_ORDER_PATH):
        global_model = joblib.load(MODEL_PATH)
        with open(FEATURE_ORDER_PATH, "r", encoding="utf-8") as f:
            global_feature_order = json.load(f)
        logging.info("✅ ML model and feature map loaded successfully into memory.")
    else:
        logging.warning("⚠️ Model files not found. ML engine will default to 0.0.")
except Exception as e:
    logging.error(f"❌ Failed to load ML model: {str(e)}. ML engine disabled.")

# =================================================================
# 2) PREDICTION LOGIC
# =================================================================
def predict_phishing_probability(feature_dict: dict) -> MLResult:
    """
    Predict phishing probability using the trained Random Forest model.
    Fails safely and defaults to 0.0 if the model is missing.
    """
    # Graceful Fallback: If model is broken, don't crash. Just return 0.
    if global_model is None or global_feature_order is None:
        return MLResult(probability=0.0, verdict="benign")

    # Ensure features are ordered exactly as during training
    row = []
    for feature in global_feature_order:
        row.append(feature_dict.get(feature, 0))

    # Use DataFrame with feature names to prevent Scikit-Learn warnings
    X = pd.DataFrame([row], columns=global_feature_order)

    # Calculate probability
    phishing_probability = global_model.predict_proba(X)[0][1]
    verdict = "phishing" if phishing_probability >= 0.5 else "benign"

    return MLResult(
        probability=float(phishing_probability),
        verdict=verdict
    )