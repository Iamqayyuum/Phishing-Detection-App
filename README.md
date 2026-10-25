<<<<<<< HEAD
# 🛡️ Phishing URL Risk Analyzer

**Project ID:** FYP02-CS-T2610-0815  
**Developer:** Mohamad Amir Qayyuum | BSc. Computer Science (Cybersecurity) | Multimedia University  
**System Accuracy:** 92.58% (Tested on 222,000 instances)  

## 📌 Project Overview
The Phishing URL Risk Analyzer is a Smart Web Application designed to detect zero-day phishing campaigns by bridging the 'time-to-index' gap. It utilizes a 3-Tier Hybrid Architecture integrating an XGBoost machine learning pipeline, heuristic analysis, and real-time API evidence fusion (Critical Threat Override).

## 📂 Project Structure

```text
├── app.py                           # The main Flask routing engine and API endpoints
├── config.py                        # The central brain for weights and thresholds
├── .env.example                     # Template for hidden API keys (VT, Google Web Risk)
├── requirements.txt                 # The master list of Python dependencies
│
├── core/                            # ⚙️ THE DETECTION ENGINES
│   ├── __init__.py                  # Tells Python this is a module
│   ├── feature_extractor.py         # Calculates the math and structural rules
│   ├── heuristics.py                # Flags anomalies like '@' symbols or IP addresses
│   ├── ml_model.py                  # Loads the AI into memory
│   ├── scoring.py                   # The 100-point Fusion logic and CTO mechanism
│   ├── threat_intel.py              # Handles Google Web Risk and VirusTotal APIs
│   ├── url_processor.py             # Cleans, normalizes, and traces raw links
│   └── explanation.py               # Generates the text advice for the UI
│
├── model/                           # 🧠 THE AI BRAIN
│   ├── phishing_model.pkl           # Trained XGBoost Machine Learning Pipeline
│   └── feature_order.json           # The exact map the AI needs to read the data
│
├── static/ & templates/             # 🎨 THE FRONTEND UI
│   ├── static/style.css             # System UI and dark-mode styling
│   └── templates/index.html         # Main dashboard and user session portals
│
└── training/                        # 🔬 RESEARCH & DEVELOPMENT
    ├── train_model.py               # Original model training scripts
    ├── prepare_dataset.py           # Data preprocessing and feature engineering
    ├── evaluate_model.py            # Validation Engine
    ├── dataset.csv                  # Datasets used for training
    └── confusion_matrix.png         # Empirical proof for thesis evaluation
=======
# phishing_detector_app
>>>>>>> 045ea5fd671be5aedd5239325373e551a5963d55
