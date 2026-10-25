from config import WEIGHTS, RISK_THRESHOLDS
from core.heuristics import compute_heuristic_score

def compute_final_risk(features, intel_results, ml_probability):
    reasons = []

    # 1) Heuristics
    heuristic_score, heuristic_reasons = compute_heuristic_score(features)
    heuristic_score = min(heuristic_score, WEIGHTS["heuristics_max"])
    reasons.extend(heuristic_reasons)

    # 2) Threat Intelligence
    intel_score = 0
    malicious_api_count = 0 

    for intel in intel_results:
        source_name = intel.source.lower()
        
        # Removed Google Web Risk from the API checks
        if "virustotal" in source_name or "openphish" in source_name:
            if intel.verdict == "malicious":
                intel_score += 10
                malicious_api_count += 1
                reasons.append(f"Security Alert: {intel.source} has confirmed this link is dangerous.")
            elif intel.verdict == "suspicious":
                intel_score += 5
                reasons.append(f"Security Warning: {intel.source} flagged this link as suspicious.")
                
        if intel.verdict == "error":
            reasons.append(f"Connection Note: We couldn't check {intel.source} right now.")

    intel_score = min(intel_score, WEIGHTS["threat_intel_max"])

    # 3) Machine Learning
    ml_score = round(ml_probability * WEIGHTS["ml_max"], 2)
    
    if ml_probability >= 0.7:
        reasons.append("Pattern Analysis: Our AI model detected strong signs of a phishing attempt in this URL.")
    elif ml_probability >= 0.4:
        reasons.append("Pattern Analysis: This URL shows some characteristics often seen in phishing websites.")
    else:
        reasons.append("Pattern Analysis: The URL structure appears to be standard and doesn't match typical phishing patterns.")

    final_score = min(round(heuristic_score + intel_score + ml_score, 2), 100)

    # 4) Critical Overrides
    if malicious_api_count > 0:
        if malicious_api_count == 1:
            final_score = max(final_score, 85.0)
            reasons.append("Safety Override: One major security authority flagged this URL. We have set the risk level to High for your protection.")
        else:
            final_score = 99.9
            reasons.append(f"Safety Override: {malicious_api_count} different security services flagged this as a threat. This link is extremely dangerous.")

    # 5) Categorization
    if final_score <= RISK_THRESHOLDS["low_max"]:
        category = "Low Risk"
        recommendation = "You're likely safe here, but keep your guard up when entering private info."
    elif final_score <= RISK_THRESHOLDS["suspicious_max"]:
        category = "Suspicious"
        recommendation = "We found some red flags. Please double-check the URL and make sure you really know this sender before continuing."
    else:
        category = "High Risk"
        recommendation = "This is almost certainly a phishing site. Please close this tab immediately and do not enter any credentials."

    return {
        "risk_score": final_score,
        "risk_category": category,
        "reasons": reasons,
        "recommendation": recommendation
    }