"""
Heuristic Analysis Module 
------------------------------------
Rule-based scoring for phishing indicators using extracted URL features
and a few direct URL pattern checks.

Maximum heuristic contribution: 40 points
"""

from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "icu", "rest", "country", "tk", "work", "quest"
}


def compute_heuristic_score(features: dict) -> tuple[int, list[str]]:
    points = 0
    reasons = []

    # --- 1) Keywords commonly used in credential-stealing pages ---
    if features.get("has_suspicious_keyword", 0) == 1:
        points += 7
        reasons.append("The URL contains suspicious keywords commonly used in phishing pages.")

    # --- 2) Too many subdomains (e.g., a.b.c.bank.com) ---
    if features.get("num_subdomains", 0) >= 3:
        points += 7
        reasons.append("The domain contains an unusually high number of subdomains.")

    # --- 3) IP address in domain (often malicious) ---
    if features.get("has_ip_in_domain", 0) == 1:
        points += 10
        reasons.append("The URL uses an IP address instead of a normal domain name.")

    # --- 4) Shortened URL (hides destination) ---
    if features.get("is_shortened_url", 0) == 1:
        points += 8
        reasons.append("The URL uses a shortening service, which can hide the true destination.")

    # --- 5) Punycode (homograph / lookalike risk) ---
    if features.get("has_punycode", 0) == 1:
        points += 8
        reasons.append("The URL contains punycode patterns, which may indicate a lookalike domain attack.")

    # --- 6) Very long URL ---
    if features.get("url_length", 0) >= 120:
        points += 5
        reasons.append("The URL is unusually long, which is a common trait in phishing links.")

    # --- 7) No HTTPS ---
    if features.get("has_https", 1) == 0:
        points += 6
        reasons.append("The URL does not use HTTPS, which increases the risk of interception or spoofing.")

    # --- 8) Excessive dots/hyphens (common in fake domains) ---
    if features.get("num_dots", 0) >= 5:
        points += 4
        reasons.append("The URL contains many dots, which can be used to mimic legitimate subdomains.")
    if features.get("num_hyphens", 0) >= 3:
        points += 4
        reasons.append("The URL contains many hyphens, which is common in deceptive domain names.")

    # --- 9) '@' symbol trick (username@domain confusion) ---
    if features.get("num_at_symbols", 0) >= 1:
        points += 10
        reasons.append("The URL contains an '@' symbol, a known phishing technique to hide the real domain.")

    # --- 10) Too many parameters (tracking / obfuscation) ---
    if features.get("num_equals", 0) >= 3:
        points += 4
        reasons.append("The URL contains many query parameters, which can be used to obfuscate malicious intent.")

    # --- 11) URL encoding or unusual characters (obfuscation) ---
    # We don't store the raw URL in features, so we infer via entropy + query length.
    if features.get("url_entropy", 0) >= 4.2:
        points += 5
        reasons.append("The URL has high randomness (entropy), which may indicate obfuscation.")
    if features.get("query_length", 0) >= 60:
        points += 4
        reasons.append("The URL has a long query string, which may be used to hide phishing payloads.")

    # --- 12) Suspicious TLD check (lightweight) ---
    # We can infer the TLD from domain length not directly available; do a quick parse safely.
    # If you prefer, you can move TLD into feature_extractor later.
    raw_url = features.get("_raw_url")
    if raw_url:
        try:
            netloc = urlparse(raw_url).netloc.lower()
            tld = netloc.split(".")[-1].split(":")[0]
            if tld in SUSPICIOUS_TLDS:
                points += 6
                reasons.append("The domain uses a suspicious top-level domain (TLD) often seen in phishing.")
        except Exception:
            pass

    # Cap at 40
    points = min(points, 40)
    return points, reasons
