import re
import math
from urllib.parse import urlparse, parse_qs
import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "bank",
    "signin", "confirm", "password", "wallet", "payment",
    "ebay", "paypal", "amazon", "apple", "microsoft", "google",
    "facebook", "instagram", "netflix", "support", "helpdesk",
    "reset", "suspend", "blocked", "alert", "urgent", "limited",
    "validation", "authenticate", "credential", "billing", "invoice",
    "checkout", "cardverify", "transaction", "authorize", "recovery",
    "unlock", "verification", "notification", "prize", "winner",
    "click", "download", "redirect", "token", "session"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "rebrand.ly", "short.io", "tiny.cc"
}

RISKY_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "club",
    "online", "site", "info", "buzz", "work", "click", "link",
    "win", "download", "stream", "gdn", "science", "party",
    "review", "trade", "webcam", "racing", "accountant",
    "loan", "cricket", "faith", "date", "men", "bid"
}

BRAND_NAMES = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "netflix", "ebay", "bank", "wellsfargo", "chase",
    "hsbc", "barclays", "dropbox", "linkedin", "twitter", "whatsapp",
    "dhl", "fedex", "ups", "usps", "irs", "gov", "coinbase",
    "binance", "blockchain", "metamask", "steam", "roblox", "discord"
]

SAFE_TLDS = {"com", "org", "edu", "gov", "net", "co", "io", "ac"}

SUSPICIOUS_EXTENSIONS = {".php", ".asp", ".aspx", ".cgi", ".exe", ".js"}

# Common legitimate domains - if URL contains these as the exact registered
# domain it is likely benign
TRUSTED_DOMAINS = {
    "google", "youtube", "facebook", "amazon", "twitter", "instagram",
    "linkedin", "microsoft", "apple", "github", "stackoverflow",
    "wikipedia", "reddit", "netflix", "spotify", "dropbox"
}

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def _count_repeated_chars(text: str) -> int:
    """Count characters that appear more than twice consecutively."""
    return len(re.findall(r'(.)\1{2,}', text))

def _longest_token(text: str) -> int:
    """Return length of longest alphanumeric token."""
    tokens = re.findall(r'[a-zA-Z0-9]+', text)
    return max((len(t) for t in tokens), default=0)

def extract_features(url: str) -> dict:
    """
    Extract lightweight features used for:
    - heuristic scoring
    - machine learning classification
    """
   
    try:
        parsed = urlparse(url)
    except ValueError:
        # If the URL is so broken it crashes the parser, fallback to an empty parse result
        # This prevents the crash and safely passes empty strings to the rest of the function
        parsed = urlparse("")
    # ---------------------------------------
    
    ext = tldextract.extract(url)

    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain = ext.subdomain or ""
    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = url.lower()
    domain_lower = domain.lower()
    netloc = parsed.netloc or ""
    full_domain = netloc.split(":")[0]

    features = {}

   

    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_at_symbols"] = url.count("@")
    features["num_question_marks"] = url.count("?")
    features["num_equals"] = url.count("=")
    features["num_slashes"] = url.count("/")

    features["num_subdomains"] = len([s for s in subdomain.split(".") if s]) if subdomain else 0
    features["has_https"] = 1 if parsed.scheme == "https" else 0

    features["has_ip_in_domain"] = 1 if re.fullmatch(
        r"\d{1,3}(\.\d{1,3}){3}", full_domain
    ) else 0

    features["has_suspicious_keyword"] = 1 if any(k in url_lower for k in SUSPICIOUS_KEYWORDS) else 0
    features["is_shortened_url"] = 1 if domain_lower in SHORTENER_DOMAINS else 0
    features["url_entropy"] = round(_shannon_entropy(url), 4)
    features["has_punycode"] = 1 if "xn--" in netloc.lower() else 0

    

    digits = sum(c.isdigit() for c in url)
    features["digit_ratio"] = round(digits / len(url), 4) if url else 0

    letters = sum(c.isalpha() for c in url)
    features["letter_ratio"] = round(letters / len(url), 4) if url else 0

    features["num_special_chars"] = len(re.findall(r'[^a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]', url))
    features["has_risky_tld"] = 1 if ext.suffix.lower() in RISKY_TLDS else 0

    words = re.split(r'[^a-zA-Z]', url)
    features["longest_word_length"] = max((len(w) for w in words if w), default=0)

    features["has_double_slash"] = 1 if "//" in path else 0
    features["domain_digit_count"] = sum(c.isdigit() for c in domain)
    
   
    try:
        features["has_port"] = 1 if parsed.port is not None else 0
    except ValueError:
        features["has_port"] = 0
   
        
    features["url_depth"] = len([seg for seg in path.split('/') if seg])
    features["domain_digit_ratio"] = round(
        sum(c.isdigit() for c in domain) / len(domain), 4
    ) if domain else 0

    
    
  

    features["has_brand_in_domain"] = 1 if any(b in domain_lower for b in BRAND_NAMES) else 0
    features["has_brand_in_subdomain"] = 1 if any(b in subdomain.lower() for b in BRAND_NAMES) else 0
    features["domain_hyphens"] = domain.count("-")
    features["domain_hyphen_ratio"] = round(domain.count("-") / len(domain), 4) if domain else 0
    features["num_numeric_sequences"] = len(re.findall(r'\d+', url))
    features["subdomain_length"] = len(subdomain)
    features["query_has_keyword"] = 1 if any(k in query.lower() for k in SUSPICIOUS_KEYWORDS) else 0
    features["path_has_keyword"] = 1 if any(k in path.lower() for k in SUSPICIOUS_KEYWORDS) else 0

    upper = sum(c.isupper() for c in url)
    features["uppercase_ratio"] = round(upper / len(url), 4) if url else 0

    features["domain_entropy"] = round(_shannon_entropy(ext.domain), 4)
    features["subdomain_entropy"] = round(_shannon_entropy(subdomain), 4)
    features["has_hex_encoding"] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0

 

    consonants = sum(1 for c in ext.domain.lower() if c in "bcdfghjklmnpqrstvwxyz")
    features["domain_consonant_ratio"] = round(consonants / len(ext.domain), 4) if ext.domain else 0

    vowels = sum(1 for c in ext.domain.lower() if c in "aeiou")
    features["domain_vowel_ratio"] = round(vowels / len(ext.domain), 4) if ext.domain else 0

    try:
        query_params = parse_qs(query)
        features["num_query_params"] = len(query_params)
    except Exception:
        features["num_query_params"] = 0

    features["has_safe_tld"] = 1 if ext.suffix.lower() in SAFE_TLDS else 0
    features["registered_domain_length"] = len(ext.domain)
    features["path_url_ratio"] = round(len(path) / len(url), 4) if url else 0
    features["has_fragment"] = 1 if parsed.fragment else 0

    consecutive = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', ext.domain.lower())
    features["max_consecutive_consonants"] = max((len(c) for c in consecutive), default=0)

    features["subdomain_digit_count"] = sum(c.isdigit() for c in subdomain)
    features["has_suspicious_extension"] = 1 if any(
        path.lower().endswith(e) for e in SUSPICIOUS_EXTENSIONS
    ) else 0
    features["suspicious_keyword_count"] = sum(1 for k in SUSPICIOUS_KEYWORDS if k in url_lower)
    features["brand_count_in_url"] = sum(1 for b in BRAND_NAMES if b in url_lower)
    features["subdomain_has_hyphen"] = 1 if "-" in subdomain else 0
    features["query_url_ratio"] = round(len(query) / len(url), 4) if url else 0



    # Trusted domain match — registered domain exactly matches known safe brand
    features["is_trusted_domain"] = 1 if ext.domain.lower() in TRUSTED_DOMAINS else 0

    # Ratio of unique characters in URL (low uniqueness = repetitive = suspicious)
    features["unique_char_ratio"] = round(
        len(set(url_lower)) / len(url), 4
    ) if url else 0

    # Longest consecutive digit sequence in URL
    digit_seqs = re.findall(r'\d+', url)
    features["longest_digit_sequence"] = max((len(d) for d in digit_seqs), default=0)

    # Number of ampersands in query (many params chained together)
    features["num_ampersands"] = url.count("&")

    # Path segment count (alias for url_depth but measured differently)
    features["path_token_count"] = len([t for t in re.split(r'[/\-_.]', path) if t])

    # Repeated character patterns in domain (gibberish signal)
    features["domain_repeated_chars"] = _count_repeated_chars(ext.domain)

    # Longest alphanumeric token in full URL
    features["longest_token_url"] = _longest_token(url)

    # Longest alphanumeric token in domain specifically
    features["longest_token_domain"] = _longest_token(domain)

    # Whether the URL contains an email address pattern (phishing lure)
    features["has_email_in_url"] = 1 if re.search(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', url) else 0

    # Ratio of dots to URL length (many dots = many subdomains = suspicious)
    features["dot_ratio"] = round(url.count(".") / len(url), 4) if url else 0

    # Whether netloc (host) length is unusually long (>50 chars)
    features["netloc_length"] = len(netloc)

    # Number of semicolons (used in some obfuscation techniques)
    features["num_semicolons"] = url.count(";")

    return features