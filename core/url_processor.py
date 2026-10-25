import requests
from urllib.parse import urlparse, urlunparse

def normalize_url(raw_url: str) -> str:
    """
    Normalize a user-input URL into a consistent format.
    - Adds scheme if missing
    - Strips whitespace
    - Prevents common formatting issues
    """
    if not raw_url:
        return ""

    url = raw_url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # --- MALFORMED IPv6 FIX APPLIED HERE ---
    try:
        parsed = urlparse(url)
    except ValueError:
        # If the URL is so mangled it crashes the parser (e.g., bad IPv6 brackets)
        # just return the raw, stripped URL string as a fallback.
        return url.lower()
    # ---------------------------------------

    # If user enters something like "http://", treat as invalid later
    netloc = parsed.netloc.strip()
    path = parsed.path.strip()

    normalized = urlunparse((
        parsed.scheme.lower(),
        netloc.lower(),
        path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
    return normalized

def expand_short_url(url: str) -> str:
    """
    Detects if a URL is from a known shortener and resolves its true destination.
    This prevents attackers from hiding malicious payloads behind bit.ly, t.co, etc.
    """
    # List of common URL shortener domains
    shorteners = [
        'bit.ly', 't.co', 'tinyurl.com', 'is.gd', 
        'cli.gs', 'pic.twitter.com', 'ow.ly', 'goo.gl', 'buff.ly'
    ]
    
    # Check if the URL contains any of the shortener domains
    if any(short_domain in url for short_domain in shorteners):
        try:
            # Send a HEAD request to follow the redirect without downloading the whole page
            response = requests.head(url, allow_redirects=True, timeout=3)
            return response.url # Return the true, unmasked URL
        except requests.RequestException:
            # If the request fails (e.g., timeout or dead link), return the original
            return url
            
    # If it's not a short URL, just return it as is
    return url

def is_valid_url(url: str) -> bool:
    """
    Basic URL validation for web submission.
    """
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme) and bool(parsed.netloc)
    except Exception:
        return False

def parse_url(url: str):
    """
    Return parsed components for later modules.
    """
    # Safeguard this one just in case as well
    try:
        return urlparse(url)
    except ValueError:
        return None