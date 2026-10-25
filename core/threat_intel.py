from dataclasses import dataclass
import time
import requests
import logging
from requests.exceptions import Timeout, RequestException

# Simple terminal logging to help debug during local testing
logging.basicConfig(level=logging.INFO)

# Pulling API keys and our 5-second timeout rule from config
from config import VIRUSTOTAL_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY, TIMEOUT_SECONDS

@dataclass
class IntelResult:
    # A clean way to standardize the output from 3 completely different APIs
    source: str
    verdict: str   # Options: "malicious", "suspicious", "clean", "unknown", "error"
    detail: str

class OpenPhishFeedManager:
    # Manages the OpenPhish text feed.
    # We download the list of bad URLs and cache it in memory for 30 minutes (1800s)
    # so we don't hammer their servers and slow down our app on every single scan.
    
    def __init__(self, cache_duration_seconds: int = 1800):
        self.feed_url = "https://openphish.com/feed.txt"
        self.cache_duration = cache_duration_seconds
        self.cached_urls = set()
        self.last_fetch_time = 0.0

    def refresh_feed_if_expired(self) -> bool:
        current_time = time.time()
        
        # Check if our local cache is still fresh
        if current_time - self.last_fetch_time < self.cache_duration and self.cached_urls:
            return True

        try:
            # Grab the latest list of zero-day threats
            resp = requests.get(self.feed_url, timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                # Store the links in a Python 'set' because looking up items in a set is much faster than a list
                self.cached_urls = set(line.strip() for line in resp.text.splitlines() if line.strip())
                self.last_fetch_time = current_time
                logging.info(f"OpenPhish updated! Cached {len(self.cached_urls)} active threats.")
                return True
            return False
        except Exception:
            return False

    def check_url(self, url: str) -> IntelResult:
        feed_available = self.refresh_feed_if_expired()
        
        if url.strip() in self.cached_urls:
            return IntelResult("OpenPhish Live Feed", "malicious", "Matched an active zero-day threat on OpenPhish.")
            
        if not feed_available and not self.cached_urls:
            return IntelResult("OpenPhish Live Feed", "error", "Could not connect to the live feed.")
            
        return IntelResult("OpenPhish Live Feed", "clean", "Not found in the current OpenPhish database.")


# Start the tracker once when the app launches so it holds memory properly
openphish_engine = OpenPhishFeedManager()


def query_google_web_risk(url: str) -> IntelResult:
    # Check the URL against Google's Web Risk API
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return IntelResult("Google Web Risk", "unknown", "API key is missing.")

    # Pass the API key directly in the URL string, pulling securely from our config
    endpoint = f"https://webrisk.googleapis.com/v1/uris:search?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    
    params = {
        "uri": url,
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
    }

    try:
        resp = requests.get(endpoint, params=params, timeout=TIMEOUT_SECONDS)
        
        # Google will block us if we spam the free tier
        if resp.status_code == 429:
             return IntelResult("Google Web Risk", "error", "API rate limit exceeded.")
        elif resp.status_code != 200:
            return IntelResult("Google Web Risk", "error", f"Failed with status: {resp.status_code}")

        data = resp.json()
        threat = data.get("threat")
        
        if threat and threat.get("threatTypes"):
            threat_list = threat.get("threatTypes")
            return IntelResult("Google Web Risk", "malicious", f"Google flagged this as: {', '.join(threat_list)}.")
            
        return IntelResult("Google Web Risk", "clean", "Google reports this URL as safe.")
        
    except Timeout:
        logging.warning("Google API took too long to respond.")
        return IntelResult("Google Web Risk", "error", "Connection timed out.")
    except RequestException:
        return IntelResult("Google Web Risk", "error", "Network connection failed.")
    except Exception as e:
        return IntelResult("Google Web Risk", "error", f"Unexpected error: {str(e)}")


def query_virustotal(url: str) -> IntelResult:
    # Query VirusTotal v3 API. 
    # This requires two steps: POST to submit the URL, then GET to read the analysis.
    if not VIRUSTOTAL_API_KEY:
        return IntelResult("VirusTotal", "unknown", "API key is missing.")

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        # Step 1: Submit the URL for scanning
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=TIMEOUT_SECONDS
        )
        
        if submit_resp.status_code == 429:
             return IntelResult("VirusTotal", "error", "API rate limit exceeded.")
        elif submit_resp.status_code not in (200, 201):
            return IntelResult("VirusTotal", "error", f"Submission failed (Status {submit_resp.status_code})")

        data = submit_resp.json()
        analysis_id = data.get("data", {}).get("id")
        
        if not analysis_id:
            return IntelResult("VirusTotal", "error", "VT didn't return an analysis ID.")

        # Step 2: Fetch the actual results using the ID we just got
        analysis_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=TIMEOUT_SECONDS
        )
        
        if analysis_resp.status_code == 429:
             return IntelResult("VirusTotal", "error", "Hit rate limit while checking results.")
        elif analysis_resp.status_code != 200:
            return IntelResult("VirusTotal", "error", f"Result fetch failed (Status {analysis_resp.status_code})")

        stats = analysis_resp.json().get("data", {}).get("attributes", {}).get("stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        # Check if enough engines flagged it
        if malicious > 0:
            return IntelResult("VirusTotal", "malicious", f"Flagged by {malicious} security vendors.")
        if suspicious > 0:
            return IntelResult("VirusTotal", "suspicious", f"Marked suspicious by {suspicious} vendors.")
            
        return IntelResult("VirusTotal", "clean", "0 security vendors flagged this URL.")
        
    except Timeout:
        logging.warning("VirusTotal API took too long to respond.")
        return IntelResult("VirusTotal", "error", "Connection timed out.")
    except RequestException:
        return IntelResult("VirusTotal", "error", "Network connection failed.")
    except Exception as e:
        return IntelResult("VirusTotal", "error", f"Unexpected error: {str(e)}")


def query_threat_intelligence(url: str) -> list[IntelResult]:
    # Run the URL through all 3 threat intelligence sources and group the results
    results = []
    results.append(query_google_web_risk(url))
    results.append(query_virustotal(url))
    results.append(openphish_engine.check_url(url)) 
    return results