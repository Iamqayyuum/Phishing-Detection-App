import time
import requests
from dataclasses import dataclass

# Fallback timeout configuration if config import fails
try:
    from config import TIMEOUT_SECONDS
except ImportError:
    TIMEOUT_SECONDS = 5

@dataclass
class OpenPhishResult:
    source: str = "OpenPhish Live Feed"
    verdict: str = "clean"  # "malicious", "clean", or "error"
    detail: str = ""

class OpenPhishEngine:
    def __init__(self, cache_duration_seconds: int = 1800):
        """
        Initializes the OpenPhish real-time feed intelligence engine.
        Implements a local caching layer (default: 30 minutes / 1800s) to minimize
        redundant network overhead and prevent application rate-limiting.
        """
        self.feed_url = "https://openphish.com/feed.txt"
        self.cache_duration = cache_duration_seconds
        self.cached_urls = set()
        self.last_fetch_time = 0.0

    def _refresh_feed_if_expired(self) -> bool:
        """
        Internal helper to check memory age and download the active feed 
        from OpenPhish if the cache window has expired.
        """
        current_time = time.time()
        # If cache is still warm and valid, bypass the download
        if current_time - self.last_fetch_time < self.cache_duration and self.cached_urls:
            return True

        try:
            response = requests.get(self.feed_url, timeout=TIMEOUT_SECONDS)
            if response.status_code == 200:
                # Split raw text block into a high-speed lookup set
                lines = response.text.splitlines()
                self.cached_urls = set(url.strip() for url in lines if url.strip())
                self.last_fetch_time = current_time
                return True
            return False
        except Exception:
            # Fail silently regarding network; downstream check will mark as error/unknown
            return False

    def check_url(self, target_url: str) -> OpenPhishResult:
        """
        Evaluates an ingestion link against the synchronized in-memory OpenPhish list.
        """
        if not target_url:
            return OpenPhishResult(verdict="clean", detail="Empty URL provided.")

        # Refresh feed. If network completely fails, fall back to current cache if available
        feed_available = self._refresh_feed_if_expired()
        
        cleaned_target = target_url.strip()

        if cleaned_target in self.cached_urls:
            return OpenPhishResult(
                verdict="malicious",
                detail="Critical Match: This URL is listed on the active OpenPhish live threat feed."
            )
            
        if not feed_available and not self.cached_urls:
            return OpenPhishResult(
                verdict="error",
                detail="Threat intelligence feed unavailable due to external connection timeout."
            )

        return OpenPhishResult(
            verdict="clean",
            detail="URL is not currently flagged in the OpenPhish community repository feed."
        )

# Global singleton instance for your Flask runtime environment to preserve memory cache
openphish_analyzer = OpenPhishEngine()