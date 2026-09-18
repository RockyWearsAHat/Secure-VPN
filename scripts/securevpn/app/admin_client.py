"""
Admin API client for fetching authentication images.

Provides interfaces to fetch entropy images from the selfhost admin API
with caching and error handling.
"""

import base64
import time
import urllib.request
import urllib.error
import json
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class AdminAPIClient:
    """Client for fetching images from the admin API."""

    def __init__(self, base_url: str = "http://localhost:8080"):
        """Initialize the admin API client.

        Args:
            base_url: The base URL of the admin API (e.g., http://localhost:8080).
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = 5

    def fetch_image(self) -> Optional[bytes]:
        """Fetch the latest image from the admin API.

        Calls GET /api/images/latest and decodes the base64 image data.

        Returns:
            The decoded image bytes, or None on error.
        """
        url = f"{self.base_url}/api/images/latest"

        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                data = response.read()
                response_obj = json.loads(data)

                if 'image' not in response_obj:
                    logger.warning("API response missing 'image' field")
                    return None

                # Decode base64 image data
                image_b64 = response_obj['image']
                image_bytes = base64.b64decode(image_b64)
                return image_bytes

        except urllib.error.URLError as e:
            logger.warning(f"Failed to fetch image from {url}: {e}")
            return None
        except urllib.error.HTTPError as e:
            logger.warning(f"HTTP error fetching image: {e.code} {e.reason}")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON response from API: {e}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error fetching image: {e}")
            return None

    def fetch_image_metadata(self) -> Optional[dict]:
        """Fetch metadata about the latest image.

        Returns:
            A dictionary with image metadata, or None on error.
        """
        url = f"{self.base_url}/api/images/latest"

        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                data = response.read()
                response_obj = json.loads(data)
                return response_obj

        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, Exception) as e:
            logger.warning(f"Failed to fetch image metadata: {e}")
            return None


class CachedAdminAPIClient:
    """Cached wrapper for the admin API client.

    Caches image data for 30 seconds to reduce API calls.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        cache_ttl: float = 30.0,
    ):
        """Initialize the cached admin API client.

        Args:
            base_url: The base URL of the admin API.
            cache_ttl: Cache time-to-live in seconds (default 30).
        """
        self.client = AdminAPIClient(base_url)
        self.cache_ttl = cache_ttl
        self._cached_image = None
        self._cache_time = None
        self._cache_miss_time = None
        self.cache_miss_backoff = 5  # Don't retry for 5 seconds after a miss

    def fetch_image(self) -> Optional[bytes]:
        """Fetch the latest image, using cache if available.

        Returns:
            The decoded image bytes, or None on error.
        """
        current_time = time.time()

        # Check if we have a valid cached image
        if (
            self._cached_image is not None
            and self._cache_time is not None
            and current_time - self._cache_time < self.cache_ttl
        ):
            return self._cached_image

        # Check if we're in backoff after a recent miss
        if (
            self._cache_miss_time is not None
            and current_time - self._cache_miss_time < self.cache_miss_backoff
        ):
            return self._cached_image  # Return stale cache if available

        # Fetch fresh image
        image = self.client.fetch_image()

        if image is not None:
            self._cached_image = image
            self._cache_time = current_time
            self._cache_miss_time = None
        else:
            self._cache_miss_time = current_time

        return image

    def clear_cache(self) -> None:
        """Clear the cached image data."""
        self._cached_image = None
        self._cache_time = None
        self._cache_miss_time = None

    def get_cache_age(self) -> Optional[float]:
        """Get the age of the cached image in seconds.

        Returns:
            The cache age in seconds, or None if not cached.
        """
        if self._cache_time is None:
            return None
        return time.time() - self._cache_time

    def is_cache_valid(self) -> bool:
        """Check if the current cache is still valid.

        Returns:
            True if cache is valid, False otherwise.
        """
        if self._cache_time is None:
            return False
        age = self.get_cache_age()
        return age is not None and age < self.cache_ttl
