"""
Image-based time-locked VPN authentication.

Implements visual-entropy image-based authentication for VPN handshakes.
Uses image data and time-bucketed keys for per-30-second authentication.
"""

import hashlib
import time
from typing import Optional, Tuple
from functools import lru_cache
import threading


class ImageAuthValidator:
    """Validates image-based authentication keys for VPN handshakes.

    Uses time-bucketed authentication with ±30 second tolerance.
    Implements multi-layer caching for performance.
    """

    def __init__(self, cache_size: int = 1000):
        """Initialize the validator with optional cache size."""
        self.cache_size = cache_size
        self._cache = {}
        self._lock = threading.Lock()
        self._image_data = None
        self._image_timestamp = None

    def set_image_data(self, image_data: bytes) -> None:
        """Store the current image data for authentication.

        Args:
            image_data: The raw image bytes to use for authentication.
        """
        with self._lock:
            self._image_data = image_data
            self._image_timestamp = time.time()
            self._cache.clear()  # Invalidate cache on new image

    def get_image_data(self) -> Optional[bytes]:
        """Retrieve the stored image data.

        Returns:
            The current image data, or None if not set.
        """
        with self._lock:
            return self._image_data

    def get_image_age(self) -> Optional[float]:
        """Get the age of the current image in seconds.

        Returns:
            The age of the image in seconds, or None if not set.
        """
        with self._lock:
            if self._image_timestamp is None:
                return None
            return time.time() - self._image_timestamp

    def _get_bucket(self, timestamp: float) -> int:
        """Calculate the 30-second bucket for a timestamp.

        Args:
            timestamp: Unix timestamp in seconds.

        Returns:
            The bucket start time (floor to 30-second boundary).
        """
        return int((timestamp // 30) * 30)

    def derive_auth_key(
        self, image_data: bytes, timestamp: float
    ) -> bytes:
        """Derive a 32-byte authentication key from image data and timestamp.

        Uses SHA3-256 with time-bucketed values.

        Args:
            image_data: The image data bytes.
            timestamp: Unix timestamp in seconds.

        Returns:
            A 32-byte authentication key.
        """
        bucket = self._get_bucket(timestamp)
        bucket_bytes = bucket.to_bytes(8, byteorder='big')
        combined = image_data + bucket_bytes
        return hashlib.sha3_256(combined).digest()

    def validate_auth_key(
        self, provided_key: bytes, current_time: Optional[float] = None
    ) -> bool:
        """Validate an authentication key against the current image.

        Checks current and previous time buckets (±30 sec tolerance).

        Args:
            provided_key: The 32-byte key provided by the client.
            current_time: Optional timestamp override (defaults to now).

        Returns:
            True if the key is valid, False otherwise.
        """
        if self._image_data is None:
            return False

        if current_time is None:
            current_time = time.time()

        if len(provided_key) != 32:
            return False

        # Check with cache
        with self._lock:
            if self._image_data is None:
                return False
            image_data = self._image_data

        # Create cache key
        cache_key = (
            id(image_data),
            current_time // 30  # Cache by bucket
        )

        with self._lock:
            if cache_key in self._cache:
                valid_keys = self._cache[cache_key]
                return provided_key in valid_keys

        # Generate valid keys for current and previous buckets
        current_bucket = self._get_bucket(current_time)
        previous_bucket = current_bucket - 30

        valid_keys = set()
        for bucket_time in [current_bucket, previous_bucket]:
            key = self.derive_auth_key(image_data, bucket_time)
            valid_keys.add(key)

        # Store in cache
        with self._lock:
            if len(self._cache) >= self.cache_size:
                # Simple eviction: clear oldest 10%
                to_remove = list(self._cache.keys())[: self.cache_size // 10]
                for k in to_remove:
                    del self._cache[k]
            self._cache[cache_key] = valid_keys

        return provided_key in valid_keys

    def validate_auth_key_with_tolerance(
        self,
        provided_key: bytes,
        current_time: Optional[float] = None,
        tolerance_sec: int = 30,
    ) -> bool:
        """Validate an authentication key with custom tolerance window.

        Args:
            provided_key: The 32-byte key provided by the client.
            current_time: Optional timestamp override (defaults to now).
            tolerance_sec: Tolerance window in seconds (multiples of 30).

        Returns:
            True if the key is valid within tolerance, False otherwise.
        """
        if self._image_data is None:
            return False

        if current_time is None:
            current_time = time.time()

        if len(provided_key) != 32:
            return False

        with self._lock:
            if self._image_data is None:
                return False
            image_data = self._image_data

        current_bucket = self._get_bucket(current_time)
        bucket_count = (tolerance_sec // 30) + 1

        for i in range(bucket_count):
            bucket_time = current_bucket - (i * 30)
            key = self.derive_auth_key(image_data, bucket_time)
            if key == provided_key:
                return True

        return False

    def get_current_key(self, current_time: Optional[float] = None) -> Optional[bytes]:
        """Get the current valid authentication key.

        Returns the key for the current 30-second bucket.

        Args:
            current_time: Optional timestamp override (defaults to now).

        Returns:
            The current authentication key, or None if no image is set.
        """
        if self._image_data is None:
            return None

        if current_time is None:
            current_time = time.time()

        with self._lock:
            if self._image_data is None:
                return None
            return self.derive_auth_key(self._image_data, current_time)

    def get_next_key(self, current_time: Optional[float] = None) -> Optional[bytes]:
        """Get the next authentication key (30 seconds from now).

        Args:
            current_time: Optional timestamp override (defaults to now).

        Returns:
            The next authentication key, or None if no image is set.
        """
        if self._image_data is None:
            return None

        if current_time is None:
            current_time = time.time()

        with self._lock:
            if self._image_data is None:
                return None
            next_bucket = self._get_bucket(current_time) + 30
            return self.derive_auth_key(self._image_data, next_bucket)

    def clear_cache(self) -> None:
        """Clear the internal authentication key cache."""
        with self._lock:
            self._cache.clear()

    def clear_image(self) -> None:
        """Clear the stored image data and cache."""
        with self._lock:
            self._image_data = None
            self._image_timestamp = None
            self._cache.clear()


# Global validator instance
_global_validator = None


def get_validator() -> ImageAuthValidator:
    """Get the global image auth validator instance."""
    global _global_validator
    if _global_validator is None:
        _global_validator = ImageAuthValidator()
    return _global_validator


def derive_auth_key(image_data: bytes, timestamp: float) -> bytes:
    """Derive a 32-byte authentication key (convenience function).

    Args:
        image_data: The image data bytes.
        timestamp: Unix timestamp in seconds.

    Returns:
        A 32-byte authentication key.
    """
    return get_validator().derive_auth_key(image_data, timestamp)


def validate_auth_key(provided_key: bytes, current_time: Optional[float] = None) -> bool:
    """Validate an authentication key (convenience function).

    Args:
        provided_key: The 32-byte key provided by the client.
        current_time: Optional timestamp override (defaults to now).

    Returns:
        True if the key is valid, False otherwise.
    """
    return get_validator().validate_auth_key(provided_key, current_time)
