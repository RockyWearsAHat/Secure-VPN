"""
Tests for image-based authentication module.

Tests ImageAuthValidator, AdminAPIClient, and CachedAdminAPIClient.
"""

import unittest
import time
import hashlib
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scripts', 'securevpn', 'app'))

from vpn_image_auth import (
    ImageAuthValidator, derive_auth_key, validate_auth_key, get_validator
)
from admin_client import AdminAPIClient, CachedAdminAPIClient


class TestImageAuthValidator(unittest.TestCase):
    """Test the ImageAuthValidator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.validator = ImageAuthValidator()
        self.test_image = b'test_image_data_12345'

    def test_initialization(self):
        """Test validator initialization."""
        self.assertIsNone(self.validator.get_image_data())
        self.assertIsNone(self.validator.get_image_age())

    def test_set_and_get_image_data(self):
        """Test setting and getting image data."""
        self.validator.set_image_data(self.test_image)
        self.assertEqual(self.validator.get_image_data(), self.test_image)

    def test_image_age(self):
        """Test getting image age."""
        self.validator.set_image_data(self.test_image)
        age = self.validator.get_image_age()
        self.assertIsNotNone(age)
        self.assertLess(age, 1.0)  # Should be very recent

    def test_derive_auth_key(self):
        """Test deriving authentication keys."""
        key = self.validator.derive_auth_key(self.test_image, 1000.0)
        self.assertEqual(len(key), 32)  # SHA3-256 produces 32 bytes

        # Same input should produce same output
        key2 = self.validator.derive_auth_key(self.test_image, 1000.0)
        self.assertEqual(key, key2)

        # Different timestamp should produce different output
        key3 = self.validator.derive_auth_key(self.test_image, 1030.0)
        self.assertNotEqual(key, key3)

    def test_bucket_calculation(self):
        """Test time bucket calculation."""
        bucket1 = self.validator._get_bucket(1000.0)
        bucket2 = self.validator._get_bucket(1015.0)
        bucket3 = self.validator._get_bucket(1030.0)

        # Same bucket within 30 seconds
        self.assertEqual(bucket1, bucket2)
        # Different bucket at 30 second boundary
        self.assertEqual(bucket3, bucket1 + 30)

    def test_validate_auth_key_no_image(self):
        """Test validation fails without image data."""
        key = b'\x00' * 32
        result = self.validator.validate_auth_key(key)
        self.assertFalse(result)

    def test_validate_auth_key_current_bucket(self):
        """Test validation with current bucket."""
        self.validator.set_image_data(self.test_image)
        current_time = time.time()
        correct_key = self.validator.derive_auth_key(
            self.test_image, current_time
        )

        result = self.validator.validate_auth_key(correct_key, current_time)
        self.assertTrue(result)

    def test_validate_auth_key_previous_bucket(self):
        """Test validation with previous bucket (±30 sec tolerance)."""
        self.validator.set_image_data(self.test_image)
        current_time = time.time()
        previous_bucket = self.validator._get_bucket(current_time) - 30
        previous_key = self.validator.derive_auth_key(
            self.test_image, previous_bucket
        )

        result = self.validator.validate_auth_key(previous_key, current_time)
        self.assertTrue(result)

    def test_validate_auth_key_invalid(self):
        """Test validation with invalid key."""
        self.validator.set_image_data(self.test_image)
        invalid_key = b'\xFF' * 32
        result = self.validator.validate_auth_key(invalid_key)
        self.assertFalse(result)

    def test_validate_auth_key_wrong_length(self):
        """Test validation rejects keys of wrong length."""
        self.validator.set_image_data(self.test_image)
        wrong_length_key = b'\x00' * 31
        result = self.validator.validate_auth_key(wrong_length_key)
        self.assertFalse(result)

    def test_validate_auth_key_with_tolerance(self):
        """Test validation with custom tolerance."""
        self.validator.set_image_data(self.test_image)
        current_time = time.time()

        # Key from 3 buckets ago (90 seconds)
        old_bucket = self.validator._get_bucket(current_time) - 90
        old_key = self.validator.derive_auth_key(self.test_image, old_bucket)

        # Should fail with default tolerance
        result = self.validator.validate_auth_key(old_key, current_time)
        self.assertFalse(result)

        # Should pass with wider tolerance
        result = self.validator.validate_auth_key_with_tolerance(
            old_key, current_time, tolerance_sec=90
        )
        self.assertTrue(result)

    def test_get_current_key(self):
        """Test getting current authentication key."""
        self.validator.set_image_data(self.test_image)
        current_key = self.validator.get_current_key()
        self.assertIsNotNone(current_key)
        self.assertEqual(len(current_key), 32)

    def test_get_next_key(self):
        """Test getting next authentication key."""
        self.validator.set_image_data(self.test_image)
        current_key = self.validator.get_current_key()
        next_key = self.validator.get_next_key()

        self.assertIsNotNone(next_key)
        self.assertEqual(len(next_key), 32)
        # Should be different from current (30 seconds later)
        self.assertNotEqual(current_key, next_key)

    def test_clear_cache(self):
        """Test clearing the validation cache."""
        self.validator.set_image_data(self.test_image)
        current_time = time.time()
        key = self.validator.derive_auth_key(self.test_image, current_time)

        # Validate to populate cache
        self.validator.validate_auth_key(key, current_time)

        # Clear cache (should not raise)
        self.validator.clear_cache()

    def test_clear_image(self):
        """Test clearing the image data."""
        self.validator.set_image_data(self.test_image)
        self.assertIsNotNone(self.validator.get_image_data())

        self.validator.clear_image()
        self.assertIsNone(self.validator.get_image_data())

    def test_thread_safety(self):
        """Test basic thread safety of cache operations."""
        import threading

        self.validator.set_image_data(self.test_image)
        results = []

        def validate_keys():
            current_time = time.time()
            for _ in range(10):
                key = self.validator.derive_auth_key(self.test_image, current_time)
                result = self.validator.validate_auth_key(key, current_time)
                results.append(result)

        threads = [threading.Thread(target=validate_keys) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All validations should succeed
        self.assertTrue(all(results))

    def test_global_validator(self):
        """Test the global validator singleton."""
        validator1 = get_validator()
        validator2 = get_validator()
        self.assertIs(validator1, validator2)


class TestAdminAPIClient(unittest.TestCase):
    """Test the AdminAPIClient class."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = AdminAPIClient("http://localhost:8080")

    @patch('urllib.request.urlopen')
    def test_fetch_image_success(self, mock_urlopen):
        """Test successful image fetch."""
        import json
        import base64

        test_image = b'test_image_data'
        encoded = base64.b64encode(test_image).decode('utf-8')
        response_data = json.dumps({'image': encoded}).encode('utf-8')

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        result = self.client.fetch_image()
        self.assertEqual(result, test_image)

    @patch('urllib.request.urlopen')
    def test_fetch_image_network_error(self, mock_urlopen):
        """Test fetch with network error."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        result = self.client.fetch_image()
        self.assertIsNone(result)

    @patch('urllib.request.urlopen')
    def test_fetch_image_missing_field(self, mock_urlopen):
        """Test fetch with missing image field."""
        import json

        response_data = json.dumps({'data': 'no image here'}).encode('utf-8')
        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        result = self.client.fetch_image()
        self.assertIsNone(result)


class TestCachedAdminAPIClient(unittest.TestCase):
    """Test the CachedAdminAPIClient class."""

    def setUp(self):
        """Set up test fixtures."""
        self.cached_client = CachedAdminAPIClient("http://localhost:8080", cache_ttl=1.0)

    @patch.object(AdminAPIClient, 'fetch_image')
    def test_cache_hit(self, mock_fetch):
        """Test cache hit."""
        test_image = b'test_image_data'
        mock_fetch.return_value = test_image

        # First fetch
        result1 = self.cached_client.fetch_image()
        self.assertEqual(result1, test_image)
        self.assertEqual(mock_fetch.call_count, 1)

        # Second fetch (should hit cache)
        result2 = self.cached_client.fetch_image()
        self.assertEqual(result2, test_image)
        self.assertEqual(mock_fetch.call_count, 1)  # Not called again

    @patch.object(AdminAPIClient, 'fetch_image')
    def test_cache_miss(self, mock_fetch):
        """Test cache expiration."""
        test_image = b'test_image_data'
        mock_fetch.return_value = test_image

        # First fetch
        result1 = self.cached_client.fetch_image()
        self.assertEqual(result1, test_image)

        # Wait for cache to expire
        time.sleep(1.1)

        # Second fetch (should miss cache)
        result2 = self.cached_client.fetch_image()
        self.assertEqual(result2, test_image)
        self.assertEqual(mock_fetch.call_count, 2)

    @patch.object(AdminAPIClient, 'fetch_image')
    def test_cache_age(self, mock_fetch):
        """Test getting cache age."""
        test_image = b'test_image_data'
        mock_fetch.return_value = test_image

        self.assertIsNone(self.cached_client.get_cache_age())

        self.cached_client.fetch_image()
        age = self.cached_client.get_cache_age()
        self.assertIsNotNone(age)
        self.assertLess(age, 0.1)

    @patch.object(AdminAPIClient, 'fetch_image')
    def test_is_cache_valid(self, mock_fetch):
        """Test cache validity check."""
        test_image = b'test_image_data'
        mock_fetch.return_value = test_image

        self.assertFalse(self.cached_client.is_cache_valid())

        self.cached_client.fetch_image()
        self.assertTrue(self.cached_client.is_cache_valid())

        time.sleep(1.1)
        self.assertFalse(self.cached_client.is_cache_valid())

    @patch.object(AdminAPIClient, 'fetch_image')
    def test_clear_cache(self, mock_fetch):
        """Test clearing cache."""
        test_image = b'test_image_data'
        mock_fetch.return_value = test_image

        self.cached_client.fetch_image()
        self.assertTrue(self.cached_client.is_cache_valid())

        self.cached_client.clear_cache()
        self.assertFalse(self.cached_client.is_cache_valid())


class TestConvenientFunctions(unittest.TestCase):
    """Test module-level convenience functions."""

    def test_derive_auth_key_function(self):
        """Test the module-level derive_auth_key function."""
        test_image = b'test_image'
        key = derive_auth_key(test_image, 1000.0)
        self.assertEqual(len(key), 32)

    def test_validate_auth_key_function(self):
        """Test the module-level validate_auth_key function."""
        # This requires setting image data first via the global validator
        test_image = b'test_image'
        validator = get_validator()
        validator.set_image_data(test_image)

        current_time = time.time()
        key = derive_auth_key(test_image, current_time)
        result = validate_auth_key(key, current_time)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
