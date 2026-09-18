"""
Integration tests for image authentication with protocol handshake.

Tests the integration of image auth with the SecureVPN protocol.
"""

import unittest
import struct
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import time

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scripts', 'securevpn', 'app'))

from protocol import SecureVPNProtocol, PacketType, ProtocolError, HandshakeState
from crypto_core import IdentityKeys, KeyExchange, SecurityKeys
from vpn_image_auth import ImageAuthValidator, derive_auth_key


class TestProtocolImageAuthIntegration(unittest.TestCase):
    """Test image authentication integration with protocol."""

    def setUp(self):
        """Set up test fixtures."""
        # Create identity keys for client and server
        self.server_identity = IdentityKeys()
        self.client_identity = IdentityKeys()

        # Create protocol handlers
        self.server_protocol = SecureVPNProtocol(
            identity=self.server_identity,
            peer_identity_pubkey=self.client_identity.get_public_bytes()
        )

        self.client_protocol = SecureVPNProtocol(
            identity=self.client_identity,
            peer_identity_pubkey=self.server_identity.get_public_bytes()
        )

        self.test_image = b'test_entropy_image_data_for_auth'

    def test_image_auth_initialization(self):
        """Test that image auth is initialized in protocol."""
        # Image auth should be enabled if modules are available
        if self.server_protocol.image_auth_enabled:
            self.assertIsNotNone(self.server_protocol.image_auth_validator)
            self.assertIsNotNone(self.server_protocol.image_auth_client)

    def test_legacy_client_auth_without_image_key(self):
        """Test that legacy CLIENT_AUTH (without image key) still works."""
        # Perform handshake
        client_hello, client_state = self.client_protocol.create_client_hello()
        server_hello, server_state, server_keys = self.server_protocol.process_client_hello(client_hello)

        # Client processes server hello and derives keys
        client_keys = self.client_protocol.process_server_hello(server_hello, client_state)

        # Create legacy CLIENT_AUTH (97 bytes, no image auth key)
        sign_msg = (
            server_state.peer_ephemeral_pubkey +
            server_state.ephemeral_exchange.get_public_bytes() +
            struct.pack('<d', server_state.client_timestamp) +
            struct.pack('<d', server_state.server_timestamp)
        )
        signature = self.client_identity.sign(sign_msg)

        plaintext = struct.pack(
            '<B32s64s',
            PacketType.CLIENT_AUTH,
            self.client_identity.get_public_bytes(),
            signature
        )

        client_auth = client_keys.encrypt(plaintext)

        # Server should accept legacy format
        result = self.server_protocol.process_client_auth(client_auth, server_state, server_keys)
        self.assertTrue(result)

    def test_extended_client_auth_with_image_key(self):
        """Test CLIENT_AUTH with image authentication key."""
        # Set up image auth on server
        if self.server_protocol.image_auth_enabled:
            self.server_protocol.image_auth_validator.set_image_data(self.test_image)

            # Perform handshake
            client_hello, client_state = self.client_protocol.create_client_hello()
            server_hello, server_state, server_keys = self.server_protocol.process_client_hello(client_hello)

            # Client processes server hello and derives keys
            client_keys = self.client_protocol.process_server_hello(server_hello, client_state)

            # Create CLIENT_AUTH with image auth key (129 bytes)
            sign_msg = (
                server_state.peer_ephemeral_pubkey +
                server_state.ephemeral_exchange.get_public_bytes() +
                struct.pack('<d', server_state.client_timestamp) +
                struct.pack('<d', server_state.server_timestamp)
            )
            signature = self.client_identity.sign(sign_msg)

            # Generate current auth key
            auth_key = derive_auth_key(self.test_image, time.time())

            plaintext = struct.pack(
                '<B32s64s32s',
                PacketType.CLIENT_AUTH,
                self.client_identity.get_public_bytes(),
                signature,
                auth_key
            )

            client_auth = client_keys.encrypt(plaintext)

            # Server should accept extended format with valid image key
            result = self.server_protocol.process_client_auth(client_auth, server_state, server_keys)
            self.assertTrue(result)

    def test_invalid_image_key_rejection(self):
        """Test that invalid image keys are rejected."""
        # Set up image auth on server
        if self.server_protocol.image_auth_enabled:
            self.server_protocol.image_auth_validator.set_image_data(self.test_image)

            # Perform handshake
            client_hello, client_state = self.client_protocol.create_client_hello()
            server_hello, server_state, server_keys = self.server_protocol.process_client_hello(client_hello)

            # Client processes server hello and derives keys
            client_keys = self.client_protocol.process_server_hello(server_hello, client_state)

            # Create CLIENT_AUTH with INVALID image auth key
            sign_msg = (
                server_state.peer_ephemeral_pubkey +
                server_state.ephemeral_exchange.get_public_bytes() +
                struct.pack('<d', server_state.client_timestamp) +
                struct.pack('<d', server_state.server_timestamp)
            )
            signature = self.client_identity.sign(sign_msg)

            # Use an invalid auth key
            invalid_auth_key = b'\xFF' * 32

            plaintext = struct.pack(
                '<B32s64s32s',
                PacketType.CLIENT_AUTH,
                self.client_identity.get_public_bytes(),
                signature,
                invalid_auth_key
            )

            client_auth = client_keys.encrypt(plaintext)

            # Server should reject invalid image key
            with self.assertRaises(ProtocolError) as ctx:
                self.server_protocol.process_client_auth(client_auth, server_state, server_keys)
            self.assertIn("Image authentication", str(ctx.exception))

    def test_image_auth_with_no_image_graceful_fallback(self):
        """Test graceful fallback when image auth enabled but no image available."""
        # Keep image auth enabled but don't set image data
        if self.server_protocol.image_auth_enabled:
            # Make sure no image is set
            self.server_protocol.image_auth_validator.clear_image()

            # Perform handshake
            client_hello, client_state = self.client_protocol.create_client_hello()
            server_hello, server_state, server_keys = self.server_protocol.process_client_hello(client_hello)

            # Client processes server hello and derives keys
            client_keys = self.client_protocol.process_server_hello(server_hello, client_state)

            # Create extended CLIENT_AUTH with image auth key
            sign_msg = (
                server_state.peer_ephemeral_pubkey +
                server_state.ephemeral_exchange.get_public_bytes() +
                struct.pack('<d', server_state.client_timestamp) +
                struct.pack('<d', server_state.server_timestamp)
            )
            signature = self.client_identity.sign(sign_msg)

            # Any auth key when no image is available (graceful fallback)
            auth_key = b'\x00' * 32

            plaintext = struct.pack(
                '<B32s64s32s',
                PacketType.CLIENT_AUTH,
                self.client_identity.get_public_bytes(),
                signature,
                auth_key
            )

            client_auth = client_keys.encrypt(plaintext)

            # Should allow through with warning (graceful fallback)
            result = self.server_protocol.process_client_auth(client_auth, server_state, server_keys)
            self.assertTrue(result)

    def test_refresh_image_auth(self):
        """Test refreshing image authentication from API."""
        if self.server_protocol.image_auth_enabled:
            with patch.object(
                self.server_protocol.image_auth_client, 'fetch_image',
                return_value=self.test_image
            ):
                result = self.server_protocol._refresh_image_auth()
                self.assertTrue(result)

                # Verify image was set
                self.assertEqual(
                    self.server_protocol.image_auth_validator.get_image_data(),
                    self.test_image
                )

    def test_validate_image_auth_key_no_auth(self):
        """Test validation when auth is disabled."""
        # Disable image auth
        self.server_protocol.image_auth_enabled = False

        # Any key should validate as True (pass-through)
        result = self.server_protocol._validate_image_auth_key(b'\xFF' * 32)
        self.assertTrue(result)

    def test_wrong_packet_length_rejection(self):
        """Test that packets with wrong length are rejected."""
        # Perform handshake
        client_hello, client_state = self.client_protocol.create_client_hello()
        server_hello, server_state, server_keys = self.server_protocol.process_client_hello(client_hello)

        # Client processes server hello and derives keys
        client_keys = self.client_protocol.process_server_hello(server_hello, client_state)

        # Create a packet with wrong length (not 97 or 129 bytes)
        plaintext = b'\x03' + b'x' * 100  # Wrong length

        wrong_packet = client_keys.encrypt(plaintext)

        # Should raise ProtocolError
        with self.assertRaises(ProtocolError) as ctx:
            self.server_protocol.process_client_auth(wrong_packet, server_state, server_keys)
        self.assertIn("invalid length", str(ctx.exception))


class TestImageAuthKeyFormat(unittest.TestCase):
    """Test the image auth key derivation matches specification."""

    def test_key_derivation_formula(self):
        """Test that key derivation matches the specification."""
        image_data = b'test_image'
        timestamp = 1000.0

        # Calculate bucket manually
        bucket = int((timestamp // 30) * 30)
        expected_bucket = 990  # (1000 // 30) * 30 = 33 * 30 = 990

        self.assertEqual(bucket, expected_bucket)

        # Derive key
        import hashlib
        bucket_bytes = bucket.to_bytes(8, byteorder='big')
        combined = image_data + bucket_bytes
        expected_key = hashlib.sha3_256(combined).digest()

        # Use the validator to derive
        validator = ImageAuthValidator()
        actual_key = validator.derive_auth_key(image_data, timestamp)

        self.assertEqual(actual_key, expected_key)
        self.assertEqual(len(actual_key), 32)  # SHA3-256


if __name__ == '__main__':
    unittest.main()
