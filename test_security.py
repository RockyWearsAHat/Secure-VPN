"""
Comprehensive Security and Functionality Tests for SecureVPN

Tests cover:
- Cryptographic operations
- Protocol handshake
- Replay attack protection
- MITM protection
- Key exchange
- Data encryption/decryption
- Session key derivation
"""

import unittest
import struct
import time
from crypto_core import (
    IdentityKeys, KeyExchange, SecurityKeys, CryptoException,
    constant_time_compare, validate_timestamp, secure_random
)
from protocol import (
    SecureVPNProtocol, ProtocolError, PacketType,
    frame_packet, parse_framed_packet, HandshakeState
)


class TestCryptographicPrimitives(unittest.TestCase):
    """Test core cryptographic operations"""
    
    def test_identity_key_generation(self):
        """Test Ed25519 identity key generation"""
        identity = IdentityKeys()
        
        # Check key sizes
        pub_bytes = identity.get_public_bytes()
        priv_bytes = identity.get_private_bytes()
        
        self.assertEqual(len(pub_bytes), 32)
        self.assertEqual(len(priv_bytes), 32)
    
    def test_identity_signature_verification(self):
        """Test Ed25519 signing and verification"""
        identity = IdentityKeys()
        message = b"Test message for signing"
        
        # Sign message
        signature = identity.sign(message)
        self.assertEqual(len(signature), 64)
        
        # Verify signature
        self.assertTrue(
            IdentityKeys.verify_signature(
                identity.get_public_bytes(),
                message,
                signature
            )
        )
    
    def test_identity_signature_tamper_detection(self):
        """Test that tampering is detected"""
        identity = IdentityKeys()
        message = b"Original message"
        signature = identity.sign(message)
        
        # Tampered message should fail verification
        tampered = b"Tampered message"
        self.assertFalse(
            IdentityKeys.verify_signature(
                identity.get_public_bytes(),
                tampered,
                signature
            )
        )
        
        # Tampered signature should fail
        tampered_sig = bytearray(signature)
        tampered_sig[0] ^= 0x01
        self.assertFalse(
            IdentityKeys.verify_signature(
                identity.get_public_bytes(),
                message,
                bytes(tampered_sig)
            )
        )
    
    def test_key_exchange(self):
        """Test X25519 key exchange"""
        # Simulate Alice and Bob
        alice = KeyExchange()
        bob = KeyExchange()
        
        # Exchange public keys
        alice_pub = alice.get_public_bytes()
        bob_pub = bob.get_public_bytes()
        
        self.assertEqual(len(alice_pub), 32)
        self.assertEqual(len(bob_pub), 32)
        
        # Derive shared secrets
        alice_shared = alice.derive_shared_secret(bob_pub)
        bob_shared = bob.derive_shared_secret(alice_pub)
        
        # Shared secrets should match
        self.assertEqual(alice_shared, bob_shared)
        self.assertEqual(len(alice_shared), 32)
    
    def test_session_key_derivation(self):
        """Test HKDF session key derivation"""
        kex = KeyExchange()
        shared_secret = secure_random(32)
        
        # Derive client and server keys
        client_keys = kex.derive_session_keys(shared_secret, is_client=True)
        server_keys = kex.derive_session_keys(shared_secret, is_client=False)
        
        # Keys should be different for tx/rx
        self.assertNotEqual(
            client_keys._tx_key,
            client_keys._rx_key
        )
        
        # Client TX should match server RX and vice versa
        self.assertEqual(client_keys._tx_key, server_keys._rx_key)
        self.assertEqual(client_keys._rx_key, server_keys._tx_key)
    
    def test_encryption_decryption(self):
        """Test ChaCha20-Poly1305 encryption"""
        kex = KeyExchange()
        shared_secret = secure_random(32)
        keys = kex.derive_session_keys(shared_secret, is_client=True)
        
        plaintext = b"Secret message"
        
        # Encrypt
        ciphertext = keys.encrypt(plaintext)
        self.assertNotEqual(plaintext, ciphertext)
        self.assertGreater(len(ciphertext), len(plaintext))
        
        # Decrypt with matching keys (swap for simulation)
        peer_keys = kex.derive_session_keys(shared_secret, is_client=False)
        decrypted = peer_keys.decrypt(ciphertext)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_replay_protection(self):
        """Test that replay attacks are prevented"""
        kex = KeyExchange()
        shared_secret = secure_random(32)
        client_keys = kex.derive_session_keys(shared_secret, is_client=True)
        server_keys = kex.derive_session_keys(shared_secret, is_client=False)
        
        # Encrypt message
        plaintext = b"Message"
        ciphertext = client_keys.encrypt(plaintext)
        
        # Decrypt once (should work)
        decrypted = server_keys.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)
        
        # Try to replay same packet (should fail)
        with self.assertRaises(CryptoException) as ctx:
            server_keys.decrypt(ciphertext)
        
        self.assertIn("Replay", str(ctx.exception))
    
    def test_authentication_tag_verification(self):
        """Test that tampering is detected via authentication tag"""
        kex = KeyExchange()
        shared_secret = secure_random(32)
        client_keys = kex.derive_session_keys(shared_secret, is_client=True)
        server_keys = kex.derive_session_keys(shared_secret, is_client=False)
        
        # Encrypt message
        ciphertext = client_keys.encrypt(b"Message")
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[10] ^= 0x01  # Flip a bit
        
        # Decryption should fail
        with self.assertRaises(CryptoException) as ctx:
            server_keys.decrypt(bytes(tampered))
        
        self.assertIn("Authentication failed", str(ctx.exception))
    
    def test_constant_time_compare(self):
        """Test constant-time comparison"""
        a = b"secret123"
        b = b"secret123"
        c = b"secret124"
        
        self.assertTrue(constant_time_compare(a, b))
        self.assertFalse(constant_time_compare(a, c))
        self.assertFalse(constant_time_compare(a, b"short"))
    
    def test_timestamp_validation(self):
        """Test timestamp freshness validation"""
        # Current time should be valid
        self.assertTrue(validate_timestamp(time.time()))
        
        # Recent past should be valid
        self.assertTrue(validate_timestamp(time.time() - 100))
        
        # Recent future should be valid (clock skew)
        self.assertTrue(validate_timestamp(time.time() + 100))
        
        # Far past should be invalid
        self.assertFalse(validate_timestamp(time.time() - 400))
        
        # Far future should be invalid
        self.assertFalse(validate_timestamp(time.time() + 400))
    
    def test_secure_random(self):
        """Test secure random generation"""
        r1 = secure_random(32)
        r2 = secure_random(32)
        
        self.assertEqual(len(r1), 32)
        self.assertEqual(len(r2), 32)
        self.assertNotEqual(r1, r2)  # Should be different


class TestProtocol(unittest.TestCase):
    """Test protocol handshake and packet handling"""
    
    def setUp(self):
        """Set up test identities"""
        self.client_identity = IdentityKeys()
        self.server_identity = IdentityKeys()
        
        self.client_pubkey = self.client_identity.get_public_bytes()
        self.server_pubkey = self.server_identity.get_public_bytes()
    
    def test_full_handshake(self):
        """Test complete handshake flow"""
        # Initialize protocols
        client_proto = SecureVPNProtocol(self.client_identity, self.server_pubkey)
        server_proto = SecureVPNProtocol(self.server_identity, self.client_pubkey)
        
        # Step 1: Client creates CLIENT_HELLO
        client_hello, client_state = client_proto.create_client_hello()
        self.assertIsNotNone(client_hello)
        self.assertIsInstance(client_state, HandshakeState)
        
        # Step 2: Server processes CLIENT_HELLO and creates SERVER_HELLO
        server_hello, server_state, server_keys = server_proto.process_client_hello(client_hello)
        self.assertIsNotNone(server_hello)
        self.assertIsInstance(server_keys, SecurityKeys)
        
        # Step 3: Client processes SERVER_HELLO
        client_keys = client_proto.process_server_hello(server_hello, client_state)
        self.assertIsInstance(client_keys, SecurityKeys)
        
        # Step 4: Client creates CLIENT_AUTH
        client_auth = client_proto.create_client_auth(client_state, client_keys)
        self.assertIsNotNone(client_auth)
        
        # Step 5: Server verifies CLIENT_AUTH
        auth_result = server_proto.process_client_auth(client_auth, server_state, server_keys)
        self.assertTrue(auth_result)
        
        # Test data exchange
        test_data = b"Test payload"
        encrypted = client_proto.create_data_packet(test_data, client_keys)
        decrypted = server_proto.parse_data_packet(encrypted, server_keys)
        self.assertEqual(test_data, decrypted)
    
    def test_handshake_wrong_identity(self):
        """Test that wrong identity is rejected"""
        # Client expects different server
        wrong_identity = IdentityKeys()
        client_proto = SecureVPNProtocol(self.client_identity, wrong_identity.get_public_bytes())
        server_proto = SecureVPNProtocol(self.server_identity, self.client_pubkey)
        
        # Step 1: CLIENT_HELLO
        client_hello, client_state = client_proto.create_client_hello()
        
        # Step 2: SERVER_HELLO
        server_hello, server_state, server_keys = server_proto.process_client_hello(client_hello)
        
        # Step 3: Client should reject SERVER_HELLO (wrong identity)
        with self.assertRaises(ProtocolError) as ctx:
            client_proto.process_server_hello(server_hello, client_state)
        
        self.assertIn("identity", str(ctx.exception).lower())
    
    def test_handshake_tampered_signature(self):
        """Test that tampered signatures are detected"""
        client_proto = SecureVPNProtocol(self.client_identity, self.server_pubkey)
        server_proto = SecureVPNProtocol(self.server_identity, self.client_pubkey)
        
        # Step 1: CLIENT_HELLO
        client_hello, client_state = client_proto.create_client_hello()
        
        # Step 2: SERVER_HELLO (tamper with it)
        server_hello, server_state, server_keys = server_proto.process_client_hello(client_hello)
        
        # Tamper with signature in SERVER_HELLO
        tampered = bytearray(server_hello)
        tampered[-10] ^= 0x01
        
        # Step 3: Client should reject tampered SERVER_HELLO
        with self.assertRaises(ProtocolError) as ctx:
            client_proto.process_server_hello(bytes(tampered), client_state)
        
        self.assertIn("signature", str(ctx.exception).lower())
    
    def test_packet_framing(self):
        """Test packet framing and parsing"""
        test_packet = b"Test packet data"
        
        # Frame packet
        framed = frame_packet(test_packet)
        self.assertEqual(len(framed), 4 + len(test_packet))
        
        # Parse packet
        parsed, remaining = parse_framed_packet(framed)
        self.assertEqual(parsed, test_packet)
        self.assertEqual(remaining, b"")
    
    def test_packet_framing_multiple(self):
        """Test parsing multiple packets in buffer"""
        packet1 = b"First packet"
        packet2 = b"Second packet"
        
        # Create buffer with two packets
        buffer = frame_packet(packet1) + frame_packet(packet2)
        
        # Parse first
        p1, buffer = parse_framed_packet(buffer)
        self.assertEqual(p1, packet1)
        
        # Parse second
        p2, buffer = parse_framed_packet(buffer)
        self.assertEqual(p2, packet2)
        
        # No more packets
        self.assertEqual(buffer, b"")
    
    def test_packet_framing_incomplete(self):
        """Test handling of incomplete packets"""
        test_packet = b"Test"
        framed = frame_packet(test_packet)
        
        # Only send first few bytes
        incomplete = framed[:5]
        
        # Should return None and keep buffer
        parsed, remaining = parse_framed_packet(incomplete)
        self.assertIsNone(parsed)
        self.assertEqual(remaining, incomplete)
    
    def test_data_packet_encryption(self):
        """Test data packet creation and parsing"""
        kex = KeyExchange()
        shared = secure_random(32)
        client_keys = kex.derive_session_keys(shared, is_client=True)
        server_keys = kex.derive_session_keys(shared, is_client=False)
        
        client_proto = SecureVPNProtocol(self.client_identity, self.server_pubkey)
        server_proto = SecureVPNProtocol(self.server_identity, self.client_pubkey)
        
        # Create and parse data packet
        payload = b"Important data"
        encrypted = client_proto.create_data_packet(payload, client_keys)
        decrypted = server_proto.parse_data_packet(encrypted, server_keys)
        
        self.assertEqual(payload, decrypted)


class TestSecurityProperties(unittest.TestCase):
    """Test security properties and attack resistance"""
    
    def test_forward_secrecy(self):
        """Test that ephemeral keys provide forward secrecy"""
        # First session
        kex1 = KeyExchange()
        peer_pub1 = KeyExchange().get_public_bytes()
        shared1 = kex1.derive_shared_secret(peer_pub1)
        
        # Second session with new ephemeral keys
        kex2 = KeyExchange()
        peer_pub2 = KeyExchange().get_public_bytes()
        shared2 = kex2.derive_shared_secret(peer_pub2)
        
        # Shared secrets should be different
        self.assertNotEqual(shared1, shared2)
    
    def test_counter_exhaustion_protection(self):
        """Test that counter exhaustion is detected"""
        kex = KeyExchange()
        shared = secure_random(32)
        keys = kex.derive_session_keys(shared, is_client=True)
        
        # Set counter near limit
        keys.tx_counter = 2**64 - 100
        
        # Should raise exception before overflow
        with self.assertRaises(CryptoException) as ctx:
            keys.encrypt(b"data")
        
        self.assertIn("Counter exhaustion", str(ctx.exception))
    
    def test_rekey_conditions(self):
        """Test rekey condition detection"""
        kex = KeyExchange()
        shared = secure_random(32)
        keys = kex.derive_session_keys(shared, is_client=True)
        
        # Initially no rekey needed
        self.assertFalse(keys.should_rekey(0))
        
        # Large data transfer triggers rekey
        self.assertTrue(keys.should_rekey(2_000_000_000))
        
        # Time-based rekey
        keys.last_rekey = time.time() - 4000  # 4000 seconds ago
        self.assertTrue(keys.should_rekey(0))
    
    def test_identity_key_persistence(self):
        """Test that identity keys can be serialized and restored"""
        identity1 = IdentityKeys()
        
        # Serialize
        priv_bytes = identity1.get_private_bytes()
        pub_bytes = identity1.get_public_bytes()
        
        # Restore
        identity2 = IdentityKeys.from_private_bytes(priv_bytes)
        
        # Should be functionally equivalent
        self.assertEqual(pub_bytes, identity2.get_public_bytes())
        
        # Sign with both
        message = b"test"
        sig1 = identity1.sign(message)
        sig2 = identity2.sign(message)
        
        # Both signatures should verify with same public key
        self.assertTrue(IdentityKeys.verify_signature(pub_bytes, message, sig1))
        self.assertTrue(IdentityKeys.verify_signature(pub_bytes, message, sig2))


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def test_empty_data_encryption(self):
        """Test encryption of empty data"""
        kex = KeyExchange()
        shared = secure_random(32)
        keys = kex.derive_session_keys(shared, is_client=True)
        
        # Should handle empty payload
        encrypted = keys.encrypt(b"")
        self.assertGreater(len(encrypted), 8)  # Counter + tag
    
    def test_large_data_encryption(self):
        """Test encryption of large payloads"""
        kex = KeyExchange()
        shared = secure_random(32)
        client_keys = kex.derive_session_keys(shared, is_client=True)
        server_keys = kex.derive_session_keys(shared, is_client=False)
        
        # 64KB payload
        large_data = secure_random(65536)
        
        encrypted = client_keys.encrypt(large_data)
        decrypted = server_keys.decrypt(encrypted)
        
        self.assertEqual(large_data, decrypted)
    
    def test_invalid_packet_sizes(self):
        """Test handling of invalid packet sizes"""
        # Too short for counter + tag
        with self.assertRaises(CryptoException):
            kex = KeyExchange()
            shared = secure_random(32)
            keys = kex.derive_session_keys(shared, is_client=False)
            keys.decrypt(b"tooshort")
    
    def test_protocol_version_mismatch(self):
        """Test protocol version checking"""
        client_identity = IdentityKeys()
        server_identity = IdentityKeys()
        
        server_proto = SecureVPNProtocol(
            server_identity,
            client_identity.get_public_bytes()
        )
        
        # Create malformed CLIENT_HELLO with wrong version
        bad_hello = struct.pack(
            '<BBd32s32s',
            PacketType.CLIENT_HELLO,
            99,  # Wrong version
            time.time(),
            secure_random(32),
            client_identity.get_public_bytes()
        )
        
        with self.assertRaises(ProtocolError) as ctx:
            server_proto.process_client_hello(bad_hello)
        
        self.assertIn("version", str(ctx.exception).lower())


def run_tests():
    """Run all test suites"""
    print("="*70)
    print("SecureVPN Security Test Suite")
    print("="*70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestCryptographicPrimitives))
    suite.addTests(loader.loadTestsFromTestCase(TestProtocol))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityProperties))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print()
    print("="*70)
    print("Test Summary")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed")
        return 1


if __name__ == "__main__":
    exit(run_tests())
