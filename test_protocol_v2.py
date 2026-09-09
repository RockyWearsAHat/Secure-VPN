"""
Tests for the protocol v2 (hybrid X25519 + ML-KEM-768) handshake.

Covers exactly the two properties the v2 rollout must guarantee:
  (a) a v2 client <-> v2 server handshake completes and both sides derive
      matching session keys, with a real ML-KEM shared secret folded in.
  (b) a v1-tagged packet handed to this (v2) code raises ProtocolError
      cleanly -- no hang, no silent misparse, no raw struct.error escaping.
"""

import struct
import unittest

from crypto_core import IdentityKeys, SecurityKeys
from protocol import (
    SecureVPNProtocol, ProtocolError, PacketType, HandshakeState,
    MLKEM_CIPHERTEXT_BYTES, MLKEM_PUBLICKEY_BYTES,
)

try:
    import mlkem768
    MLKEM_AVAILABLE = True
except ImportError:
    MLKEM_AVAILABLE = False


@unittest.skipUnless(MLKEM_AVAILABLE, "mlkem768 extension module not built/importable")
class TestProtocolV2Handshake(unittest.TestCase):
    def setUp(self):
        self.client_identity = IdentityKeys()
        self.server_identity = IdentityKeys()
        self.client_pubkey = self.client_identity.get_public_bytes()
        self.server_pubkey = self.server_identity.get_public_bytes()

    def test_v2_handshake_matching_session_keys(self):
        """(a) v2 client <-> v2 server: matching derived session keys on both sides."""
        client_proto = SecureVPNProtocol(self.client_identity, self.server_pubkey)
        server_proto = SecureVPNProtocol(self.server_identity, self.client_pubkey)
        self.assertEqual(client_proto.PROTOCOL_VERSION, 2)
        self.assertEqual(server_proto.PROTOCOL_VERSION, 2)

        client_hello, client_state = client_proto.create_client_hello()
        # Confirm this really is the v2 wire shape (carries the 1184-byte ek).
        _t, version = struct.unpack('<BB', client_hello[:2])
        self.assertEqual(version, 2)
        self.assertEqual(len(client_hello), 1 + 1 + 8 + 32 + 32 + MLKEM_PUBLICKEY_BYTES)
        self.assertIsNotNone(client_state.mlkem_decaps_key)

        server_hello, server_state, server_keys = server_proto.process_client_hello(client_hello)
        _t2, version2 = struct.unpack('<BB', server_hello[:2])
        self.assertEqual(version2, 2)
        self.assertEqual(len(server_hello), 1 + 1 + 8 + 32 + 32 + MLKEM_CIPHERTEXT_BYTES + 64)
        self.assertIsNotNone(server_state.mlkem_shared_secret)
        self.assertEqual(len(server_state.mlkem_shared_secret), 32)

        client_keys = client_proto.process_server_hello(server_hello, client_state)
        self.assertIsInstance(client_keys, SecurityKeys)
        self.assertIsNotNone(client_state.mlkem_shared_secret)

        # The two sides must have derived the SAME ML-KEM shared secret via
        # encaps/decaps, and it must be real key material (not all-zero).
        self.assertEqual(client_state.mlkem_shared_secret, server_state.mlkem_shared_secret)
        self.assertNotEqual(client_state.mlkem_shared_secret, b"\x00" * 32)

        # Finish the handshake and confirm the derived *session* keys work
        # symmetrically end to end (which they can only do if both sides fed
        # the identical hybrid secret into HKDF).
        client_auth = client_proto.create_client_auth(client_state, client_keys)
        auth_ok = server_proto.process_client_auth(client_auth, server_state, server_keys)
        self.assertTrue(auth_ok)

        payload = b"hybrid handshake data"
        encrypted = client_proto.create_data_packet(payload, client_keys)
        decrypted = server_proto.parse_data_packet(encrypted, server_keys)
        self.assertEqual(payload, decrypted)

        # And the reverse direction too, proving tx/rx are correctly crossed.
        reply = b"server reply over hybrid session"
        encrypted_reply = server_proto.create_data_packet(reply, server_keys)
        decrypted_reply = client_proto.parse_data_packet(encrypted_reply, client_keys)
        self.assertEqual(reply, decrypted_reply)

    def test_v1_tagged_client_hello_rejected_cleanly(self):
        """(b) A v1-tagged CLIENT_HELLO handed to v2-aware server code raises
        ProtocolError -- not a hang, not a struct.error, not a silent misparse
        of the (differently-shaped) v1 packet as if it were v2."""
        server_proto = SecureVPNProtocol(self.server_identity, self.client_pubkey)
        self.assertEqual(server_proto.PROTOCOL_VERSION, 2)

        # Build a legitimate-shaped v1 CLIENT_HELLO (74 bytes, no ML-KEM key).
        client_identity = self.client_identity
        v1_packet = struct.pack(
            '<BBd32s32s',
            PacketType.CLIENT_HELLO,
            1,
            0.0,
            b"\x00" * 32,
            client_identity.get_public_bytes(),
        )

        with self.assertRaises(ProtocolError) as ctx:
            server_proto.process_client_hello(v1_packet)
        self.assertIn("version", str(ctx.exception).lower())

    def test_v1_tagged_server_hello_rejected_cleanly(self):
        """Same guarantee on the client side's process_server_hello."""
        client_proto = SecureVPNProtocol(self.client_identity, self.server_pubkey)
        _client_hello, client_state = client_proto.create_client_hello()

        # A v1-shaped SERVER_HELLO (138 bytes) fed to v2-aware client code.
        v1_server_hello = struct.pack(
            '<BBd32s32s64s',
            PacketType.SERVER_HELLO,
            1,
            0.0,
            b"\x00" * 32,
            self.server_pubkey,
            b"\x00" * 64,
        )

        with self.assertRaises(ProtocolError) as ctx:
            client_proto.process_server_hello(v1_server_hello, client_state)
        self.assertIn("version", str(ctx.exception).lower())

    def test_truncated_v2_hello_does_not_crash_with_raw_struct_error(self):
        """A short/garbage packet must not escape as struct.error -- only
        ProtocolError should ever propagate out of these entry points."""
        server_proto = SecureVPNProtocol(self.server_identity, self.client_pubkey)
        with self.assertRaises(ProtocolError):
            server_proto.process_client_hello(b"\x01")  # 1 byte: no version at all

        client_proto = SecureVPNProtocol(self.client_identity, self.server_pubkey)
        _client_hello, client_state = client_proto.create_client_hello()
        with self.assertRaises(ProtocolError):
            client_proto.process_server_hello(b"", client_state)


if __name__ == "__main__":
    unittest.main()
