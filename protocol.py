"""
SecureVPN Protocol Implementation

Handles the handshake protocol and packet framing.
Includes image-based authentication for visual entropy.
"""

import hmac
import struct
import time
import logging
from enum import IntEnum
from typing import Dict, Tuple, Optional
from dataclasses import dataclass

from crypto_core import (
    IdentityKeys, KeyExchange, SecurityKeys, CryptoException,
    validate_timestamp, secure_random
)

logger = logging.getLogger(__name__)

# Import image authentication modules (graceful fallback if not available)
try:
    from scripts.securevpn.app.vpn_image_auth import (
        ImageAuthValidator, derive_auth_key, validate_auth_key, get_validator
    )
    from scripts.securevpn.app.admin_client import (
        AdminAPIClient, CachedAdminAPIClient
    )
    _IMAGE_AUTH_AVAILABLE = True
except ImportError:
    _IMAGE_AUTH_AVAILABLE = False
    logger.debug("Image authentication modules not available - running without image auth")

# ML-KEM-768 is optional: only required to actually run a v2 (hybrid)
# handshake. It is imported lazily inside the v2 code paths so that a v1-only
# deployment (or a checkout where the mlkem768 extension hasn't been built)
# is unaffected -- importing protocol.py must not fail just because nobody
# built mlkem768 yet.
try:
    import mlkem768  # type: ignore
    _MLKEM_AVAILABLE = True
except ImportError:
    mlkem768 = None  # type: ignore
    _MLKEM_AVAILABLE = False

# ML-KEM-768 sizes (FIPS 203 / this repo's mlkem768 crate). Hardcoded here
# (rather than only read off the module) so v2 struct layouts can be defined
# even before mlkem768 is imported/available.
MLKEM_PUBLICKEY_BYTES = 1184
MLKEM_CIPHERTEXT_BYTES = 1088
MLKEM_SHARED_SECRET_BYTES = 32


class PacketType(IntEnum):
    """Protocol packet types"""
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    CLIENT_AUTH = 0x03
    DATA = 0x10
    KEEPALIVE = 0x11
    REKEY = 0x12
    CLOSE = 0xFF


class ProtocolError(Exception):
    """Protocol-level error"""
    pass


@dataclass
class HandshakeState:
    """State during handshake"""
    identity: IdentityKeys
    peer_identity_pubkey: bytes
    ephemeral_exchange: KeyExchange
    peer_ephemeral_pubkey: Optional[bytes] = None
    client_timestamp: Optional[float] = None
    server_timestamp: Optional[float] = None
    # Which roster entry this handshake resolved to, for the log line and for
    # revocation. None on the client side, where there is only ever one peer.
    peer_name: Optional[str] = None
    # Protocol v2 (hybrid X25519+ML-KEM-768) fields. All None for a v1
    # handshake -- their presence/absence is exactly what
    # SecurityKeys/derive_session_keys uses to decide whether to fold an
    # ML-KEM shared secret into the HKDF chain.
    mlkem_decaps_key: Optional[bytes] = None  # client only: dk, kept until decaps
    mlkem_shared_secret: Optional[bytes] = None


class SecureVPNProtocol:
    """
    Implements the SecureVPN protocol.
    
    This class handles:
    - Handshake protocol (CLIENT_HELLO, SERVER_HELLO, CLIENT_AUTH)
    - Packet framing and parsing
    - Session key derivation
    - Protocol state machine
    """
    
    # Bumped from 1 to 2 additively: v1's wire format and key derivation are
    # untouched and their parsing code is kept intact below (see the
    # `_v1` methods) -- v2 adds a hybrid X25519+ML-KEM-768 handshake on top.
    # A handler always speaks exactly one version (no negotiation); a peer
    # tagging a packet with any other version is rejected with ProtocolError
    # before any version-specific struct.unpack is attempted, so a version
    # mismatch can never turn into a silent misparse or a struct.error crash.
    PROTOCOL_VERSION = 2
    MAX_TIMESTAMP_SKEW = 300.0  # 5 minutes
    MAX_PACKET_SIZE = 65535
    
    def __init__(
        self,
        identity: IdentityKeys,
        peer_identity_pubkey: Optional[bytes] = None,
        peer_roster: Optional[Dict[str, bytes]] = None,
    ):
        """
        Initialize protocol handler.

        Args:
            identity: Our identity keys
            peer_identity_pubkey: The one peer we expect. This is what a client
                uses — it knows exactly which server it is dialling — and it is
                also the server's single-peer shape, kept so a deployment that
                passes one key behaves exactly as it did before rosters existed.
            peer_roster: {name: 32-byte public key} — the server's authorised
                set. When given, the peer is *selected* by the identity key the
                client presents in CLIENT_HELLO and then verified against that
                one key for the remainder of the handshake, exactly as the
                single-key path does. Selecting by presented key is not a
                weakening: the key is public, and possession of the matching
                private key is still proven by the Ed25519 signature over the
                transcript in CLIENT_AUTH. A key that is not in the roster is
                refused with the same error an unknown key always got.

        Raises:
            ValueError: If neither a peer nor a roster is given, which would be
                a server that authorises everybody.
        """
        if peer_identity_pubkey is None and not peer_roster:
            raise ValueError(
                "a protocol handler needs either peer_identity_pubkey or a "
                "non-empty peer_roster; refusing to run with no authorised peer"
            )
        self.identity = identity
        self.peer_identity_pubkey = peer_identity_pubkey
        self.peer_roster = dict(peer_roster) if peer_roster else None
        self.session_keys: Optional[SecurityKeys] = None
        self.handshake_complete = False

        # Image authentication setup (graceful fallback if unavailable)
        self.image_auth_enabled = False
        self.image_auth_validator = None
        self.image_auth_client = None

        if _IMAGE_AUTH_AVAILABLE:
            try:
                self.image_auth_validator = get_validator()
                # Initialize cached API client for fetching images (default endpoint)
                self.image_auth_client = CachedAdminAPIClient(
                    base_url="http://localhost:8080"
                )
                self.image_auth_enabled = True
                logger.debug("Image authentication enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize image auth: {e}")
                self.image_auth_enabled = False

    def _refresh_image_auth(self) -> bool:
        """
        Refresh the image data from the admin API.

        Returns:
            True if image was successfully fetched and set, False otherwise.
        """
        if not self.image_auth_enabled or self.image_auth_client is None:
            return False

        try:
            image_data = self.image_auth_client.fetch_image()
            if image_data is not None and self.image_auth_validator is not None:
                self.image_auth_validator.set_image_data(image_data)
                logger.debug(f"Image auth refreshed: {len(image_data)} bytes")
                return True
        except Exception as e:
            logger.warning(f"Failed to refresh image auth: {e}")

        return False

    def _validate_image_auth_key(self, auth_key: bytes) -> bool:
        """
        Validate an image authentication key.

        Args:
            auth_key: The 32-byte authentication key from the client.

        Returns:
            True if the key is valid or image auth is not enabled, False otherwise.
        """
        if not self.image_auth_enabled or self.image_auth_validator is None:
            return True  # Allow if auth is not configured

        # If we don't have an image yet, try to fetch one
        if self.image_auth_validator.get_image_data() is None:
            self._refresh_image_auth()

        # If still no image, allow through with warning (graceful fallback)
        if self.image_auth_validator.get_image_data() is None:
            logger.warning("Image auth enabled but no image available - allowing peer through")
            return True

        # Validate the key
        return self.image_auth_validator.validate_auth_key(auth_key)

    def _resolve_peer(self, presented_pubkey: bytes) -> Tuple[Optional[str], Optional[bytes]]:
        """
        Find the authorised peer whose identity key the client presented.

        Every candidate is compared with `hmac.compare_digest` and the loop is
        not short-circuited, so the time this takes does not depend on which
        entry matched or on how far down the roster it sits.

        Returns:
            (name, key) for a match, (None, None) for a key nobody holds.
        """
        matched_name: Optional[str] = None
        matched_key: Optional[bytes] = None

        if self.peer_roster is not None:
            for name, key in self.peer_roster.items():
                if hmac.compare_digest(presented_pubkey, key):
                    matched_name, matched_key = name, key
        elif self.peer_identity_pubkey is not None:
            if hmac.compare_digest(presented_pubkey, self.peer_identity_pubkey):
                matched_key = self.peer_identity_pubkey

        return matched_name, matched_key
    
    # ========== Client-side handshake ==========
    
    def create_client_hello(self) -> Tuple[bytes, HandshakeState]:
        """
        Create CLIENT_HELLO packet (step 1 of handshake).

        v2 (default, hybrid): also generates an ML-KEM-768 keypair and
        includes the 1184-byte encapsulation key in the packet; the matching
        decapsulation key is kept in the returned HandshakeState until
        process_server_hello() decapsulates the server's response.

        Returns:
            (packet_bytes, handshake_state)
        """
        if self.PROTOCOL_VERSION == 1:
            return self._create_client_hello_v1()
        elif self.PROTOCOL_VERSION == 2:
            return self._create_client_hello_v2()
        raise ProtocolError(f"Unsupported protocol version: {self.PROTOCOL_VERSION}")

    def _create_client_hello_v1(self) -> Tuple[bytes, HandshakeState]:
        """Legacy v1 CLIENT_HELLO -- X25519-only, kept intact unchanged."""
        kex = KeyExchange()
        timestamp = time.time()

        # [type(1)] [version(1)] [timestamp(8)] [ephemeral_pub(32)] [identity_pub(32)]
        packet = struct.pack(
            '<BBd32s32s',
            PacketType.CLIENT_HELLO,
            1,
            timestamp,
            kex.get_public_bytes(),
            self.identity.get_public_bytes()
        )

        state = HandshakeState(
            identity=self.identity,
            peer_identity_pubkey=self.peer_identity_pubkey,
            ephemeral_exchange=kex,
            client_timestamp=timestamp
        )

        return packet, state

    def _create_client_hello_v2(self) -> Tuple[bytes, HandshakeState]:
        """v2 CLIENT_HELLO -- adds the ML-KEM-768 encapsulation key."""
        if not _MLKEM_AVAILABLE:
            raise ProtocolError(
                "protocol v2 requires the mlkem768 extension module, which is not importable "
                "(build it with maturin, see mlkem768/README/pyproject.toml)"
            )
        kex = KeyExchange()
        timestamp = time.time()
        mlkem_ek, mlkem_dk = mlkem768.keygen()
        if len(mlkem_ek) != MLKEM_PUBLICKEY_BYTES:
            raise ProtocolError(f"ML-KEM ek has unexpected length {len(mlkem_ek)}")

        # [type(1)] [version(1)] [timestamp(8)] [ephemeral_pub(32)] [identity_pub(32)] [mlkem_ek(1184)]
        packet = struct.pack(
            '<BBd32s32s1184s',
            PacketType.CLIENT_HELLO,
            2,
            timestamp,
            kex.get_public_bytes(),
            self.identity.get_public_bytes(),
            mlkem_ek
        )

        state = HandshakeState(
            identity=self.identity,
            peer_identity_pubkey=self.peer_identity_pubkey,
            ephemeral_exchange=kex,
            client_timestamp=timestamp,
            mlkem_decaps_key=mlkem_dk
        )

        return packet, state

    def process_server_hello(self, packet: bytes, state: HandshakeState) -> SecurityKeys:
        """
        Process SERVER_HELLO packet (step 2 of handshake).

        The wire version is read from the packet's own version byte (peeking
        only [type,version] before choosing a struct format) so a
        wrong-version packet is rejected with ProtocolError instead of being
        unpacked with the wrong struct layout (which would either raise a
        raw struct.error or, worse, silently parse garbage).

        Args:
            packet: SERVER_HELLO packet bytes
            state: Handshake state from create_client_hello

        Returns:
            SecurityKeys for the session

        Raises:
            ProtocolError: On invalid packet, version mismatch, or failed verification
        """
        if len(packet) < 2:
            raise ProtocolError("SERVER_HELLO packet too short to contain a version")
        _peek_type, version = struct.unpack('<BB', packet[:2])

        if version != self.PROTOCOL_VERSION:
            raise ProtocolError(f"Protocol version mismatch: {version} != {self.PROTOCOL_VERSION}")

        if version == 1:
            return self._process_server_hello_v1(packet, state)
        elif version == 2:
            return self._process_server_hello_v2(packet, state)
        raise ProtocolError(f"Unsupported protocol version: {version}")

    def _process_server_hello_v1(self, packet: bytes, state: HandshakeState) -> SecurityKeys:
        """Legacy v1 SERVER_HELLO parsing -- X25519-only, kept intact unchanged."""
        if len(packet) < 138:  # 1+1+8+32+32+64 minimum
            raise ProtocolError("SERVER_HELLO packet too short")

        pkt_type, version, server_time, server_eph_pub, server_id_pub, signature = struct.unpack(
            '<BBd32s32s64s',
            packet[:138]
        )

        if pkt_type != PacketType.SERVER_HELLO:
            raise ProtocolError(f"Expected SERVER_HELLO, got {pkt_type}")

        if not validate_timestamp(server_time, self.MAX_TIMESTAMP_SKEW):
            raise ProtocolError("Server timestamp out of acceptable range")

        if server_id_pub != self.peer_identity_pubkey:
            raise ProtocolError("Server identity key mismatch")

        sign_msg = (
            state.ephemeral_exchange.get_public_bytes() +
            server_eph_pub +
            struct.pack('<d', state.client_timestamp) +
            struct.pack('<d', server_time)
        )

        if not IdentityKeys.verify_signature(server_id_pub, sign_msg, signature):
            raise ProtocolError("Server signature verification failed")

        shared_secret = state.ephemeral_exchange.derive_shared_secret(server_eph_pub)
        session_keys = state.ephemeral_exchange.derive_session_keys(shared_secret, is_client=True)

        state.peer_ephemeral_pubkey = server_eph_pub
        state.server_timestamp = server_time

        return session_keys

    def _process_server_hello_v2(self, packet: bytes, state: HandshakeState) -> SecurityKeys:
        """v2 SERVER_HELLO parsing -- adds the ML-KEM-768 ciphertext, whose
        bytes are bound into the signed transcript alongside the ephemeral
        X25519 keys and timestamps."""
        if not _MLKEM_AVAILABLE:
            raise ProtocolError(
                "protocol v2 requires the mlkem768 extension module, which is not importable"
            )
        expected_len = 1 + 1 + 8 + 32 + 32 + MLKEM_CIPHERTEXT_BYTES + 64  # 1226
        if len(packet) < expected_len:
            raise ProtocolError("SERVER_HELLO (v2) packet too short")

        pkt_type, version, server_time, server_eph_pub, server_id_pub, mlkem_ct, signature = struct.unpack(
            f'<BBd32s32s{MLKEM_CIPHERTEXT_BYTES}s64s',
            packet[:expected_len]
        )

        if pkt_type != PacketType.SERVER_HELLO:
            raise ProtocolError(f"Expected SERVER_HELLO, got {pkt_type}")

        if not validate_timestamp(server_time, self.MAX_TIMESTAMP_SKEW):
            raise ProtocolError("Server timestamp out of acceptable range")

        if server_id_pub != self.peer_identity_pubkey:
            raise ProtocolError("Server identity key mismatch")

        # Sign: client_eph_pub || server_eph_pub || client_time || server_time || mlkem_ct
        sign_msg = (
            state.ephemeral_exchange.get_public_bytes() +
            server_eph_pub +
            struct.pack('<d', state.client_timestamp) +
            struct.pack('<d', server_time) +
            mlkem_ct
        )

        if not IdentityKeys.verify_signature(server_id_pub, sign_msg, signature):
            raise ProtocolError("Server signature verification failed")

        if state.mlkem_decaps_key is None:
            raise ProtocolError("Handshake state missing ML-KEM decapsulation key")

        shared_secret = state.ephemeral_exchange.derive_shared_secret(server_eph_pub)
        mlkem_shared_secret = mlkem768.decaps(state.mlkem_decaps_key, mlkem_ct)

        session_keys = state.ephemeral_exchange.derive_session_keys(
            shared_secret, is_client=True, mlkem_shared_secret=mlkem_shared_secret
        )

        state.peer_ephemeral_pubkey = server_eph_pub
        state.server_timestamp = server_time
        state.mlkem_shared_secret = mlkem_shared_secret

        return session_keys
    
    def create_client_auth(self, state: HandshakeState, session_keys: SecurityKeys) -> bytes:
        """
        Create CLIENT_AUTH packet (step 3 of handshake).
        
        Args:
            state: Handshake state
            session_keys: Session keys from process_server_hello
            
        Returns:
            CLIENT_AUTH packet bytes
        """
        # Type guard: ensure peer_ephemeral_pubkey is set
        assert state.peer_ephemeral_pubkey is not None, "Handshake state incomplete"
        assert state.client_timestamp is not None, "Client timestamp not set"
        assert state.server_timestamp is not None, "Server timestamp not set"
        
        # Create signature over handshake transcript
        sign_msg = (
            state.ephemeral_exchange.get_public_bytes() +
            state.peer_ephemeral_pubkey +
            struct.pack('<d', state.client_timestamp) +
            struct.pack('<d', state.server_timestamp)
        )
        signature = self.identity.sign(sign_msg)
        
        # Build plaintext: [type(1)] [identity_pub(32)] [signature(64)]
        plaintext = struct.pack('<B32s64s', PacketType.CLIENT_AUTH, self.identity.get_public_bytes(), signature)
        
        # Encrypt with session keys
        encrypted = session_keys.encrypt(plaintext)
        
        return encrypted
    
    # ========== Server-side handshake ==========
    
    def process_client_hello(self, packet: bytes) -> Tuple[bytes, HandshakeState, SecurityKeys]:
        """
        Process CLIENT_HELLO and create SERVER_HELLO response (server-side).

        Dispatches on the packet's own version byte (peeked before any
        version-specific struct.unpack) so a version this handler does not
        speak is rejected with ProtocolError rather than misparsed.

        Args:
            packet: CLIENT_HELLO packet bytes

        Returns:
            (server_hello_packet, handshake_state, session_keys)

        Raises:
            ProtocolError: On invalid packet or version mismatch
        """
        if len(packet) < 2:
            raise ProtocolError("CLIENT_HELLO packet too short to contain a version")
        _peek_type, version = struct.unpack('<BB', packet[:2])

        if version != self.PROTOCOL_VERSION:
            raise ProtocolError(f"Protocol version mismatch: {version} != {self.PROTOCOL_VERSION}")

        if version == 1:
            return self._process_client_hello_v1(packet)
        elif version == 2:
            return self._process_client_hello_v2(packet)
        raise ProtocolError(f"Unsupported protocol version: {version}")

    def _process_client_hello_v1(self, packet: bytes) -> Tuple[bytes, HandshakeState, SecurityKeys]:
        """Legacy v1 CLIENT_HELLO handling -- X25519-only, kept intact unchanged."""
        if len(packet) != 74:  # 1+1+8+32+32
            raise ProtocolError("CLIENT_HELLO packet invalid length")

        pkt_type, version, client_time, client_eph_pub, client_id_pub = struct.unpack(
            '<BBd32s32s',
            packet
        )

        if pkt_type != PacketType.CLIENT_HELLO:
            raise ProtocolError(f"Expected CLIENT_HELLO, got {pkt_type}")

        if not validate_timestamp(client_time, self.MAX_TIMESTAMP_SKEW):
            raise ProtocolError("Client timestamp out of acceptable range")

        peer_name, expected_pubkey = self._resolve_peer(client_id_pub)
        if expected_pubkey is None:
            raise ProtocolError("Client identity key mismatch")

        kex = KeyExchange()
        server_time = time.time()

        shared_secret = kex.derive_shared_secret(client_eph_pub)
        session_keys = kex.derive_session_keys(shared_secret, is_client=False)

        sign_msg = (
            client_eph_pub +
            kex.get_public_bytes() +
            struct.pack('<d', client_time) +
            struct.pack('<d', server_time)
        )
        signature = self.identity.sign(sign_msg)

        server_hello = struct.pack(
            '<BBd32s32s64s',
            PacketType.SERVER_HELLO,
            1,
            server_time,
            kex.get_public_bytes(),
            self.identity.get_public_bytes(),
            signature
        )

        state = HandshakeState(
            identity=self.identity,
            peer_identity_pubkey=expected_pubkey,
            ephemeral_exchange=kex,
            peer_ephemeral_pubkey=client_eph_pub,
            client_timestamp=client_time,
            server_timestamp=server_time,
            peer_name=peer_name
        )

        return server_hello, state, session_keys

    def _process_client_hello_v2(self, packet: bytes) -> Tuple[bytes, HandshakeState, SecurityKeys]:
        """v2 CLIENT_HELLO handling -- adds ML-KEM-768 encapsulation against
        the client's ek, binding the resulting ciphertext into the server's
        signed transcript."""
        if not _MLKEM_AVAILABLE:
            raise ProtocolError(
                "protocol v2 requires the mlkem768 extension module, which is not importable"
            )
        expected_len = 1 + 1 + 8 + 32 + 32 + MLKEM_PUBLICKEY_BYTES  # 1258
        if len(packet) != expected_len:
            raise ProtocolError("CLIENT_HELLO (v2) packet invalid length")

        pkt_type, version, client_time, client_eph_pub, client_id_pub, mlkem_ek = struct.unpack(
            f'<BBd32s32s{MLKEM_PUBLICKEY_BYTES}s',
            packet
        )

        if pkt_type != PacketType.CLIENT_HELLO:
            raise ProtocolError(f"Expected CLIENT_HELLO, got {pkt_type}")

        if not validate_timestamp(client_time, self.MAX_TIMESTAMP_SKEW):
            raise ProtocolError("Client timestamp out of acceptable range")

        peer_name, expected_pubkey = self._resolve_peer(client_id_pub)
        if expected_pubkey is None:
            raise ProtocolError("Client identity key mismatch")

        kex = KeyExchange()
        server_time = time.time()

        shared_secret = kex.derive_shared_secret(client_eph_pub)
        mlkem_ct, mlkem_shared_secret = mlkem768.encaps(mlkem_ek)

        session_keys = kex.derive_session_keys(
            shared_secret, is_client=False, mlkem_shared_secret=mlkem_shared_secret
        )

        # Sign: client_eph_pub || server_eph_pub || client_time || server_time || mlkem_ct
        sign_msg = (
            client_eph_pub +
            kex.get_public_bytes() +
            struct.pack('<d', client_time) +
            struct.pack('<d', server_time) +
            mlkem_ct
        )
        signature = self.identity.sign(sign_msg)

        server_hello = struct.pack(
            f'<BBd32s32s{MLKEM_CIPHERTEXT_BYTES}s64s',
            PacketType.SERVER_HELLO,
            2,
            server_time,
            kex.get_public_bytes(),
            self.identity.get_public_bytes(),
            mlkem_ct,
            signature
        )

        state = HandshakeState(
            identity=self.identity,
            peer_identity_pubkey=expected_pubkey,
            ephemeral_exchange=kex,
            peer_ephemeral_pubkey=client_eph_pub,
            client_timestamp=client_time,
            server_timestamp=server_time,
            peer_name=peer_name,
            mlkem_shared_secret=mlkem_shared_secret
        )

        return server_hello, state, session_keys
    
    def process_client_auth(self, packet: bytes, state: HandshakeState, session_keys: SecurityKeys) -> bool:
        """
        Process CLIENT_AUTH packet (server-side, final handshake step).

        Supports both legacy 97-byte format (1+32+64) and extended 129-byte format
        (1+32+64+32 with image auth key). Image authentication is validated if present.

        Args:
            packet: Encrypted CLIENT_AUTH packet
            state: Handshake state
            session_keys: Session keys

        Returns:
            True if authentication successful

        Raises:
            ProtocolError: On verification failure
        """
        try:
            # Decrypt packet
            plaintext = session_keys.decrypt(packet)

            # Support both old (97 bytes) and new (129 bytes with auth_key) formats
            auth_key = None
            if len(plaintext) == 97:  # 1+32+64
                pkt_type, client_id_pub, signature = struct.unpack('<B32s64s', plaintext)
                logger.debug("CLIENT_AUTH: using legacy format (no image auth)")
            elif len(plaintext) == 129:  # 1+32+64+32
                pkt_type, client_id_pub, signature, auth_key = struct.unpack(
                    '<B32s64s32s', plaintext
                )
                logger.debug("CLIENT_AUTH: using extended format (with image auth)")
            else:
                raise ProtocolError(f"CLIENT_AUTH plaintext invalid length: {len(plaintext)}")

            if pkt_type != PacketType.CLIENT_AUTH:
                raise ProtocolError(f"Expected CLIENT_AUTH, got {pkt_type}")

            # Verify client identity against the key THIS handshake resolved to
            # in CLIENT_HELLO, never against the handler's roster: presenting one
            # roster key in the hello and another in the auth must not pass.
            if not hmac.compare_digest(client_id_pub, state.peer_identity_pubkey):
                raise ProtocolError("Client identity mismatch in AUTH")

            # Type guard: ensure state is complete
            assert state.peer_ephemeral_pubkey is not None, "Peer ephemeral key not set"
            assert state.client_timestamp is not None, "Client timestamp not set"
            assert state.server_timestamp is not None, "Server timestamp not set"

            # Verify signature
            sign_msg = (
                state.peer_ephemeral_pubkey +
                state.ephemeral_exchange.get_public_bytes() +
                struct.pack('<d', state.client_timestamp) +
                struct.pack('<d', state.server_timestamp)
            )

            if not IdentityKeys.verify_signature(client_id_pub, sign_msg, signature):
                raise ProtocolError("Client signature verification failed")

            # Validate image authentication if provided
            if auth_key is not None:
                if not self._validate_image_auth_key(auth_key):
                    raise ProtocolError("Image authentication key validation failed")
                logger.debug(f"Image auth validated for peer {state.peer_name or 'unknown'}")

            return True

        except CryptoException as e:
            raise ProtocolError(f"Decryption failed: {e}")
    
    # ========== Data transport ==========
    
    def create_data_packet(self, data: bytes, session_keys: SecurityKeys) -> bytes:
        """
        Create encrypted DATA packet.
        
        Args:
            data: Payload to encrypt
            session_keys: Active session keys
            
        Returns:
            Encrypted packet
        """
        if len(data) > self.MAX_PACKET_SIZE - 100:  # Leave room for overhead
            raise ProtocolError(f"Data too large: {len(data)} bytes")
        
        # Prepend packet type
        plaintext = struct.pack('<B', PacketType.DATA) + data
        
        # Encrypt
        return session_keys.encrypt(plaintext)
    
    def parse_data_packet(self, packet: bytes, session_keys: SecurityKeys) -> bytes:
        """
        Parse and decrypt DATA packet.
        
        Args:
            packet: Encrypted packet
            session_keys: Active session keys
            
        Returns:
            Decrypted payload
            
        Raises:
            ProtocolError: On decryption or parse failure
        """
        try:
            plaintext = session_keys.decrypt(packet)
            
            if len(plaintext) < 1:
                raise ProtocolError("DATA packet empty")
            
            pkt_type = struct.unpack('<B', plaintext[:1])[0]
            
            if pkt_type != PacketType.DATA:
                raise ProtocolError(f"Expected DATA packet, got {pkt_type}")
            
            return plaintext[1:]
            
        except CryptoException as e:
            raise ProtocolError(f"Decryption failed: {e}")
    
    def create_keepalive(self, session_keys: SecurityKeys) -> bytes:
        """Create KEEPALIVE packet"""
        plaintext = struct.pack('<B', PacketType.KEEPALIVE)
        return session_keys.encrypt(plaintext)
    
    def create_close(self, session_keys: SecurityKeys) -> bytes:
        """Create CLOSE packet"""
        plaintext = struct.pack('<B', PacketType.CLOSE)
        return session_keys.encrypt(plaintext)


def frame_packet(packet: bytes) -> bytes:
    """
    Frame a packet with length prefix for stream transport.
    
    Args:
        packet: Raw packet bytes
        
    Returns:
        [length(4)] + packet
    """
    return struct.pack('<I', len(packet)) + packet


def parse_framed_packet(data: bytes) -> Tuple[Optional[bytes], bytes]:
    """
    Parse a length-prefixed packet from stream.
    
    Args:
        data: Buffer containing potential packet(s)
        
    Returns:
        (packet, remaining_data) or (None, data) if incomplete
    """
    if len(data) < 4:
        return None, data
    
    packet_len = struct.unpack('<I', data[:4])[0]
    
    if packet_len > SecureVPNProtocol.MAX_PACKET_SIZE:
        raise ProtocolError(f"Packet too large: {packet_len}")
    
    if len(data) < 4 + packet_len:
        return None, data  # Incomplete packet
    
    packet = data[4:4+packet_len]
    remaining = data[4+packet_len:]
    
    return packet, remaining
