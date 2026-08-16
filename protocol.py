"""
SecureVPN Protocol Implementation

Handles the handshake protocol and packet framing.
"""

import hmac
import struct
import time
from enum import IntEnum
from typing import Dict, Tuple, Optional
from dataclasses import dataclass

from crypto_core import (
    IdentityKeys, KeyExchange, SecurityKeys, CryptoException,
    validate_timestamp, secure_random
)


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


class SecureVPNProtocol:
    """
    Implements the SecureVPN protocol.
    
    This class handles:
    - Handshake protocol (CLIENT_HELLO, SERVER_HELLO, CLIENT_AUTH)
    - Packet framing and parsing
    - Session key derivation
    - Protocol state machine
    """
    
    PROTOCOL_VERSION = 1
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
        
        Returns:
            (packet_bytes, handshake_state)
        """
        # Generate ephemeral key for this session
        kex = KeyExchange()
        timestamp = time.time()
        
        # Build packet: [type(1)] [version(1)] [timestamp(8)] [ephemeral_pub(32)] [identity_pub(32)]
        packet = struct.pack(
            '<BBd32s32s',
            PacketType.CLIENT_HELLO,
            self.PROTOCOL_VERSION,
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
    
    def process_server_hello(self, packet: bytes, state: HandshakeState) -> SecurityKeys:
        """
        Process SERVER_HELLO packet (step 2 of handshake).
        
        Args:
            packet: SERVER_HELLO packet bytes
            state: Handshake state from create_client_hello
            
        Returns:
            SecurityKeys for the session
            
        Raises:
            ProtocolError: On invalid packet or failed verification
        """
        if len(packet) < 138:  # 1+1+8+32+32+64 minimum
            raise ProtocolError("SERVER_HELLO packet too short")
        
        # Parse packet: [type(1)] [version(1)] [timestamp(8)] [ephemeral_pub(32)] [identity_pub(32)] [signature(64)]
        pkt_type, version, server_time, server_eph_pub, server_id_pub, signature = struct.unpack(
            '<BBd32s32s64s',
            packet[:138]
        )
        
        if pkt_type != PacketType.SERVER_HELLO:
            raise ProtocolError(f"Expected SERVER_HELLO, got {pkt_type}")
        
        if version != self.PROTOCOL_VERSION:
            raise ProtocolError(f"Protocol version mismatch: {version} != {self.PROTOCOL_VERSION}")
        
        # Validate timestamp
        if not validate_timestamp(server_time, self.MAX_TIMESTAMP_SKEW):
            raise ProtocolError("Server timestamp out of acceptable range")
        
        # Verify server identity matches expected
        if server_id_pub != self.peer_identity_pubkey:
            raise ProtocolError("Server identity key mismatch")
        
        # Verify signature over handshake transcript
        # Sign: client_eph_pub || server_eph_pub || client_time || server_time
        sign_msg = (
            state.ephemeral_exchange.get_public_bytes() +
            server_eph_pub +
            struct.pack('<d', state.client_timestamp) +
            struct.pack('<d', server_time)
        )
        
        if not IdentityKeys.verify_signature(server_id_pub, sign_msg, signature):
            raise ProtocolError("Server signature verification failed")
        
        # Perform ECDH key exchange
        shared_secret = state.ephemeral_exchange.derive_shared_secret(server_eph_pub)
        
        # Derive session keys (we are client)
        session_keys = state.ephemeral_exchange.derive_session_keys(shared_secret, is_client=True)
        
        # Update state
        state.peer_ephemeral_pubkey = server_eph_pub
        state.server_timestamp = server_time
        
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
        
        Args:
            packet: CLIENT_HELLO packet bytes
            
        Returns:
            (server_hello_packet, handshake_state, session_keys)
            
        Raises:
            ProtocolError: On invalid packet
        """
        if len(packet) != 74:  # 1+1+8+32+32
            raise ProtocolError("CLIENT_HELLO packet invalid length")
        
        # Parse packet
        pkt_type, version, client_time, client_eph_pub, client_id_pub = struct.unpack(
            '<BBd32s32s',
            packet
        )
        
        if pkt_type != PacketType.CLIENT_HELLO:
            raise ProtocolError(f"Expected CLIENT_HELLO, got {pkt_type}")
        
        if version != self.PROTOCOL_VERSION:
            raise ProtocolError(f"Protocol version mismatch: {version}")
        
        # Validate timestamp
        if not validate_timestamp(client_time, self.MAX_TIMESTAMP_SKEW):
            raise ProtocolError("Client timestamp out of acceptable range")
        
        # Select the authorised peer this key belongs to. With one peer
        # configured this is the same comparison it always was; with a roster it
        # is a lookup, and a key nobody holds fails here with the same message.
        peer_name, expected_pubkey = self._resolve_peer(client_id_pub)
        if expected_pubkey is None:
            raise ProtocolError("Client identity key mismatch")

        # Generate our ephemeral key
        kex = KeyExchange()
        server_time = time.time()
        
        # Perform ECDH
        shared_secret = kex.derive_shared_secret(client_eph_pub)
        
        # Derive session keys (we are server)
        session_keys = kex.derive_session_keys(shared_secret, is_client=False)
        
        # Create signature over handshake
        sign_msg = (
            client_eph_pub +
            kex.get_public_bytes() +
            struct.pack('<d', client_time) +
            struct.pack('<d', server_time)
        )
        signature = self.identity.sign(sign_msg)
        
        # Build SERVER_HELLO
        server_hello = struct.pack(
            '<BBd32s32s64s',
            PacketType.SERVER_HELLO,
            self.PROTOCOL_VERSION,
            server_time,
            kex.get_public_bytes(),
            self.identity.get_public_bytes(),
            signature
        )
        
        state = HandshakeState(
            identity=self.identity,
            # The resolved key, not the handler's — from here on this handshake
            # is bound to exactly one peer, so CLIENT_AUTH cannot be answered by
            # a different roster entry than CLIENT_HELLO claimed to be.
            peer_identity_pubkey=expected_pubkey,
            ephemeral_exchange=kex,
            peer_ephemeral_pubkey=client_eph_pub,
            client_timestamp=client_time,
            server_timestamp=server_time,
            peer_name=peer_name
        )

        return server_hello, state, session_keys
    
    def process_client_auth(self, packet: bytes, state: HandshakeState, session_keys: SecurityKeys) -> bool:
        """
        Process CLIENT_AUTH packet (server-side, final handshake step).
        
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
            
            if len(plaintext) != 97:  # 1+32+64
                raise ProtocolError("CLIENT_AUTH plaintext invalid length")
            
            # Parse plaintext
            pkt_type, client_id_pub, signature = struct.unpack('<B32s64s', plaintext)
            
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
