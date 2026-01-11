# SecureVPN Protocol Specification

## Overview

A custom VPN protocol implementing state-of-the-art cryptographic practices for secure SSH tunneling.

## Security Guarantees

- **Confidentiality**: ChaCha20-Poly1305 authenticated encryption
- **Authentication**: Mutual authentication using Ed25519 signatures
- **Key Exchange**: X25519 Elliptic Curve Diffie-Hellman
- **Perfect Forward Secrecy**: Ephemeral keys for each session
- **Replay Protection**: Nonce-based with timestamp validation
- **Integrity**: AEAD guarantees message authentication
- **Post-Quantum Consideration**: Designed for future hybrid key exchange

## Cryptographic Primitives

- **Encryption**: ChaCha20-Poly1305 (AEAD)
- **Key Exchange**: X25519 (ECDH on Curve25519)
- **Signatures**: Ed25519
- **Hashing**: BLAKE2b
- **KDF**: HKDF with SHA-256

## Protocol Flow

### 1. Initialization Phase

Both parties possess:

- Long-term Ed25519 identity keypair
- Known peer's public identity key

### 2. Handshake Protocol

```
Client                                    Server
------                                    ------
Generate ephemeral X25519 keypair (Ce)
                                          Generate ephemeral X25519 keypair (Se)

CLIENT_HELLO
- Protocol version
- Client ephemeral public key (Ce_pub)
- Timestamp
- Client identity public key (Ci_pub)
--------------------------------->

                                          Verify timestamp freshness
                                          Perform ECDH: shared_secret = Se_priv * Ce_pub
                                          Derive keys using HKDF

                                          SERVER_HELLO
                                          - Server ephemeral public key (Se_pub)
                                          - Timestamp
                                          - Server identity public key (Si_pub)
                                          - Signature over (Ce_pub || Se_pub || timestamps)
<---------------------------------

Verify server signature
Perform ECDH: shared_secret = Ce_priv * Se_pub
Verify shared_secret matches
Derive keys using HKDF

CLIENT_AUTH
- Signature over (Ce_pub || Se_pub || timestamps)
- Encrypted with derived key
--------------------------------->

                                          Verify client signature
                                          Session established

```

### 3. Key Derivation

After ECDH, derive multiple keys using HKDF:

```
shared_secret = ECDH(ephemeral_priv, ephemeral_pub_peer)
master_key = HKDF-Extract(salt=NULL, ikm=shared_secret)

tx_key = HKDF-Expand(master_key, info="tx", length=32)
rx_key = HKDF-Expand(master_key, info="rx", length=32)
```

Client uses `tx_key` for sending, `rx_key` for receiving (opposite for server).

### 4. Data Transport

Each packet:

```
[8 bytes: counter (nonce)] [encrypted payload + 16 byte auth tag]
```

- Counter increments for each packet (prevents replay)
- Counter used as nonce for ChaCha20-Poly1305
- Maximum counter: 2^64-1, trigger rekey before overflow
- Payload authenticated and encrypted

### 5. Session Management

- **Rekey interval**: Every 1 hour or 1 GB of data
- **Timeout**: 5 minutes of inactivity
- **Keepalive**: Every 30 seconds

### 6. Packet Types

- `CLIENT_HELLO (0x01)`: Initial handshake
- `SERVER_HELLO (0x02)`: Server response
- `CLIENT_AUTH (0x03)`: Client authentication
- `DATA (0x10)`: Encrypted data
- `KEEPALIVE (0x11)`: Connection maintenance
- `REKEY (0x12)`: Key rotation
- `CLOSE (0xFF)`: Graceful shutdown

## Security Analysis

### Threat Model

- **Network attacker**: Can read, modify, inject, replay packets
- **Protected against**: MITM, replay, tampering, eavesdropping
- **Not protected against**: Endpoint compromise, side-channels

### Attack Resistance

- **Replay attacks**: Monotonic counter + timestamp validation
- **MITM attacks**: Mutual authentication with pre-shared identity keys
- **Forward secrecy**: Ephemeral keys destroyed after session
- **DoS resistance**: Stateless handshake validation before resource allocation

## Implementation Requirements

1. **Key Storage**: Identity keys stored encrypted at rest
2. **Secure Random**: Use OS CSPRNG for all random generation
3. **Constant-Time**: Use constant-time comparison for MACs
4. **Memory Safety**: Zero sensitive material after use
5. **Error Handling**: No timing side-channels in error paths
