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
- **Post-Quantum**: Protocol v2 adds a hybrid X25519 + ML-KEM-768 key
  exchange (see "Protocol v2" below) so that a future large-scale quantum
  computer breaking X25519 alone still leaves the session key protected by
  ML-KEM-768.

## Cryptographic Primitives

- **Encryption**: ChaCha20-Poly1305 (AEAD)
- **Key Exchange**: X25519 (ECDH on Curve25519); v2 adds ML-KEM-768 (FIPS 203)
  run alongside it (see "Protocol v2")
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

After ECDH, derive multiple keys using HKDF-SHA256 (`crypto_core.py:
KeyExchange.derive_session_keys`):

```
shared_secret = ECDH(ephemeral_priv, ephemeral_pub_peer)          # v1
shared_secret = ECDH(...) || ML-KEM-768-shared-secret             # v2, see below

master_key = HKDF-Extract-and-Expand(salt=NULL, ikm=shared_secret,
                                      info="SecureVPN-v1", length=32)

tx_key = HKDF-Extract-and-Expand(salt=master_key, ikm="",
                                  info="client-tx" | "server-tx", length=32)
rx_key = HKDF-Extract-and-Expand(salt=master_key, ikm="",
                                  info="server-tx" | "client-tx", length=32)
```

(The client uses `info="client-tx"` for its own `tx_key` and
`info="server-tx"` for `rx_key`; the server does the reverse, so both sides
land on the same two keys with tx/rx swapped.) `master_key` is zeroed after
use. The `info` label is literally `"SecureVPN-v1"` in both protocol v1 and
v2 -- it identifies the *KDF construction*, not the wire protocol version,
and was deliberately left unchanged so v1 sessions derive byte-identical
keys to before v2 existed.

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

## Protocol v2: hybrid X25519 + ML-KEM-768 handshake

`SecureVPNProtocol.PROTOCOL_VERSION` is `2` (bumped additively from `1`).
Every handshake entry point reads the packet's own `[type, version]` bytes
before choosing a struct layout, so a peer speaking a version this build
doesn't match is rejected with `ProtocolError` immediately -- it is never
handed to the wrong version's `struct.unpack` (which would either crash
with a raw `struct.error` or, worse, misparse the bytes as if they were
well-formed). v1's wire format and key derivation are kept byte-for-byte
intact in `_v1`-suffixed methods; v2 lives alongside it in `_v2`-suffixed
methods, not on top of it.

### Why ML-KEM-768 was hand-rolled here

This repository's own `crypto_core.py` already implements X25519, Ed25519,
HKDF, and ChaCha20-Poly1305 by composing primitives from `cryptography`
(itself a mature, audited wrapper over OpenSSL/BoringSSL) rather than by
outsourcing the whole handshake to a pre-built VPN stack -- that is the
established style of this codebase: build the protocol from well-understood
building blocks, reviewed in the open, rather than depend on an opaque
"do everything" library. ML-KEM-768 has no equivalent mature binding
available to this project (no `pqcrypto`/`ml-kem`/`liboqs`/`kyber` crate
was used, per the implementation constraint this feature was built under),
so implementing FIPS 203 directly, in the open, with the same "small
building blocks, testable in isolation" discipline as the rest of
`crypto_core.py`, was a deliberate, reviewed exception to "don't roll your
own crypto" -- not an oversight. It is a hybrid construction specifically
*because* of that: X25519 is mature and battle-tested, ML-KEM-768 is
new and hand-rolled, and combining them (rather than trusting ML-KEM-768
alone) means a flaw in either one does not by itself break the session key
-- an attacker needs to break both.

### Wire format

```
CLIENT_HELLO (v2, 1258 bytes)
[type(1)] [version=2(1)] [timestamp(8)] [Ce_pub(32)] [Ci_pub(32)] [mlkem_ek(1184)]

SERVER_HELLO (v2, 1226 bytes)
[type(1)] [version=2(1)] [timestamp(8)] [Se_pub(32)] [Si_pub(32)] [mlkem_ct(1088)] [signature(64)]
```

`mlkem_ek` is the client's fresh ML-KEM-768 encapsulation key (a new keypair
per handshake, matching the ephemeral-X25519-per-session model). The server
encapsulates against it to get `(mlkem_ct, mlkem_shared_secret)` and sends
back `mlkem_ct`; the client decapsulates it with the matching (also
per-handshake, discarded afterward) decapsulation key to recover the same
`mlkem_shared_secret`. `mlkem_ct` is included in the data the server signs
(`Ce_pub || Se_pub || client_time || server_time || mlkem_ct`), so a
tampered ciphertext is caught by Ed25519 signature verification, not left
to be silently absorbed into a wrong session key.

### Key derivation (v2)

```
x25519_secret = ECDH(ephemeral_priv, ephemeral_pub_peer)
mlkem_secret  = ML-KEM-768-Decaps(dk, ct)   # or Encaps output on the server side
hybrid_secret = x25519_secret || mlkem_secret     # concatenation, in that order

master_key = HKDF-Extract-and-Expand(salt=NULL, ikm=hybrid_secret,
                                      info="SecureVPN-v1", length=32)
# tx_key / rx_key derivation from master_key is otherwise IDENTICAL to v1
```

This is the only change `derive_session_keys()` makes for v2: the `info`
labels and the two-step extract/expand shape are untouched, so a security
review of v1's KDF chain applies unchanged to v2's -- the only new question
is whether `hybrid_secret` is at least as hard to predict as
`x25519_secret` alone, which holds as long as ML-KEM-768 is not *weaker*
than "no additional secret at all" (i.e., even a broken ML-KEM-768
implementation cannot make v2 worse than v1, only fail to add security).

### Honest caveats

- **Verified against real FIPS 203 KAT vectors (2026-09-09)**: this
  ML-KEM-768 implementation (`mlkem768/`) is checked against the real NIST
  ACVP keyGen KAT (tgId=2, tcId=26, fetched live from
  github.com/usnistgov/ACVP-Server) and matches it byte-for-byte
  (`mlkem768/tests/kat_keygen.rs`). A full keygen→encaps→decaps chain from
  that same seed also matches an independent second reference
  implementation (`kyber-py`, a pure-Python FIPS 203 implementation)
  byte-for-byte. Two real bugs were found and fixed to reach this: (1)
  K-PKE.KeyGen must derive `(rho, sigma) = G(d || k)` with the module rank
  `k` appended to the seed, which the code omitted; (2) the uniform-matrix
  XOF seed byte order was backwards between the untransposed and
  transposed matrix generation. In addition to these KATs, the 1000+-trial
  internal round-trip self-tests and NTT/CBD/compression self-tests
  described in `CRYPTOGRAPHY_EXPLAINED.md` continue to pass. This is now
  believed interoperable with other conformant ML-KEM-768 implementations,
  though full interop has only been checked against one independent
  Python implementation, not a hardware HSM or another production stack.
- **Constant-time posture**: CBD sampling and the Fujisaki-Okamoto implicit
  rejection check in `decaps` avoid secret-dependent branches and use a
  computed mask instead of an early return. This has NOT been checked with
  a timing harness (e.g. dudect) -- residual timing-channel risk is real,
  not just theoretical, until that is done.
- **Fail-safe, not fail-open**: because the KDF chain and info labels are
  unchanged, a v2 build that somehow got a *wrong* (but correctly-shaped)
  `mlkem_shared_secret` would simply fail to decrypt the next message
  (wrong key), not silently downgrade to a weaker but "working" session.

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
