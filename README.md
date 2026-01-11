# SecureVPN - Custom VPN Implementation

A from-scratch VPN implementation using state-of-the-art cryptography, designed for secure SSH tunneling. Built without any pre-existing VPN libraries like WireGuard.

## 🔒 Security Features

### Cryptographic Primitives

- **Encryption**: ChaCha20-Poly1305 (AEAD cipher)
- **Key Exchange**: X25519 (Elliptic Curve Diffie-Hellman)
- **Signatures**: Ed25519 (EdDSA)
- **Key Derivation**: HKDF with SHA-256
- **Password KDF**: Scrypt (for key storage)

### Security Guarantees

✅ **Perfect Forward Secrecy** - Ephemeral keys per session  
✅ **Mutual Authentication** - Both parties verify identity  
✅ **Replay Protection** - Monotonic counter with timestamp validation  
✅ **Authentication** - AEAD ensures message integrity  
✅ **No Information Leakage** - Constant-time comparisons  
✅ **Key Rotation** - Automatic rekey after 1 hour or 1 GB  
✅ **MITM Protection** - Pre-shared public keys

### Attack Resistance

- ✓ Network eavesdropping (encrypted with ChaCha20-Poly1305)
- ✓ Replay attacks (counter-based nonces + timestamps)
- ✓ Man-in-the-middle (mutual Ed25519 authentication)
- ✓ Tampering (authenticated encryption)
- ✓ Identity spoofing (pre-shared public keys)
- ✓ Counter exhaustion (automatic detection)

## 🏗️ Architecture

```
┌─────────────┐                               ┌─────────────┐
│   Client    │                               │   Server    │
│             │                               │             │
│  SSH Client │                               │ SSH Server  │
│      ↓      │                               │      ↑      │
│  Port 2222  │                               │  Port 22    │
│      ↓      │                               │      ↑      │
│ ┌─────────┐ │  Encrypted VPN Tunnel (8443)  │ ┌─────────┐ │
│ │  Client │ │ ════════════════════════════> │ │  Server │ │
│ │  VPN    │ │  ChaCha20-Poly1305 + X25519  │ │   VPN   │ │
│ └─────────┘ │ <════════════════════════════ │ └─────────┘ │
└─────────────┘                               └─────────────┘
```

### Protocol Flow

1. **Handshake (3 steps)**

   - CLIENT_HELLO: Client sends ephemeral public key + identity
   - SERVER_HELLO: Server sends ephemeral public key + signed response
   - CLIENT_AUTH: Client proves identity with signature

2. **Key Derivation**

   - ECDH on ephemeral X25519 keys → shared secret
   - HKDF expands to separate TX/RX keys
   - Ephemeral keys destroyed after handshake

3. **Data Transport**
   - Each packet: `[counter(8)] + [encrypted_payload + auth_tag(16)]`
   - Counter prevents replay attacks
   - AEAD ensures confidentiality + integrity

## 📦 Installation

### Prerequisites

- Python 3.8+
- pip

### Setup

```bash
# Clone or navigate to VPN directory
cd /Users/alexwaldmann/Desktop/VPN

# Install dependencies
pip install -r requirements.txt

# Generate keys (first time only)
python key_manager.py
```

The key setup will create:

- `~/.securevpn/keys/server.key` (server private key)
- `~/.securevpn/keys/server.pub` (server public key)
- `~/.securevpn/keys/client.key` (client private key)
- `~/.securevpn/keys/client.pub` (client public key)

### Key Exchange

After generating keys, you need to exchange public keys between client and server:

**On the server machine:**

```bash
cd ~/.securevpn/keys
# Share server.pub with client
cat server.pub
```

**On the client machine:**

```bash
cd ~/.securevpn/keys
# Share client.pub with server
cat client.pub

# Import server's public key
echo "securevpn-ed25519 <SERVER_PUBLIC_KEY_BASE64> server" > server.pub
```

**On the server machine:**

```bash
cd ~/.securevpn/keys
# Import client's public key
echo "securevpn-ed25519 <CLIENT_PUBLIC_KEY_BASE64> client" > client.pub
```

## 🚀 Usage

### Start the Server

On the machine with SSH server:

```bash
python server.py --host 0.0.0.0 --port 8443
```

Options:

- `--host`: Listen address (default: 0.0.0.0)
- `--port`: Listen port (default: 8443)
- `--ssh-host`: Local SSH server address (default: 127.0.0.1)
- `--ssh-port`: Local SSH port (default: 22)
- `--identity`: Identity key name (default: server)
- `--peer`: Peer key name (default: client)
- `--password`: Password for encrypted key

### Start the Client

On the machine connecting to server:

```bash
python client.py SERVER_IP --port 8443 --local-port 2222
```

Options:

- `SERVER_IP`: VPN server address (required)
- `--port`: VPN server port (default: 8443)
- `--local-host`: Local proxy address (default: 127.0.0.1)
- `--local-port`: Local proxy port (default: 2222)
- `--identity`: Identity key name (default: client)
- `--peer`: Peer key name (default: server)
- `--password`: Password for encrypted key

### Connect via SSH

Once the VPN tunnel is established:

```bash
ssh -p 2222 username@127.0.0.1
```

This connects through the secure VPN tunnel to the remote SSH server!

## 🧪 Testing

Run the comprehensive security test suite:

```bash
python test_security.py
```

Tests cover:

- ✓ Cryptographic primitives (signing, encryption, key exchange)
- ✓ Protocol handshake (all 3 steps)
- ✓ Replay attack protection
- ✓ Signature verification and tamper detection
- ✓ MITM protection
- ✓ Counter exhaustion handling
- ✓ Forward secrecy
- ✓ Edge cases and error handling

## 📁 Project Structure

```
VPN/
├── PROTOCOL.md           # Detailed protocol specification
├── README.md             # This file
├── requirements.txt      # Python dependencies
├── crypto_core.py        # Cryptographic primitives
├── protocol.py           # Protocol implementation
├── key_manager.py        # Key generation and management
├── server.py             # VPN server
├── client.py             # VPN client
└── test_security.py      # Comprehensive test suite
```

## 🔐 Security Considerations

### What This Protects Against

- ✅ Network eavesdropping
- ✅ Packet injection/tampering
- ✅ Replay attacks
- ✅ Man-in-the-middle attacks
- ✅ Identity spoofing

### What This Doesn't Protect Against

- ❌ Endpoint compromise (malware on client/server)
- ❌ Side-channel attacks (timing, power analysis)
- ❌ Vulnerabilities in the Python runtime or cryptography library
- ❌ Physical access to machines

### Best Practices

1. **Key Storage**: Store private keys in encrypted form with strong passwords
2. **Key Rotation**: Regularly generate new identity keys
3. **Network Security**: Use firewall rules to restrict VPN port access
4. **Monitoring**: Monitor server logs for suspicious activity
5. **Updates**: Keep cryptography library updated

## 🎯 Use Cases

### ✅ Recommended Use Cases

- Secure SSH access to remote servers
- Development/testing environments
- Learning cryptographic protocol design
- Low-level VPN education

### ❌ Not Recommended For

- Production critical infrastructure (use audited solutions like WireGuard)
- High-availability requirements
- Mobile/roaming scenarios
- Full network-layer VPN (this is application-layer)

## 📚 Protocol Details

See [PROTOCOL.md](PROTOCOL.md) for complete protocol specification including:

- Detailed handshake flow
- Key derivation process
- Packet format specifications
- Security analysis
- Threat model

## 🛠️ Advanced Usage

### Password-Protected Keys

Generate keys with password protection:

```bash
python key_manager.py
# Enter password when prompted
```

Then use with password:

```bash
python server.py --password "your_password"
python client.py SERVER_IP --password "your_password"
```

### Custom Key Locations

Keys are stored in `~/.securevpn/keys/` by default. You can manage keys programmatically:

```python
from key_manager import KeyManager

km = KeyManager()
identity = km.load_identity("server", password="secret")
peer_pub = km.load_peer_public_key("client")
```

### Multiple Client Support

The server can handle multiple clients. Generate separate identities:

```bash
# Create keys for client1, client2, etc.
from key_manager import KeyManager
km = KeyManager()
km.generate_identity("client1")
km.generate_identity("client2")
```

## 🤝 Contributing

This is an educational project demonstrating cryptographic protocol implementation. Contributions for:

- Additional tests
- Documentation improvements
- Security analysis
- Code review

are welcome!

## ⚠️ Disclaimer

This is a custom VPN implementation created for educational purposes and specific use cases. While it implements industry-standard cryptographic primitives and follows security best practices:

1. It has **not been audited** by security professionals
2. It's **not intended for production** critical infrastructure
3. Use at your own risk
4. For production use, prefer audited solutions like WireGuard, OpenVPN, or IPsec

## 📄 License

This project is provided as-is for educational and research purposes.

## 🔗 References

- [RFC 7539](https://tools.ietf.org/html/rfc7539) - ChaCha20-Poly1305
- [RFC 7748](https://tools.ietf.org/html/rfc7748) - Curve25519 and Curve448
- [RFC 8032](https://tools.ietf.org/html/rfc8032) - EdDSA (Ed25519)
- [RFC 5869](https://tools.ietf.org/html/rfc5869) - HKDF
- [Noise Protocol Framework](https://noiseprotocol.org/) - Inspiration for handshake design
- [WireGuard Paper](https://www.wireguard.com/papers/wireguard.pdf) - Modern VPN design patterns

---

**Built with ❤️ and modern cryptography**
