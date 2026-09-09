# Cryptography Explained - What's Actually Happening

This document explains the "buzzwords" from the README in plain English, showing what's actually happening under the hood.

## 🔐 Cryptographic Primitives (The Building Blocks)

### ChaCha20-Poly1305 (Encryption)

**What it is:** A way to encrypt your data so nobody can read it.

**How it works:**

```
Your data: "Hello, this is my SSH password: hunter2"
          ↓ (ChaCha20 encryption)
Encrypted: "x7#$mQ9@pLz&vN2!..." (looks like random garbage)
          ↓ (send over internet)
Decrypted: "Hello, this is my SSH password: hunter2" (only at destination)
```

**Real example in code:**

```python
# Encrypting
plaintext = b"ssh password"
encrypted = cipher.encrypt(nonce, plaintext)
# Result: Random-looking bytes that only the other side can decrypt

# Decrypting
decrypted = cipher.decrypt(nonce, encrypted)
# Result: Original "ssh password" back
```

**Why ChaCha20-Poly1305?**

- **ChaCha20** = Fast encryption algorithm (faster than AES on phones/computers without special hardware)
- **Poly1305** = Authentication tag that proves data wasn't tampered with
- Together = "AEAD" (Authenticated Encryption with Associated Data) means: encrypt + verify in one step

**Analogy:** Like putting your letter in a locked box that also has a tamper-proof seal. If someone breaks the seal or tries to change the letter, you'll know.

---

### X25519 (Key Exchange)

**What it is:** A way for two people to agree on a secret password without ever sending the password over the internet.

**How it works - The "color mixing" analogy:**

```
Alice has secret color: Red
Bob has secret color: Blue
Public color everyone knows: Yellow

Alice creates: Red + Yellow = Orange (sends to Bob publicly)
Bob creates: Blue + Yellow = Green (sends to Alice publicly)

Alice receives Green, adds her Red: Green + Red = Brown
Bob receives Orange, adds his Blue: Orange + Blue = Brown

Both end up with Brown, but an eavesdropper only sees Orange, Green, and Yellow!
They can't figure out Brown without knowing the secret Red or Blue.
```

**Real example:**

```python
# Alice generates her secret key
alice_private = X25519PrivateKey.generate()
alice_public = alice_private.public_key()

# Bob generates his secret key
bob_private = X25519PrivateKey.generate()
bob_public = bob_private.public_key()

# They exchange public keys (anyone can see these)
# Then each does magic math:

alice_shared_secret = alice_private.exchange(bob_public)
bob_shared_secret = bob_private.exchange(alice_public)

# alice_shared_secret == bob_shared_secret
# But nobody watching the network can figure this out!
```

**Why X25519?**

- Uses elliptic curve cryptography (ECC) - very secure with small keys
- "25519" refers to Curve25519, a specific mathematical curve
- Much faster and more secure than older methods (like RSA)

**Analogy:** It's like two people independently solving a complex math problem and arriving at the same answer, but anyone watching only sees the questions, not the answers.

---

### ML-KEM-768 (Post-Quantum Key Exchange, protocol v2)

**What it is:** A second, independent way for two people to agree on a secret, designed so that even a future quantum computer breaking X25519 (above) does not break the session. It's a NIST-standardized (FIPS 203) "key encapsulation mechanism" (KEM), not a Diffie-Hellman-style exchange like X25519.

**Why it exists alongside X25519, not instead of it:**

```
X25519:      mature, decades of cryptanalysis, but a large-enough quantum
             computer running Shor's algorithm could eventually break it.

ML-KEM-768:  believed quantum-resistant (based on the hardness of lattice
             problems), but newer and less battle-tested than X25519.

hybrid:      combine BOTH secrets. An attacker has to break BOTH X25519
             AND ML-KEM-768 to recover the session key -- breaking just
             one gets them nothing.
```

**How it works - the "sealed box" analogy** (different shape from X25519's
color-mixing, because a KEM is asymmetric -- one side generates a key *pair*,
the other side uses the public half to seal a *fresh* secret for them):

```
Client generates a keypair: encapsulation key (ek, public) + decapsulation key (dk, secret)
Client sends ek to the server.

Server picks a random secret, "seals" it using ek:
    (ciphertext, server_shared_secret) = Encaps(ek)
Server sends ciphertext back. Nobody but the ek/dk pair's owner can open it.

Client "unseals" the ciphertext with its dk:
    client_shared_secret = Decaps(dk, ciphertext)

client_shared_secret == server_shared_secret
An eavesdropper sees ek and ciphertext, but (assuming ML-KEM-768's hardness
assumption holds) cannot recover the secret from them.
```

**Real example (this repo's own implementation, `mlkem768/`):**

```python
import mlkem768

# Client: generate a fresh keypair for this handshake only
ek, dk = mlkem768.keygen()          # ek: 1184 bytes, dk: 2400 bytes

# ... client sends ek to server in CLIENT_HELLO ...

# Server: seal a fresh secret against the client's public key
ciphertext, server_secret = mlkem768.encaps(ek)   # ciphertext: 1088 bytes

# ... server sends ciphertext back in SERVER_HELLO ...

# Client: unseal it with the matching secret key
client_secret = mlkem768.decaps(dk, ciphertext)

# client_secret == server_secret (both 32 bytes) -- verified by 1000+
# round-trip trials in mlkem768/src/lib.rs's own test suite.
```

**Combining it with X25519 (the "hybrid secret"):**

```python
hybrid_secret = x25519_shared_secret + mlkem_shared_secret  # concatenation
# ... fed into the SAME HKDF chain X25519-only sessions already used ...
```

**Why hand-rolled, and what that costs:** Common advice is "never write your
own cryptography" -- and this codebase mostly follows that, building
X25519/Ed25519/HKDF/ChaCha20-Poly1305 from the well-audited `cryptography`
library rather than reimplementing elliptic-curve math from scratch. ML-KEM-768
is the deliberate exception: no mature Python/Rust binding was available to
lean on here (no `pqcrypto`/`ml-kem`/`liboqs`/`kyber` dependency), so
`mlkem768/` implements FIPS 203 directly -- NTT, centered binomial sampling,
compression, the K-PKE primitive, and the encaps/decaps wrapper with
Fujisaki-Okamoto-style implicit rejection, each piece unit-tested in
isolation the same way the rest of this codebase's crypto is explained
piece by piece in this document. The honest cost: a real NIST ACVP
known-answer-test vector was fetched and checked against this
implementation's output, and it does **not** byte-match (the internal
domain-separation choices weren't written to reproduce the FIPS 203
Appendix exactly) -- so this build is verified correct against *itself*
(round-trip tests: keygen → encaps → decaps always agree) but not proven
interoperable with any other ML-KEM-768 implementation. It should be
treated as "this codebase's own hybrid handshake," not as a drop-in
replacement people can mix-and-match with other post-quantum TLS stacks.

**Analogy:** X25519 is like two people mixing paint colors and getting the
same result without revealing their own color. ML-KEM-768 is like one
person locking a box with a padlock only the *other* person's key can open,
then mailing the locked box -- a fundamentally different mechanism, chosen
specifically so a weakness discovered in one mechanism (say, elliptic-curve
math falling to a quantum computer) doesn't also break the other.

---

### Ed25519 (Signatures)

**What it is:** A way to prove "I really sent this message" (like a digital signature you can't forge).

**How it works:**

```
Your private key: (secret, only you have)
Your public key: (everyone knows this is you)

You sign a message:
Message: "Transfer $100 to Bob"
Private key: (your secret)
         ↓
Signature: "x9mQ2pL..." (unique to this message + your key)

Anyone can verify:
Message: "Transfer $100 to Bob"
Signature: "x9mQ2pL..."
Your public key: (public)
         ↓
Verification: ✓ "Yes, this was really signed by you"

If someone changes even ONE letter:
Message: "Transfer $100 to Rob" (Bob → Rob)
         ↓
Verification: ✗ "Signature invalid! Message was tampered!"
```

**Real example:**

```python
# Generate identity
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Sign a message
message = b"I agree to these terms"
signature = private_key.sign(message)

# Anyone can verify (even if they don't have the private key)
public_key.verify(signature, message)  # Raises error if invalid

# If message is tampered:
tampered = b"I DO NOT agree to these terms"
public_key.verify(signature, tampered)  # ERROR - signature doesn't match!
```

**Why Ed25519?**

- Super fast signing and verification
- Very small signatures (64 bytes)
- Practically impossible to forge

**Analogy:** Like a wax seal on a letter. You can see it's sealed (verify), but only the person with the signet ring can create that specific seal (sign).

---

### HKDF (Key Derivation Function)

**What it is:** A way to turn one secret into multiple different secrets.

**How it works:**

```
One master secret: "abc123xyz"
              ↓ HKDF
Key for sending: "fj29dksl..."
Key for receiving: "pl8xmq3k..."
Key for verification: "zn7vb2wp..."

All derived from same source, but totally different
```

**Real example:**

```python
# You have one shared secret from key exchange
shared_secret = b"xyz123abc..."  # From X25519 exchange

# Derive multiple keys for different purposes
tx_key = HKDF(shared_secret, info=b"client-tx").derive()
rx_key = HKDF(shared_secret, info=b"server-tx").derive()

# tx_key and rx_key are completely different
# But both sides can compute them from the same shared_secret
```

**Why HKDF?**

- Never reuse the same key for multiple purposes
- Can't work backwards from derived keys to find the master secret
- Standard way to "stretch" one key into many

**Protocol v2 (hybrid):** the *only* thing that changes is what goes into
`shared_secret` above -- instead of just the X25519 output, it's
`x25519_secret || mlkem_shared_secret` (see the ML-KEM-768 section above).
Everything downstream (the `info` labels, the `client-tx`/`server-tx` split,
zeroing the master key after use) is identical between v1 and v2. That's a
deliberate design choice: it means a security review of v1's HKDF chain
carries over to v2 almost unchanged, and it means ML-KEM-768 can only add
security here, never remove it -- even a hypothetically broken
`mlkem_shared_secret` (e.g. an attacker who could predict it) still leaves
the session as strong as v1 was, because `x25519_secret` is still mixed in.

**Analogy:** Like having one master key that you can use to make many different specific keys (mailbox key, garage key, office key), but those specific keys can't be used to recreate the master.

---

### Scrypt (Password KDF)

**What it is:** A way to turn a weak password into a strong encryption key, while making it really hard for attackers to guess.

**How it works:**

```
Your password: "password123"
               ↓
               Scrypt (takes ~1 second of intense computation)
               ↓
Strong key: "x9mQ2pL8vN3zB..." (256 bits of random-looking data)

Attacker trying to guess:
Try "password1" → Scrypt (1 second) → Wrong
Try "password2" → Scrypt (1 second) → Wrong
Try "password3" → Scrypt (1 second) → Wrong
... billions of guesses = years of computation
```

**Real example:**

```python
# Storing a password
password = "my_secret_password"
salt = os.urandom(32)  # Random data

# Derive encryption key (takes ~1 second intentionally)
kdf = Scrypt(salt=salt, length=32, n=2**18, r=8, p=1)
encryption_key = kdf.derive(password.encode())

# Now use encryption_key to encrypt your private keys
```

**Why Scrypt?**

- **Time cost**: Each guess takes time (can't try millions per second)
- **Memory cost**: Each guess requires lots of RAM (can't use cheap GPUs)
- Makes password cracking impractical

**Analogy:** Like a lock that deliberately takes 5 seconds to open, even with the right key. This doesn't bother you (5 seconds is fine), but an attacker trying a million combinations would need 57 days instead of instant.

---

## 🛡️ Security Guarantees (What This Protects Against)

### Perfect Forward Secrecy

**What it means:** If someone steals your keys TODAY, they can't decrypt messages from YESTERDAY.

**How it works:**

```
Session 1 (Yesterday):
  Generate temporary keys → Use them → Destroy them
  Encrypted data: "xQ9m2..."

Session 2 (Today):
  Generate NEW temporary keys → Use them → Destroy them
  Encrypted data: "pL8v3..."

Attacker steals your long-term key today:
  - Can't decrypt Session 1 (temporary keys were destroyed)
  - Can't decrypt Session 2 (different temporary keys, also destroyed)
```

**Real example:**

```python
# Each connection generates NEW ephemeral keys
session1_key = X25519PrivateKey.generate()  # Yesterday
# ... use it ...
del session1_key  # Destroyed

session2_key = X25519PrivateKey.generate()  # Today (completely different)
# Even if attacker gets your identity key, they can't decrypt old sessions
```

**Why it matters:** Government seizes your server? Old conversations stay private. Hacker compromises you? Past data is still safe.

**Analogy:** Using a different padlock for each day. Stealing today's padlock doesn't help open yesterday's locked box.

---

### Mutual Authentication

**What it means:** Both sides prove their identity to each other (not just client → server).

**How normal websites work:**

```
You → [HTTPS] → Bank website
     "Is this really my bank?" ✓ (bank proves identity)
     "Is this really me?" (bank hopes you logged in correctly)
```

**How this VPN works:**

```
Client ←→ Server
  ↓           ↓
"Prove you're the server" ✓
  ↓           ↓
"Prove you're the client" ✓

Both sides verify each other before exchanging ANY data
```

**Real example:**

```python
# Server signs handshake with its private key
server_signature = server_private_key.sign(handshake_data)

# Client verifies using server's public key (which it knows in advance)
server_public_key.verify(server_signature, handshake_data)  # ✓

# Then client signs with its private key
client_signature = client_private_key.sign(handshake_data)

# Server verifies using client's public key
client_public_key.verify(client_signature, handshake_data)  # ✓

# Only after BOTH verify does data transfer begin
```

**Why it matters:** Prevents man-in-the-middle attacks. You know you're talking to the real server, and the server knows it's really you.

**Analogy:** Like showing each other your driver's licenses before having a sensitive conversation.

---

### Replay Protection

**What it means:** An attacker can't record your messages and "replay" them later to fool the system.

**The attack without protection:**

```
1. You send: "Transfer $100 to Bob" (encrypted)
2. Attacker records this encrypted message
3. Later, attacker replays the same message
4. System thinks it's a new request
5. Another $100 gets transferred!
```

**How we prevent it:**

```
Message 1: [Counter: 0] "Transfer $100"
Message 2: [Counter: 1] "Check balance"
Message 3: [Counter: 2] "Logout"

If attacker replays Message 1:
  System sees: Counter = 0, but last counter was 2
  System: "This is old! Reject it!" ✗
```

**Real example:**

```python
# Sender
counter = 0
for message in messages:
    packet = encrypt(counter + message)
    counter += 1  # 0, 1, 2, 3...

# Receiver
last_counter = -1
def receive(packet):
    counter, message = decrypt(packet)
    if counter <= last_counter:
        raise Exception("Replay attack detected!")
    last_counter = counter
    return message
```

**Why it matters:** Prevents attackers from capturing your "login" message and replaying it to login as you later.

**Analogy:** Like numbering pages in a book. If someone tries to insert an old page, you'll notice the numbers are wrong.

---

### AEAD (Authentication)

**What it means:** The encryption also proves the message wasn't tampered with.

**Old way (bad):**

```
Encrypt data → Send encrypted data
Attacker flips some bits in transit
Receiver decrypts → Gets garbage but might not notice
```

**AEAD way (good):**

```
Encrypt data + Generate authentication tag
Send encrypted data + tag
Attacker flips some bits
Receiver tries to decrypt → Tag doesn't match → REJECT
```

**Real example:**

```python
# Encrypting with AEAD
cipher = ChaCha20Poly1305(key)
ciphertext = cipher.encrypt(nonce, plaintext)
# ciphertext = actual_encrypted_data + 16_byte_auth_tag

# Decrypting
try:
    plaintext = cipher.decrypt(nonce, ciphertext)
except InvalidTag:
    print("Someone tampered with this message!")
    # Decryption won't even happen if tag is wrong
```

**Why it matters:** Prevents an attacker from modifying encrypted messages (even if they can't read them).

**Analogy:** Like a tamper-evident seal on a medicine bottle. You know if someone opened it, even if you can't see what's inside.

---

### Constant-Time Comparisons

**What it means:** Comparing secrets in a way that doesn't leak information through timing.

**The problem (timing attack):**

```python
# BAD - stops at first difference
def compare(secret, guess):
    for i in range(len(secret)):
        if secret[i] != guess[i]:
            return False  # Stops here - this takes different time!
    return True

# Timing:
compare("password", "axxxxxx")  # Fast (fails at 'a' vs 'p')
compare("password", "pxxxxxx")  # Slower (fails at 'a' vs second char)
compare("password", "paxxxxx")  # Even slower
...
Attacker can measure timing to guess the password!
```

**The solution:**

```python
# GOOD - always compares entire string
def constant_time_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y  # Always does ALL comparisons
    return result == 0  # Same time regardless

# Timing is always the same, no matter how many characters match
```

**Real example in code:**

```python
# When checking authentication tags or passwords
if constant_time_compare(computed_tag, received_tag):
    # Valid
else:
    # Invalid

# Attacker can't learn anything from timing
```

**Why it matters:** Prevents sophisticated timing attacks where attackers measure how long your program takes to reveal secret information.

**Analogy:** Like grading a test by looking at every answer even if you see a wrong one early, so students can't tell from your reaction which question they got wrong.

---

## 🎯 Putting It All Together - A Real Connection

Here's what happens when you connect through the VPN, step by step:

### Step 1: Key Exchange (X25519)

```
Client generates: ephemeral_private_key_client (secret)
Server generates: ephemeral_private_key_server (secret)

They exchange public keys:
Client sends: ephemeral_public_key_client
Server sends: ephemeral_public_key_server

Both calculate:
shared_secret = ECDH(my_private, their_public)
# Both end up with the same shared_secret!
```

### Step 2: Authentication (Ed25519)

```
Server signs: "I'm the real server" + handshake_data
Client verifies: ✓ "Yes, this signature matches server's public key"

Client signs: "I'm the real client" + handshake_data
Server verifies: ✓ "Yes, this signature matches client's public key"

Both verified ✓
```

### Step 3: Key Derivation (HKDF)

```
shared_secret → HKDF → client_tx_key (client encrypts with this)
                    → client_rx_key (client decrypts with this)
                    → server_tx_key (same as client_rx_key)
                    → server_rx_key (same as client_tx_key)
```

### Step 4: Encrypted Communication (ChaCha20-Poly1305)

```
Client wants to send: "ssh login: password123"

counter = 0
encrypted = ChaCha20Poly1305(client_tx_key).encrypt(counter, plaintext)
send: [counter: 0][encrypted_data + auth_tag]

Server receives:
counter = 0 (checks: 0 > -1? Yes ✓)
decrypted = ChaCha20Poly1305(server_rx_key).decrypt(counter, encrypted)
# auth_tag automatically verified ✓
result: "ssh login: password123"
```

### Step 5: Replay Protection

```
Next message:
Client: counter = 1
Server: checks 1 > 0? Yes ✓

Attacker replays first message:
Attacker: counter = 0
Server: checks 0 > 1? No ✗ REJECT
```

## 📊 Summary: What Each Piece Does

| Technology            | What It Does                                   | Why It Matters                                  |
| --------------------- | ---------------------------------------------- | ----------------------------------------------- |
| **ChaCha20-Poly1305** | Encrypts your data + proves it wasn't tampered | Nobody can read or modify your traffic          |
| **X25519**            | Lets you agree on a secret without sending it  | Eavesdroppers can't learn the encryption key    |
| **Ed25519**           | Proves who sent a message                      | Prevents impersonation and MITM attacks         |
| **HKDF**              | Turns one secret into many keys                | Each purpose gets its own key (safer)           |
| **Scrypt**            | Makes passwords hard to crack                  | Even weak passwords become strong keys          |
| **Counters**          | Detects replayed messages                      | Prevents replay attacks                         |
| **Ephemeral Keys**    | New keys every session                         | Past data stays encrypted even if you're hacked |
| **Constant-Time**     | Compares secrets without timing leaks          | Prevents timing side-channel attacks            |

## 🔍 The Big Picture

Think of the VPN like sending a letter through hostile territory:

1. **X25519**: You and recipient agree on a secret code (without telling anyone)
2. **ChaCha20**: You write your letter in that secret code
3. **Poly1305**: You add a tamper-proof seal
4. **Ed25519**: You sign it with your unique signature
5. **Counter**: You number each letter (1, 2, 3...) so copies can't be reused
6. **Ephemeral Keys**: You use a different code for each day
7. **HKDF**: From one master code, you create separate codes for "send" and "receive"

All of this happens in milliseconds, completely automatically, every time you connect!

---

**No More Buzzwords** - Now you know what's really happening! 🎉
