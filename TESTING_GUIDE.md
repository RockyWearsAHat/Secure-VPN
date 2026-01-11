# Testing Between PC and Laptop

## The Error You're Seeing

```
Connection failed: [Errno 61] Connect call failed ('127.0.0.1', 8443)
```

**This means:** The client can't connect because **the server isn't running yet!**

`Errno 61` on macOS = "Connection refused" = nothing is listening on that port.

## Solution: Start Server First!

You need to run the **server** before the **client** can connect.

---

## 🖥️ Testing Locally (One Machine)

### Option 1: Quick Test Script

```bash
cd /Users/alexwaldmann/Desktop/VPN

# This starts both server AND client automatically
python test_locally.py
```

### Option 2: Manual (Two Terminals)

**Terminal 1 - Start Server:**

```bash
cd /Users/alexwaldmann/Desktop/VPN
python server.py --host 127.0.0.1 --port 8443
```

Wait until you see:

```
✓ SecureVPN server listening on 127.0.0.1:8443
✓ Waiting for client connections...
```

**Terminal 2 - Start Client:**

```bash
cd /Users/alexwaldmann/Desktop/VPN
python client.py 127.0.0.1 --port 8443 --local-port 2222
```

**Terminal 3 - Test SSH:**

```bash
ssh -p 2222 $USER@127.0.0.1
```

---

## 💻 Testing Between PC and Laptop (Same Network)

Yes, being on the same network is actually **perfect** for testing! Here's how:

### Step 1: Setup Keys on Both Machines

**On PC (will be server):**

```bash
cd /path/to/VPN
python key_manager.py
# This creates server and client keys
```

**On Laptop (will be client):**

```bash
cd /path/to/VPN
python key_manager.py
# This creates server and client keys
```

### Step 2: Exchange Public Keys

**On PC - Get server public key:**

```bash
cd ~/.securevpn/keys
cat server.pub
# Copy the output (looks like: securevpn-ed25519 ABC123... server)
```

**On Laptop - Import PC's server key:**

```bash
cd ~/.securevpn/keys
# Paste the server.pub content from PC:
echo "securevpn-ed25519 ABC123... server" > server.pub
```

**On Laptop - Get client public key:**

```bash
cd ~/.securevpn/keys
cat client.pub
# Copy the output
```

**On PC - Import laptop's client key:**

```bash
cd ~/.securevpn/keys
# Paste the client.pub content from laptop:
echo "securevpn-ed25519 XYZ789... client" > client.pub
```

### Step 3: Find PC's IP Address

**On PC:**

```bash
# macOS/Linux
ifconfig | grep "inet " | grep -v 127.0.0.1

# Or simpler on macOS
ipconfig getifaddr en0    # WiFi
ipconfig getifaddr en1    # Ethernet

# Example output: 192.168.1.100
```

**Note your PC's local IP** (will be something like `192.168.1.x` or `10.0.0.x`)

### Step 4: Start Server on PC

**On PC:**

```bash
cd /path/to/VPN

# Start server listening on ALL interfaces
python server.py --host 0.0.0.0 --port 8443
```

You should see:

```
✓ SecureVPN server listening on 0.0.0.0:8443
✓ Forwarding to SSH server at 127.0.0.1:22
✓ Waiting for client connections...
```

### Step 5: Connect from Laptop

**On Laptop:**

```bash
cd /path/to/VPN

# Replace 192.168.1.100 with your PC's actual IP
python client.py 192.168.1.100 --port 8443 --local-port 2222
```

You should see:

```
✓ Connected to VPN server
✓ CLIENT_HELLO sent
✓ SERVER_HELLO received and verified
✓ CLIENT_AUTH sent
✓ Handshake complete, secure tunnel established

✓ Local SSH proxy listening on 127.0.0.1:2222
```

### Step 6: SSH Through the Tunnel

**On Laptop:**

```bash
# SSH through the encrypted VPN tunnel to your PC
ssh -p 2222 your_pc_username@127.0.0.1
```

**What's happening:**

- Laptop connects to `127.0.0.1:2222` (local proxy)
- Local proxy encrypts and sends to PC at `192.168.1.100:8443`
- PC decrypts and forwards to its local SSH server on port 22
- All traffic encrypted end-to-end!

---

## 🔥 Firewall Configuration

If you can't connect, you might need to open the firewall:

### macOS (PC/Server)

```bash
# Allow incoming connections on port 8443
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/python3
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/local/bin/python3
```

Or disable firewall temporarily:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off
```

### Linux (PC/Server)

```bash
# UFW
sudo ufw allow 8443/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
```

### Windows (PC/Server)

```powershell
# PowerShell (Run as Administrator)
New-NetFirewallRule -DisplayName "SecureVPN" -Direction Inbound -LocalPort 8443 -Protocol TCP -Action Allow
```

---

## 🧪 Testing the Connection

### Test 1: Verify Server is Listening

**On PC:**

```bash
# Check if port 8443 is open
lsof -i :8443
# or
netstat -an | grep 8443
```

### Test 2: Verify Network Connectivity

**On Laptop:**

```bash
# Can you reach the PC?
ping 192.168.1.100

# Can you connect to the port?
nc -zv 192.168.1.100 8443
# or
telnet 192.168.1.100 8443
```

### Test 3: Verify SSH Server

**On PC:**

```bash
# Make sure SSH server is running
sudo systemsetup -setremotelogin on  # macOS
# or
sudo systemctl start ssh  # Linux
```

---

## 📋 Troubleshooting Checklist

### "Connection refused" (Errno 61)

- [ ] Is the server actually running? (`python server.py`)
- [ ] Are you connecting to the right IP?
- [ ] Is the port correct? (default: 8443)

### "Connection timeout"

- [ ] Is firewall blocking port 8443?
- [ ] Are both machines on same network?
- [ ] Can you ping between machines?

### "Handshake failed"

- [ ] Did you exchange public keys correctly?
- [ ] Is `server.pub` on laptop the same as PC's `server.pub`?
- [ ] Is `client.pub` on PC the same as laptop's `client.pub`?

### "Identity not found"

- [ ] Did you run `python key_manager.py` on both machines?
- [ ] Are keys in `~/.securevpn/keys/`?

---

## 🎯 Quick Reference

### On Server Machine (PC)

```bash
# 1. Generate keys
python key_manager.py

# 2. Share server.pub with client
cat ~/.securevpn/keys/server.pub

# 3. Import client.pub from client machine
echo "securevpn-ed25519 <CLIENT_PUBKEY> client" > ~/.securevpn/keys/client.pub

# 4. Find your IP
ipconfig getifaddr en0

# 5. Start server
python server.py --host 0.0.0.0 --port 8443
```

### On Client Machine (Laptop)

```bash
# 1. Generate keys
python key_manager.py

# 2. Share client.pub with server
cat ~/.securevpn/keys/client.pub

# 3. Import server.pub from server machine
echo "securevpn-ed25519 <SERVER_PUBKEY> server" > ~/.securevpn/keys/server.pub

# 4. Connect to server (use server's IP)
python client.py 192.168.1.100 --port 8443 --local-port 2222

# 5. SSH through tunnel
ssh -p 2222 username@127.0.0.1
```

---

## 🌐 Same Network is Perfect!

Being on the same network (WiFi/LAN) is actually **ideal** for testing because:

✅ **Fast**: Low latency, high bandwidth  
✅ **Safe**: Traffic doesn't leave your local network  
✅ **Easy**: No port forwarding or router config needed  
✅ **Realistic**: Still tests encryption, authentication, all security features

The VPN works exactly the same whether you're:

- Same machine (127.0.0.1)
- Same network (192.168.x.x)
- Different networks (across the internet)

Only difference is the IP address you connect to!

---

## 📱 Example: Laptop → Desktop (Both on WiFi)

**Desktop (192.168.1.100):**

```bash
python server.py --host 0.0.0.0
# ✓ Listening on 0.0.0.0:8443
```

**Laptop (192.168.1.200):**

```bash
python client.py 192.168.1.100
# ✓ Connected to VPN server
# ✓ Local SSH proxy listening on 127.0.0.1:2222

ssh -p 2222 desktop_user@127.0.0.1
# You're now SSH'd into your desktop through encrypted VPN!
```

**What just happened:**

1. Laptop encrypts SSH traffic with ChaCha20-Poly1305
2. Sends encrypted packets over WiFi to desktop
3. Desktop decrypts and forwards to local SSH
4. Reverse for responses
5. All traffic encrypted end-to-end!

Even though you're on the same network, **nobody else on the WiFi can see your SSH session** because it's encrypted! 🔒
