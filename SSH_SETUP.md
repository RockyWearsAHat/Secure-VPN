# SSH Server Setup Guide

## ✅ Your VPN is Working!

If you saw this output, your VPN is functioning perfectly:

```
✓ CLIENT_HELLO sent
✓ SERVER_HELLO received and verified
✓ CLIENT_AUTH sent
✓ Handshake complete, secure tunnel established
```

**The cryptography, authentication, and tunnel are all working correctly!** 🎉

---

## ❌ SSH Server Not Running

If you see this error on the server:

```
[127.0.0.1:xxxxx] ✗ SSH server not available at 127.0.0.1:22
```

This means **SSH is not enabled** on your machine. The VPN works, but there's no SSH server to connect to through it.

---

## 🔧 Enable SSH Server

### macOS

**Method 1: System Preferences (GUI)**

1. Open **System Preferences**
2. Click **Sharing**
3. Check the box for **Remote Login**
4. You should see "Remote Login: On"

**Method 2: Command Line**

```bash
# Enable SSH
sudo systemsetup -setremotelogin on

# Check status
sudo systemsetup -getremotelogin
# Should show: Remote Login: On
```

**Verify SSH is running:**

```bash
# Try connecting locally
ssh $USER@localhost
# or
ssh $USER@127.0.0.1

# Should prompt for password
```

### Linux

**Ubuntu/Debian:**

```bash
# Install SSH server
sudo apt update
sudo apt install openssh-server

# Start SSH service
sudo systemctl start ssh
sudo systemctl enable ssh

# Check status
sudo systemctl status ssh
```

**Fedora/RHEL/CentOS:**

```bash
# Install SSH server
sudo dnf install openssh-server

# Start SSH service
sudo systemctl start sshd
sudo systemctl enable sshd

# Check status
sudo systemctl status sshd
```

### Windows

**Windows 10/11:**

1. Open **Settings**
2. Go to **Apps** → **Optional Features**
3. Click **Add a feature**
4. Find and install **OpenSSH Server**
5. Open **Services** (services.msc)
6. Find **OpenSSH SSH Server**
7. Right-click → **Start**
8. Set Startup type to **Automatic**

**Or via PowerShell (Administrator):**

```powershell
# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start service
Start-Service sshd

# Set to start automatically
Set-Service -Name sshd -StartupType 'Automatic'

# Check status
Get-Service sshd
```

---

## ✅ Test the Complete Setup

Once SSH is enabled:

### Terminal 1: Start VPN Server

```bash
python server.py --host 127.0.0.1 --port 8443
```

You should see:

```
✓ SecureVPN server listening on 127.0.0.1:8443
✓ Forwarding to SSH server at 127.0.0.1:22
✓ Waiting for client connections...
```

### Terminal 2: Start VPN Client

```bash
python client.py 127.0.0.1 --port 8443 --local-port 2222
```

You should see:

```
✓ Handshake complete, secure tunnel established
✓ Local SSH proxy listening on 127.0.0.1:2222
✓ VPN tunnel active
```

### Terminal 3: Connect via SSH Through the VPN

```bash
ssh -p 2222 $USER@127.0.0.1
```

You should be prompted for your password and then connected!

---

## 🔍 Verify It's Working

When you SSH through the VPN:

**On the server terminal**, you'll see:

```
[127.0.0.1:xxxxx] ✓ Handshake complete, tunnel established
[127.0.0.1:xxxxx] ✓ Connected to SSH server at 127.0.0.1:22
```

This means:

1. ✅ VPN tunnel established (encrypted)
2. ✅ Connected to SSH server
3. ✅ Traffic is flowing through the encrypted tunnel!

---

## 🎯 What's Actually Happening

```
Your SSH client (Terminal 3)
         ↓
    Port 2222 (local proxy)
         ↓
    VPN Client (encrypts with ChaCha20-Poly1305)
         ↓
    Encrypted tunnel → Port 8443
         ↓
    VPN Server (decrypts)
         ↓
    SSH Server (Port 22)
```

Every byte of your SSH session is encrypted by the VPN before being sent!

---

## 🐛 Troubleshooting

### "Connection refused" on port 22

```bash
# Check if SSH is listening
sudo lsof -i :22
# or
netstat -an | grep :22

# Enable SSH (see above)
```

### "Permission denied" when SSHing

```bash
# Make sure your user can SSH
ssh $USER@localhost

# If that works, VPN should work too
```

### "Connection refused" on port 8443

```bash
# Make sure server is running
python server.py --host 127.0.0.1

# Check if it's listening
lsof -i :8443
```

### "Port 2222 already in use"

```bash
# Use different port
python client.py 127.0.0.1 --local-port 3333
ssh -p 3333 $USER@127.0.0.1
```

---

## 📊 Success Indicators

### Server Output (Good)

```
[IP:PORT] New connection
[IP:PORT] ✓ CLIENT_HELLO received
[IP:PORT] ✓ SERVER_HELLO sent
[IP:PORT] ✓ CLIENT_AUTH verified
[IP:PORT] ✓ Handshake complete, tunnel established
[IP:PORT] ✓ Connected to SSH server at 127.0.0.1:22
```

### Client Output (Good)

```
✓ Connected to VPN server
✓ CLIENT_HELLO sent
✓ SERVER_HELLO received and verified
✓ CLIENT_AUTH sent
✓ Handshake complete, secure tunnel established
✓ Local SSH proxy listening on 127.0.0.1:2222
✓ VPN tunnel active
```

### SSH Connection (Good)

```bash
$ ssh -p 2222 $USER@127.0.0.1
Password:
Last login: ...
$
```

---

## 🎉 You're Done!

Once you can SSH through the tunnel, your custom VPN is **fully operational**!

You've successfully:

- ✅ Built a VPN from scratch
- ✅ Implemented modern cryptography
- ✅ Established encrypted tunnels
- ✅ Passed all security tests
- ✅ Created a working SSH tunnel

Next steps:

- Test between your PC and laptop (see [TESTING_GUIDE.md](TESTING_GUIDE.md))
- Read about the crypto (see [CRYPTOGRAPHY_EXPLAINED.md](CRYPTOGRAPHY_EXPLAINED.md))
- Understand the protocol (see [PROTOCOL.md](PROTOCOL.md))
