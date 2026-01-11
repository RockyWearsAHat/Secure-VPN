#!/usr/bin/env python3
"""
Quick test script - Tests VPN locally on one machine

This script makes it easy to test the VPN by running both
server and client on the same machine automatically.
"""

import subprocess
import sys
import time
import os
from pathlib import Path


def check_keys():
    """Verify keys exist"""
    key_dir = Path.home() / ".securevpn" / "keys"
    
    required_files = ["server.key", "server.pub", "client.key", "client.pub"]
    missing = []
    
    for file in required_files:
        if not (key_dir / file).exists():
            missing.append(file)
    
    if missing:
        print("❌ Missing keys:", ", ".join(missing))
        print("\nGenerate keys first:")
        print("  python key_manager.py")
        return False
    
    print("✓ All keys found")
    return True


def check_ssh_server():
    """Check if SSH server is running"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', 22))
    sock.close()
    
    if result != 0:
        print("⚠ Warning: SSH server not detected on port 22")
        print("  The VPN will work, but you won't be able to SSH through it")
        print("  Start SSH server with: sudo systemsetup -setremotelogin on (macOS)")
        return False
    
    print("✓ SSH server running on port 22")
    return True


def main():
    print("=" * 60)
    print("SecureVPN Local Test")
    print("=" * 60)
    print()
    
    # Check prerequisites
    if not check_keys():
        sys.exit(1)
    
    check_ssh_server()
    
    print()
    print("This will start:")
    print("  1. VPN Server on 127.0.0.1:8443")
    print("  2. VPN Client connecting to server")
    print("  3. Local SSH proxy on 127.0.0.1:2222")
    print()
    print("Test with: ssh -p 2222 $USER@127.0.0.1")
    print("Press Ctrl+C to stop")
    print()
    
    # Start server in background
    print("[1/2] Starting server...")
    server_proc = subprocess.Popen(
        [sys.executable, "server.py", "--host", "127.0.0.1", "--port", "8443"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    # Wait for server to start
    time.sleep(2)
    
    # Check if server started successfully
    if server_proc.poll() is not None:
        print("❌ Server failed to start!")
        output, _ = server_proc.communicate()
        print(output)
        sys.exit(1)
    
    print("✓ Server started")
    
    # Start client
    print("[2/2] Starting client...")
    client_proc = subprocess.Popen(
        [sys.executable, "client.py", "127.0.0.1", "--port", "8443", "--local-port", "2222"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    # Wait for client to connect
    time.sleep(2)
    
    # Check if client connected
    if client_proc.poll() is not None:
        print("❌ Client failed to start!")
        output, _ = client_proc.communicate()
        print(output)
        server_proc.terminate()
        sys.exit(1)
    
    print("✓ Client connected")
    print()
    print("=" * 60)
    print("✓ VPN Tunnel Active!")
    print("=" * 60)
    print()
    print("Test connection:")
    print(f"  ssh -p 2222 {os.getenv('USER', 'your_username')}@127.0.0.1")
    print()
    print("Press Ctrl+C to stop...")
    print()
    
    # Keep running until interrupted
    try:
        server_proc.wait()
        client_proc.wait()
    except KeyboardInterrupt:
        print("\n\n⚠ Stopping...")
        server_proc.terminate()
        client_proc.terminate()
        server_proc.wait()
        client_proc.wait()
        print("✓ Stopped")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n✓ Stopped")
