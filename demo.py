#!/usr/bin/env python3
"""
Demo script to test VPN on localhost
Opens server and client in separate processes for quick testing
"""

import subprocess
import sys
import time
import signal
import os


def main():
    print("=" * 60)
    print("SecureVPN Local Demo")
    print("=" * 60)
    print()
    
    # Check if keys exist
    key_dir = os.path.expanduser("~/.securevpn/keys")
    if not os.path.exists(f"{key_dir}/server.key") or not os.path.exists(f"{key_dir}/client.key"):
        print("⚠ Keys not found. Generating keys...")
        print()
        subprocess.run([sys.executable, "key_manager.py"])
        print()
    
    print("Starting VPN demo on localhost...")
    print()
    print("This will:")
    print("1. Start VPN server on port 8443")
    print("2. Start VPN client connecting to localhost")
    print("3. Expose SSH proxy on port 2222")
    print()
    print("To connect: ssh -p 2222 $USER@127.0.0.1")
    print()
    print("Press Ctrl+C to stop both server and client")
    print()
    input("Press Enter to start...")
    
    # Start server
    print("\n[1/2] Starting server...")
    server_proc = subprocess.Popen(
        [sys.executable, "server.py", "--host", "127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Give server time to start
    time.sleep(2)
    
    # Start client
    print("\n[2/2] Starting client...")
    client_proc = subprocess.Popen(
        [sys.executable, "client.py", "127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Give client time to connect
    time.sleep(2)
    
    print("\n" + "=" * 60)
    print("✓ VPN tunnel established!")
    print("=" * 60)
    print()
    print("Server: localhost:8443")
    print("Client proxy: localhost:2222")
    print()
    print("Test with: ssh -p 2222 $USER@127.0.0.1")
    print()
    print("Monitoring connections... (Ctrl+C to stop)")
    print("=" * 60)
    print()
    
    # Monitor both processes
    try:
        while True:
            # Check if either process died
            if server_proc.poll() is not None:
                print("\n⚠ Server died!")
                break
            if client_proc.poll() is not None:
                print("\n⚠ Client died!")
                break
            
            # Print any output
            if server_proc.stdout:
                try:
                    line = server_proc.stdout.readline()
                    if line:
                        print(f"[SERVER] {line.rstrip()}")
                except:
                    pass
            
            if client_proc.stdout:
                try:
                    line = client_proc.stdout.readline()
                    if line:
                        print(f"[CLIENT] {line.rstrip()}")
                except:
                    pass
            
            time.sleep(0.1)
    
    except KeyboardInterrupt:
        print("\n\n⚠ Shutting down...")
    
    finally:
        # Clean shutdown
        print("Stopping server...")
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except:
            server_proc.kill()
        
        print("Stopping client...")
        client_proc.terminate()
        try:
            client_proc.wait(timeout=5)
        except:
            client_proc.kill()
        
        print("✓ Demo stopped")


if __name__ == "__main__":
    main()
