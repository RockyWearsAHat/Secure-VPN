#!/usr/bin/env python3
"""
Quick setup script for SecureVPN
"""

import subprocess
import sys
from pathlib import Path


def check_python_version():
    """Ensure Python 3.8+"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher required")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")


def install_dependencies():
    """Install required packages"""
    print("\n📦 Installing dependencies...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✓ Dependencies installed")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        sys.exit(1)


def run_tests():
    """Run test suite"""
    print("\n🧪 Running security tests...\n")
    try:
        result = subprocess.run([sys.executable, "test_security.py"])
        if result.returncode == 0:
            print("\n✓ All tests passed!")
        else:
            print("\n⚠ Some tests failed")
            return False
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return False
    return True


def setup_keys():
    """Generate initial keys"""
    print("\n🔑 Key Generation")
    print("=" * 50)
    
    response = input("Generate server and client keys now? (y/n): ").lower()
    if response == 'y':
        print()
        subprocess.run([sys.executable, "key_manager.py"])
    else:
        print("⚠ Skipping key generation")
        print("  Run 'python key_manager.py' later to generate keys")


def main():
    """Main setup flow"""
    print("=" * 50)
    print("SecureVPN Setup")
    print("=" * 50)
    
    # Check Python version
    check_python_version()
    
    # Install dependencies
    install_dependencies()
    
    # Run tests
    tests_passed = run_tests()
    
    if not tests_passed:
        print("\n⚠ Setup completed with test failures")
        print("  Review test output above for details")
    
    # Generate keys
    setup_keys()
    
    # Final instructions
    print("\n" + "=" * 50)
    print("Setup Complete!")
    print("=" * 50)
    print("\nNext steps:")
    print("1. Exchange public keys between client and server")
    print("2. On server: python server.py --host 0.0.0.0")
    print("3. On client: python client.py <SERVER_IP>")
    print("4. Connect:   ssh -p 2222 user@127.0.0.1")
    print("\nSee README.md for detailed instructions")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Setup interrupted")
        sys.exit(1)
