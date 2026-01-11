"""
SecureVPN Server

Accepts VPN connections and forwards traffic to local SSH server.
"""

import asyncio
import os
import platform
import signal
import subprocess
import sys
from contextlib import AbstractContextManager
from typing import Optional

from crypto_core import IdentityKeys, SecurityKeys, CryptoException
from protocol import SecureVPNProtocol, ProtocolError, frame_packet, parse_framed_packet
from key_manager import KeyManager
from config import load_env


class SSHServiceManager(AbstractContextManager["SSHServiceManager"]):
    """Manage the lifecycle of the local SSH service when targeting localhost."""

    def __init__(self, ssh_host: str, ssh_port: int) -> None:
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.initial_state: Optional[bool] = None
        self.managed = False

    def __enter__(self) -> "SSHServiceManager":
        if not self._should_manage():
            return self

        self.initial_state = self._get_state()

        if self.initial_state is False:
            if self._can_manage():
                if self._set_state(True):
                    self.managed = True
                    print("✓ SSH service started automatically")
                else:
                    self._warn_manual_enable()
            else:
                self._warn_manual_enable()

        return self

    def __exit__(self, exc_type, exc, exc_tb) -> bool:
        if self.managed and self.initial_state is False and self._can_manage():
            if self._set_state(False):
                print("✓ SSH service restored to original state")
            else:
                print("⚠ Unable to restore SSH service to previous state; please disable it manually if desired")
        return False

    def _should_manage(self) -> bool:
        return self.ssh_host in {"127.0.0.1", "localhost", "::1"}

    def _can_manage(self) -> bool:
        if platform.system() in {"Darwin", "Linux"}:
            try:
                return os.geteuid() == 0
            except AttributeError:
                return False
        return False

    def _get_state(self) -> Optional[bool]:
        system = platform.system()
        if system == "Darwin":
            return self._get_state_mac()
        if system == "Linux":
            return self._get_state_linux()
        return None

    def _set_state(self, enabled: bool) -> bool:
        system = platform.system()
        if system == "Darwin":
            return self._set_state_mac(enabled)
        if system == "Linux":
            return self._set_state_linux(enabled)
        return False

    def _warn_manual_enable(self) -> None:
        print("⚠ SSH service is disabled. Enable it manually to allow tunnelling (for example: enable Remote Login or start the sshd service).")

    def _run_command(self, command: list[str]) -> Optional[subprocess.CompletedProcess[str]]:
        try:
            return subprocess.run(command, capture_output=True, text=True)
        except FileNotFoundError:
            return None

    def _get_state_mac(self) -> Optional[bool]:
        result = self._run_command(["/usr/sbin/systemsetup", "-getremotelogin"])
        if result is None:
            print("⚠ Unable to inspect SSH service; /usr/sbin/systemsetup not found")
            return None
        if result.returncode != 0:
            return None
        output = result.stdout.strip().lower()
        if "on" in output:
            return True
        if "off" in output:
            return False
        return None

    def _set_state_mac(self, enabled: bool) -> bool:
        command = ["/usr/sbin/systemsetup", "-setremotelogin", "on" if enabled else "off"]
        result = self._run_command(command)
        if result is None or result.returncode != 0:
            if result and result.stderr.strip():
                print(f"⚠ Failed to modify SSH service: {result.stderr.strip()}")
            return False
        return True

    def _get_state_linux(self) -> Optional[bool]:
        checker = self._run_command(["/bin/systemctl", "is-active", "sshd"])
        if checker is None:
            checker = self._run_command(["/bin/systemctl", "is-active", "ssh"])
        if checker is None:
            return None
        if checker.returncode == 0:
            return True
        if checker.returncode == 3:  # inactive
            return False
        return None

    def _set_state_linux(self, enabled: bool) -> bool:
        unit_names = ["sshd", "ssh"]
        action = "start" if enabled else "stop"
        for unit in unit_names:
            result = self._run_command(["/bin/systemctl", action, unit])
            if result and result.returncode == 0:
                return True
        return False


class VPNServer:
    """
    VPN server that accepts connections and tunnels to local SSH.
    """
    
    def __init__(
        self,
        identity: IdentityKeys,
        peer_public_key: bytes,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8443,
        ssh_host: str = "127.0.0.1",
        ssh_port: int = 22
    ):
        """
        Initialize VPN server.
        
        Args:
            identity: Server identity keys
            peer_public_key: Expected client public key (32 bytes)
            listen_host: Host to listen on
            listen_port: Port to listen on
            ssh_host: Local SSH server host
            ssh_port: Local SSH server port
        """
        self.identity = identity
        self.peer_public_key = peer_public_key
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.server: Optional[asyncio.Server] = None
        self.active_connections = 0
    
    async def start(self):
        """Start the VPN server."""
        self.server = await asyncio.start_server(
            self.handle_client,
            self.listen_host,
            self.listen_port
        )
        
        addr = self.server.sockets[0].getsockname()
        print(f"✓ SecureVPN server listening on {addr[0]}:{addr[1]}")
        print(f"✓ Forwarding to SSH server at {self.ssh_host}:{self.ssh_port}")
        print("✓ Waiting for client connections...\n")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Handle a single client connection.
        
        Args:
            reader: Async stream reader
            writer: Async stream writer
        """
        client_addr = writer.get_extra_info('peername')
        conn_id = f"{client_addr[0]}:{client_addr[1]}"
        self.active_connections += 1
        
        print(f"[{conn_id}] New connection")
        
        try:
            # Perform handshake
            session_keys = await self.perform_handshake(reader, writer, conn_id)
            
            if session_keys is None:
                print(f"[{conn_id}] Handshake failed")
                return
            
            print(f"[{conn_id}] ✓ Handshake complete, tunnel established")
            
            # Create SSH connection
            try:
                ssh_reader, ssh_writer = await asyncio.open_connection(self.ssh_host, self.ssh_port)
                print(f"[{conn_id}] ✓ Connected to SSH server at {self.ssh_host}:{self.ssh_port}")
            except ConnectionRefusedError:
                print(f"[{conn_id}] ✗ SSH server not available at {self.ssh_host}:{self.ssh_port}")
                print(f"[{conn_id}]   Enable SSH: System Preferences → Sharing → Remote Login")
                return
            except Exception as e:
                print(f"[{conn_id}] ✗ Failed to connect to SSH: {e}")
                return
            
            # Tunnel traffic bidirectionally
            await self.tunnel_traffic(reader, writer, ssh_reader, ssh_writer, session_keys, conn_id)
            
        except Exception as e:
            print(f"[{conn_id}] Error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            self.active_connections -= 1
            print(f"[{conn_id}] Connection closed (active: {self.active_connections})")
    
    async def perform_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        conn_id: str
    ) -> Optional[SecurityKeys]:
        """
        Perform server-side handshake.
        
        Returns:
            SecurityKeys on success, None on failure
        """
        protocol = SecureVPNProtocol(self.identity, self.peer_public_key)
        buffer = b""
        
        try:
            # Step 1: Receive CLIENT_HELLO
            print(f"[{conn_id}] Waiting for CLIENT_HELLO...")
            
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=30.0)
                if not data:
                    raise ProtocolError("Connection closed during handshake")
                
                buffer += data
                packet, buffer = parse_framed_packet(buffer)
                
                if packet:
                    break
            
            # Process CLIENT_HELLO and generate SERVER_HELLO
            server_hello, state, session_keys = protocol.process_client_hello(packet)
            
            print(f"[{conn_id}] ✓ CLIENT_HELLO received")
            
            # Step 2: Send SERVER_HELLO
            writer.write(frame_packet(server_hello))
            await writer.drain()
            
            print(f"[{conn_id}] ✓ SERVER_HELLO sent")
            
            # Step 3: Receive CLIENT_AUTH
            print(f"[{conn_id}] Waiting for CLIENT_AUTH...")
            
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=30.0)
                if not data:
                    raise ProtocolError("Connection closed during handshake")
                
                buffer += data
                packet, buffer = parse_framed_packet(buffer)
                
                if packet:
                    break
            
            # Verify CLIENT_AUTH
            if protocol.process_client_auth(packet, state, session_keys):
                print(f"[{conn_id}] ✓ CLIENT_AUTH verified")
                return session_keys
            else:
                print(f"[{conn_id}] ✗ CLIENT_AUTH verification failed")
                return None
        
        except asyncio.TimeoutError:
            print(f"[{conn_id}] Handshake timeout")
            return None
        except (ProtocolError, CryptoException) as e:
            print(f"[{conn_id}] Handshake error: {e}")
            return None
    
    async def tunnel_traffic(
        self,
        vpn_reader: asyncio.StreamReader,
        vpn_writer: asyncio.StreamWriter,
        ssh_reader: asyncio.StreamReader,
        ssh_writer: asyncio.StreamWriter,
        session_keys: SecurityKeys,
        conn_id: str
    ):
        """
        Bidirectional tunnel between VPN and SSH.
        """
        protocol = SecureVPNProtocol(self.identity, self.peer_public_key)
        vpn_buffer = b""
        bytes_tx = 0
        bytes_rx = 0
        
        async def vpn_to_ssh():
            """Forward decrypted VPN traffic to SSH"""
            nonlocal vpn_buffer, bytes_rx
            
            try:
                while True:
                    data = await vpn_reader.read(8192)
                    if not data:
                        break
                    
                    vpn_buffer += data
                    
                    # Process all complete packets in buffer
                    while True:
                        packet, vpn_buffer = parse_framed_packet(vpn_buffer)
                        if packet is None:
                            break
                        
                        # Decrypt packet
                        payload = protocol.parse_data_packet(packet, session_keys)
                        bytes_rx += len(payload)
                        
                        # Forward to SSH
                        ssh_writer.write(payload)
                        await ssh_writer.drain()
            
            except Exception as e:
                print(f"[{conn_id}] VPN->SSH error: {e}")
            finally:
                ssh_writer.close()
        
        async def ssh_to_vpn():
            """Forward SSH traffic to encrypted VPN"""
            nonlocal bytes_tx
            
            try:
                while True:
                    data = await ssh_reader.read(8192)
                    if not data:
                        break
                    
                    # Encrypt and send
                    encrypted = protocol.create_data_packet(data, session_keys)
                    framed = frame_packet(encrypted)
                    bytes_tx += len(data)
                    
                    vpn_writer.write(framed)
                    await vpn_writer.drain()
            
            except Exception as e:
                print(f"[{conn_id}] SSH->VPN error: {e}")
            finally:
                vpn_writer.close()
        
        # Run both directions concurrently
        await asyncio.gather(vpn_to_ssh(), ssh_to_vpn(), return_exceptions=True)
        
        print(f"[{conn_id}] Tunnel closed (TX: {bytes_tx} bytes, RX: {bytes_rx} bytes)")


async def main():
    """Main server entry point"""
    import argparse
    
    load_env()

    parser = argparse.ArgumentParser(description="SecureVPN Server")
    parser.add_argument("--host", default=os.getenv("SECUREVPN_SERVER_HOST", "0.0.0.0"), help="Listen host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("SECUREVPN_SERVER_PORT", "8443")), help="Listen port (default: 8443)")
    parser.add_argument("--ssh-host", default=os.getenv("SECUREVPN_SERVER_SSH_HOST", "127.0.0.1"), help="SSH server host (default: 127.0.0.1)")
    parser.add_argument("--ssh-port", type=int, default=int(os.getenv("SECUREVPN_SERVER_SSH_PORT", "22")), help="SSH server port (default: 22)")
    parser.add_argument("--identity", default=os.getenv("SECUREVPN_SERVER_IDENTITY", "server"), help="Identity name (default: server)")
    parser.add_argument("--peer", default=os.getenv("SECUREVPN_SERVER_PEER", "client"), help="Peer name (default: client)")
    parser.add_argument("--password", help="Password for encrypted identity key")
    args = parser.parse_args()

    if not args.password:
        args.password = os.getenv("SECUREVPN_SERVER_PASSWORD")
    
    # Load keys
    km = KeyManager()
    
    try:
        print("Loading server identity...")
        identity = km.load_identity(args.identity, args.password)
        print("✓ Server identity loaded")
        
        print("Loading client public key...")
        peer_pubkey = km.load_peer_public_key(args.peer)
        print("✓ Client public key loaded\n")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("\nRun key_manager.py first to generate keys.")
        sys.exit(1)
    except CryptoException as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Start server
    server = VPNServer(
        identity=identity,
        peer_public_key=peer_pubkey,
        listen_host=args.host,
        listen_port=args.port,
        ssh_host=args.ssh_host,
        ssh_port=args.ssh_port
    )

    # Handle graceful shutdown
    loop = asyncio.get_event_loop()

    def signal_handler():
        print("\n\n⚠ Shutting down server...")
        if server.server:
            server.server.close()
        loop.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            pass

    try:
        with SSHServiceManager(args.ssh_host, args.ssh_port):
            await server.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
