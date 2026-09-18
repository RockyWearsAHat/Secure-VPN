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
from pathlib import Path as _PathType
from typing import Dict, Optional

from crypto_core import IdentityKeys, SecurityKeys, CryptoException
from protocol import SecureVPNProtocol, ProtocolError, frame_packet, parse_framed_packet
from key_manager import KeyManager
from config import load_env
from account_manager import init_account_manager, shutdown_account_manager, validate_vpn_user


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


class Roster:
    """
    Who may complete a handshake, resolved at the moment one is attempted.

    # Why this is a file the server re-reads, and not a list it was started with

    Enrolling somebody has to be possible *while the tunnel is up*. The first
    version took its peers from `--peer` flags and loaded them once in `main()`,
    which meant adding a person required restarting the VPN server — dropping
    every live tunnel, including the operator's own, to let a new one exist. That
    turns "let my dad in" into an outage, so in practice it never gets done as a
    product: it gets done by hand, over SSH, by the one person who already has
    access. Which is exactly the deadlock this whole enrolment path exists to
    break.

    So the authority is `<key-dir>/roster`: one peer name per line, `#` for
    comments, blank lines ignored. Adding a person is writing their `<name>.pub`
    into the key directory and their name into that file — two owner-only writes,
    no restart, no dropped tunnels.

    **Naming is still explicit.** The directory is never scanned for whatever
    `.pub` files happen to be sitting in it, because a file appearing in a folder
    must not be an authorisation. A name in the roster is a decision somebody
    made; a file on disk is not. Both the roster and the key directory are
    owner-only (`SYSTEM` + `Administrators` on the box), so writing either one
    already requires the privilege that could rewrite this server anyway.
    """

    def __init__(self, key_dir: Optional[str], names: list, roster_path: Optional[str]):
        self.key_manager = KeyManager(_PathType(key_dir)) if key_dir else KeyManager()
        # Names given on the command line are permanent members: they are how the
        # operator's own client stays authorised even if the roster file is lost.
        self.pinned = list(dict.fromkeys(names))
        self.roster_path = roster_path
        self._seen = None
        self._cache: Dict[str, bytes] = {}
        self._loaded_names: list = []

    def _stamp(self):
        """The roster file's identity, or None when there is no file."""
        if not self.roster_path:
            return None
        try:
            info = os.stat(self.roster_path)
            return (info.st_mtime, info.st_size)
        except OSError:
            return None

    def _names_now(self) -> list:
        """Pinned names plus whatever the roster file currently lists."""
        names = list(self.pinned)
        if self.roster_path:
            try:
                # utf-8-sig, not utf-8: PowerShell's `Set-Content -Encoding utf8`
                # writes a byte-order mark, and read as plain utf-8 that mark
                # glues itself to the first line — which turned the leading
                # comment into a peer name that no key could be found for. The
                # entry was skipped and announced, so it was cosmetic rather than
                # dangerous, but a roster an operator edits on Windows must
                # tolerate what Windows editors actually write.
                with open(self.roster_path, "r", encoding="utf-8-sig") as handle:
                    for line in handle:
                        entry = line.split("#", 1)[0].strip().lstrip("﻿").strip()
                        if entry:
                            names.append(entry)
            except OSError:
                # A missing roster is an empty one; the pinned names still stand,
                # so losing the file degrades to the previous behaviour rather
                # than locking everybody out.
                pass
        return list(dict.fromkeys(names))

    def current(self) -> Dict[str, bytes]:
        """
        The authorised {name: public key} map, reloaded when the roster changed.

        A name whose `.pub` cannot be read is skipped and announced rather than
        being fatal: one unreadable key must not take the tunnel down for
        everybody else.
        """
        stamp = self._stamp()
        if stamp != self._seen or not self._cache:
            names = self._names_now()
            fresh: Dict[str, bytes] = {}
            for name in names:
                try:
                    fresh[name] = self.key_manager.load_peer_public_key(name)
                except (FileNotFoundError, ValueError) as error:
                    print(f"roster: {name}: {error} — skipped")
            if names != self._loaded_names:
                print(f"roster: {len(fresh)} authorised client(s): {', '.join(sorted(fresh))}")
                self._loaded_names = names
            self._cache = fresh
            self._seen = stamp
        return self._cache


class VPNServer:
    """
    VPN server that accepts connections and tunnels to local SSH.
    """

    def __init__(
        self,
        identity: IdentityKeys,
        roster: "Roster",
        listen_host: str = "0.0.0.0",
        listen_port: int = 8443,
        ssh_host: str = "127.0.0.1",
        ssh_port: int = 22,
        location: str = "console",
    ):
        """
        Initialize VPN server.

        Args:
            identity: Server identity keys
            roster: Who may connect, resolved per handshake — see [`Roster`].
                One entry per person, never one entry shared between people: the
                name is what the log line reports and what removing an entry
                revokes, and a key two people hold is a key neither of them can
                be held to.
            listen_host: Host to listen on
            listen_port: Port to listen on
            ssh_host: Local SSH server host
            ssh_port: Local SSH server port
            location: Which VPN location this instance answers to when it
                asks the account-manager. One relay process is one location
                (`console`, `ssh`, ...); a peer authorised on the tunnel
                still needs `vpn.access:<location>` granted on the admin
                side for *this* location specifically.

        Raises:
            ValueError: If the roster is empty at start-up. A server with no
                authorised peer is refused rather than started, because the
                failure it would otherwise produce — every handshake rejected —
                looks exactly like a client misconfiguration and gets debugged
                from the wrong end. It may legitimately become empty later, by
                the operator revoking everybody; that is a running server with
                nobody authorised, which is a different and intended thing.
        """
        if not roster.current():
            raise ValueError("the roster is empty: no client could ever connect")
        self.identity = identity
        self.roster = roster
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.location = location
        self.server: Optional[asyncio.Server] = None
        self.active_connections = 0
        # Hard ceiling on concurrent connections and an overall wall-clock bound
        # on the (pre-authentication) handshake. Without these, an unauthenticated
        # attacker on the public listener can hold sockets open by dribbling one
        # byte per read (each read resets its own timeout) and exhaust file
        # descriptors / event-loop tasks — a trivial remote denial of service on
        # the only internet-facing port. Neither limit affects a legitimate client.
        self.max_connections = 256
        self.handshake_timeout = 30.0

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

        # Refuse new connections once at capacity, before counting this one, so a
        # flood of stalled pre-auth sockets cannot starve legitimate clients.
        if self.active_connections >= self.max_connections:
            print(f"[{conn_id}] Refused: connection limit ({self.max_connections}) reached")
            try:
                writer.close()
            except Exception:
                pass
            return

        self.active_connections += 1

        print(f"[{conn_id}] New connection")

        try:
            # Perform handshake under an overall wall-clock deadline. The per-read
            # timeout inside perform_handshake resets on every byte received, so
            # only this outer bound actually caps a slow-drip handshake.
            result = await asyncio.wait_for(
                self.perform_handshake(reader, writer, conn_id),
                timeout=self.handshake_timeout,
            )

            if result is None:
                print(f"[{conn_id}] Handshake failed")
                return

            session_keys, leftover = result
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
            
            # Tunnel traffic bidirectionally, seeding any request bytes the
            # handshake over-read past CLIENT_AUTH.
            await self.tunnel_traffic(reader, writer, ssh_reader, ssh_writer, session_keys, conn_id, leftover)

        except asyncio.TimeoutError:
            print(f"[{conn_id}] Handshake deadline exceeded ({self.handshake_timeout}s) - dropped")
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
    ) -> Optional[tuple]:
        """
        Perform server-side handshake.

        Returns:
            (SecurityKeys, leftover_bytes) on success, None on failure.
            leftover_bytes are any bytes read past CLIENT_AUTH — the client's
            first DATA packet(s) can arrive coalesced in the same TCP segment,
            and dropping them would strand the first request forever.
        """
        protocol = SecureVPNProtocol(self.identity, peer_roster=self.roster.current())
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

            # Name the peer as soon as the key is recognised. Which person is on
            # the tunnel is the fact this log exists to record, and it is the
            # only way an operator can tell two authorised clients apart.
            print(f"[{conn_id}] ✓ CLIENT_HELLO received from peer '{state.peer_name}'")
            
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

                # Validate user against account-manager
                user_id = state.peer_name
                client_ip = writer.get_extra_info('peername')[0] if writer.get_extra_info('peername') else 'unknown'

                validation = await validate_vpn_user(user_id, self.location, client_ip)

                if validation.get('valid'):
                    print(f"[{conn_id}] ✓ User '{user_id}' validated by account-manager")
                    # `buffer` now holds anything read past CLIENT_AUTH — hand it to
                    # the tunnel so a coalesced first request is not lost.
                    return session_keys, buffer
                else:
                    print(f"[{conn_id}] ✗ User '{user_id}' denied by account-manager: {validation.get('reason')}")
                    return None
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
        conn_id: str,
        initial_buffer: bytes = b"",
    ):
        """
        Bidirectional tunnel between VPN and SSH.

        initial_buffer carries any VPN bytes the handshake over-read (the first
        DATA packet can arrive coalesced with CLIENT_AUTH); it is decoded before
        reading further from the socket.
        """
        protocol = SecureVPNProtocol(self.identity, peer_roster=self.roster.current())
        vpn_buffer = initial_buffer
        bytes_tx = 0
        bytes_rx = 0
        
        async def vpn_to_ssh():
            """Forward decrypted VPN traffic to SSH"""
            nonlocal vpn_buffer, bytes_rx

            async def drain_buffer():
                """Decode and forward every complete packet already buffered."""
                nonlocal vpn_buffer, bytes_rx
                while True:
                    packet, vpn_buffer = parse_framed_packet(vpn_buffer)
                    if packet is None:
                        break
                    payload = protocol.parse_data_packet(packet, session_keys)
                    bytes_rx += len(payload)
                    ssh_writer.write(payload)
                    await ssh_writer.drain()

            try:
                # Process any bytes carried over from the handshake first, so a
                # request coalesced with CLIENT_AUTH is forwarded without waiting
                # for a further read that may never come.
                await drain_buffer()

                while True:
                    data = await vpn_reader.read(8192)
                    if not data:
                        break

                    vpn_buffer += data
                    await drain_buffer()

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
    parser.add_argument("--peer", action="append", metavar="NAME",
                        help="Authorised client identity, by key name. Repeat it once per "
                             "person: --peer client --peer dad. Each name must have a "
                             "<name>.pub in the key directory. Defaults to the single peer "
                             "'client', or to SECUREVPN_SERVER_PEER, which may be a "
                             "comma-separated list.")
    parser.add_argument("--roster", metavar="FILE",
                        help="File listing authorised client names, one per line, re-read on "
                             "every handshake so a person can be enrolled without restarting "
                             "the tunnel. Default: <key-dir>/roster.")
    parser.add_argument("--password", help="Password for encrypted identity key")
    parser.add_argument("--key-dir", default=os.getenv("SECUREVPN_KEY_DIR"),
                        help="Directory holding identity/peer keys (default: ~/.securevpn/keys)")
    parser.add_argument("--account-manager", default=os.getenv("SECUREVPN_ACCOUNT_MANAGER", "http://127.0.0.1:9191"),
                        help="Base URL of the selfhost admin API's loopback listener, which "
                             "answers whether a peer may use this location (default: "
                             "http://127.0.0.1:9191, i.e. server.admin_bind)")
    parser.add_argument("--account-manager-token-file", default=os.getenv("SECUREVPN_ACCOUNT_MANAGER_TOKEN_FILE"),
                        help="Path to the deployment's admin bearer token (<data_dir>/admin.token). "
                             "A path, never the secret itself, on the command line — the same "
                             "posture --key-dir already has.")
    parser.add_argument("--location", default=os.getenv("SECUREVPN_LOCATION", "console"),
                        help="Which VPN location this relay is, for the vpn.access:<location> "
                             "grant the admin API checks (default: console)")
    args = parser.parse_args()

    if not args.password:
        args.password = os.getenv("SECUREVPN_SERVER_PASSWORD")
    
    # Load keys
    from pathlib import Path as _Path
    km = KeyManager(_Path(args.key_dir)) if args.key_dir else KeyManager()
    
    try:
        print("Loading server identity...")
        identity = km.load_identity(args.identity, args.password)
        print("✓ Server identity loaded")
        
        # Pinned peers: the `--peer` flags, or the env var, or the historical
        # single peer 'client'. These stay authorised even if the roster file is
        # deleted, which is what keeps the operator's own client from being
        # locked out by a lost or corrupted file.
        pinned = args.peer or [
            name.strip()
            for name in os.getenv("SECUREVPN_SERVER_PEER", "client").split(",")
            if name.strip()
        ]
        # Everybody else is enrolled through the roster file, which is re-read
        # per handshake so adding a person never costs a restart.
        roster_path = args.roster
        if roster_path is None:
            base = args.key_dir or str(KeyManager.DEFAULT_KEY_DIR)
            roster_path = str(_PathType(base) / "roster")

        roster = Roster(args.key_dir, pinned, roster_path)
        print(f"Roster file: {roster_path}")
        if not roster.current():
            print("Error: nobody is authorised; the server would refuse every client.")
            sys.exit(1)
        print()
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
        roster=roster,
        listen_host=args.host,
        listen_port=args.port,
        ssh_host=args.ssh_host,
        ssh_port=args.ssh_port,
        location=args.location,
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
        # Initialize account manager. No token file means every check below
        # fails closed (the admin API refuses an unauthenticated request the
        # same way it refuses a wrong one) — loud in the log, not fatal here.
        if not args.account_manager_token_file:
            print(
                "⚠ --account-manager-token-file not set; every connection will be "
                "denied by the admin API (fail-secure)"
            )
        await init_account_manager(args.account_manager, args.account_manager_token_file or "")
        print(f"✓ Account manager: {args.account_manager} (location: {args.location})\n")

        with SSHServiceManager(args.ssh_host, args.ssh_port):
            await server.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)
    finally:
        await shutdown_account_manager()


if __name__ == "__main__":
    asyncio.run(main())
