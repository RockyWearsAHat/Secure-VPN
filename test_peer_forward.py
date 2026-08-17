"""
Per-peer forward tests — the tunnel saying *who*, not just letting them in.

The server has always known which person is on a session: CLIENT_HELLO selects a
roster entry by the identity key presented, CLIENT_AUTH proves possession of the
matching private key, and `HandshakeState.peer_name` carries the answer. What it
did with that answer was print it. Every authorised session was then forwarded to
the same `--ssh-host`/`--ssh-port`, so whatever received them saw one loopback
connection from 127.0.0.1 per person and could not tell two people apart. That is
why the tunnel could admit people to a network and still not be usable as a
permissions layer by anything above it.

`--peer-forward NAME=HOST:PORT` spends the answer instead of discarding it: that
peer's sessions land on that socket, so the destination port *is* the roster
entry. The tests below hold down the three things that makes true:

- the mapping is read exactly as written, and a mapping that cannot mean one
  person is refused before a socket is bound;
- a peer with no mapping keeps the behaviour it has today, so a live deployment
  is not forced to migrate everybody in one edit;
- and, end to end through a real handshake on a real socket, two authorised
  peers' bytes come out of two different local listeners.

That last one is the point of the exercise. Everything else could pass while the
carry stayed inert, which is exactly the state this flag was written to end.
"""

import asyncio
import socket
import tempfile
import shutil
import unittest
from pathlib import Path

from crypto_core import IdentityKeys
from key_manager import KeyManager
from protocol import SecureVPNProtocol, frame_packet, parse_framed_packet

import server as server_module
from server import Roster, VPNServer, parse_peer_forwards


class TunnelClosed(Exception):
    """The tunnel hung up before answering — what a refused handshake looks like."""


def free_port() -> int:
    """
    A port nothing is listening on, asked of the kernel rather than picked.

    Fixed port numbers in a test suite fail on whichever machine already runs
    something there, and the failure looks like the code under test.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class TestParsingPeerForwards(unittest.TestCase):
    """
    `NAME=HOST:PORT` into {name: (host, port)} — and what is refused.

    Every refusal here has the same shape behind it: a mapping that survives but
    does not name one person is worse than one that is rejected, because the
    deployment then records an attribution nobody can trust while the config file
    claims otherwise.
    """

    def test_a_peer_is_given_its_own_socket(self):
        self.assertEqual(
            parse_peer_forwards(["alex-mac=127.0.0.1:9443"]),
            {"alex-mac": ("127.0.0.1", 9443)},
        )

    def test_the_flag_repeats_once_per_person(self):
        self.assertEqual(
            parse_peer_forwards(["alex-mac=127.0.0.1:9443", "dad-mac=127.0.0.1:9444"]),
            {"alex-mac": ("127.0.0.1", 9443), "dad-mac": ("127.0.0.1", 9444)},
        )

    def test_nothing_given_is_the_behaviour_that_existed_before_this_flag(self):
        self.assertEqual(parse_peer_forwards(None), {})
        self.assertEqual(parse_peer_forwards([]), {})

    def test_an_ipv6_socket_is_read_as_one_address_and_one_port(self):
        """
        A v6 address is full of the character the port is split on, so the
        bracketed form has to be read before the last colon means anything.
        """
        self.assertEqual(
            parse_peer_forwards(["alex-mac=[::1]:9443"]),
            {"alex-mac": ("::1", 9443)},
        )

    def test_a_spec_that_is_not_name_equals_socket_is_refused(self):
        for spec in ("alex-mac", "=127.0.0.1:9443", "alex-mac=", "alex-mac=127.0.0.1"):
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    parse_peer_forwards([spec])

    def test_a_port_that_is_not_a_port_is_refused(self):
        for spec in ("alex-mac=127.0.0.1:https", "alex-mac=127.0.0.1:0",
                     "alex-mac=127.0.0.1:65536", "alex-mac=[::1]9443"):
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    parse_peer_forwards([spec])

    def test_the_same_peer_twice_is_refused_rather_than_resolved(self):
        """
        One of the two would win by argument order, so which socket a person
        lands on — and therefore which port names them — would depend on how the
        command line happened to be assembled.
        """
        with self.assertRaises(ValueError) as refusal:
            parse_peer_forwards(["alex-mac=127.0.0.1:9443", "alex-mac=127.0.0.1:9444"])
        self.assertIn("already has a forward", str(refusal.exception))

    def test_two_peers_behind_one_socket_is_refused(self):
        """
        The whole claim of this feature is that a port names one person. Two
        people on one port is two people with one identity, which is the finding
        this flag exists to answer, reintroduced through the flag itself.
        """
        with self.assertRaises(ValueError) as refusal:
            parse_peer_forwards(["alex-mac=127.0.0.1:9443", "dad-mac=127.0.0.1:9443"])
        self.assertIn("names neither of them", str(refusal.exception))


class TestChoosingTheForward(unittest.TestCase):
    """
    Which socket a session lands on, given the peer the handshake resolved to.

    No sockets here: `forward_for` is the whole decision, and it is a function of
    the name and the mapping.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.keys = Path(self.tmp) / "keys"
        km = KeyManager(self.keys)
        self.identity = km.generate_identity("server")
        km.generate_identity("alex-mac")
        self.roster = Roster(str(self.keys), ["alex-mac"], str(self.keys / "roster"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_server(self, peer_forwards=None, listen_host="127.0.0.1", listen_port=8443):
        return VPNServer(
            identity=self.identity,
            roster=self.roster,
            listen_host=listen_host,
            listen_port=listen_port,
            ssh_host="127.0.0.1",
            ssh_port=443,
            peer_forwards=peer_forwards,
        )

    def test_a_peer_with_its_own_socket_lands_on_it(self):
        vpn = self.make_server({"alex-mac": ("127.0.0.1", 9443)})
        self.assertEqual(vpn.forward_for("alex-mac"), ("127.0.0.1", 9443))

    def test_a_peer_with_no_socket_lands_where_it_always_did(self):
        """
        The mixed roster. This tunnel is somebody's only way in, so a change that
        demanded every peer be migrated in one edit would demand it of a live
        deployment whose operator is on the far side of it.
        """
        vpn = self.make_server({"alex-mac": ("127.0.0.1", 9443)})
        self.assertEqual(vpn.forward_for("dad-mac"), ("127.0.0.1", 443))

    def test_a_server_with_no_forwards_at_all_is_unchanged(self):
        vpn = self.make_server()
        self.assertEqual(vpn.forward_for("alex-mac"), ("127.0.0.1", 443))
        self.assertEqual(vpn.peer_forwards, {})

    def test_the_single_peer_shape_has_no_name_and_uses_the_shared_forward(self):
        """
        Started with one key rather than a roster, `peer_name` is None: there is
        no entry to look up, and the shared forward is the only answer.
        """
        vpn = self.make_server({"alex-mac": ("127.0.0.1", 9443)})
        self.assertEqual(vpn.forward_for(None), ("127.0.0.1", 443))

    def test_a_forward_pointing_at_the_tunnels_own_listener_is_refused(self):
        """
        A session handed straight back into the tunnel, and a plausible typo: the
        listen port is the one number a peer's own configuration already holds.
        """
        with self.assertRaises(ValueError) as refusal:
            self.make_server({"alex-mac": ("127.0.0.1", 8443)}, listen_port=8443)
        self.assertIn("own listener", str(refusal.exception))

    def test_a_wildcard_listener_is_also_reachable_at_loopback(self):
        """
        Bound to 0.0.0.0, the server answers on every local address — so
        127.0.0.1 on the listen port is the same socket under another name, and
        an equality test on the host would have let it through.
        """
        with self.assertRaises(ValueError):
            self.make_server({"alex-mac": ("127.0.0.1", 8443)},
                             listen_host="0.0.0.0", listen_port=8443)

    def test_a_different_port_on_the_listen_host_is_fine(self):
        vpn = self.make_server({"alex-mac": ("127.0.0.1", 9443)},
                               listen_host="0.0.0.0", listen_port=8443)
        self.assertEqual(vpn.forward_for("alex-mac"), ("127.0.0.1", 9443))


class TestTheCarryEndToEnd(unittest.IsolatedAsyncioTestCase):
    """
    Two authorised people, one tunnel, two destinations — over real sockets.

    This is the test that can tell the difference between the feature working and
    the feature being written down. It stands three ordinary TCP listeners up as
    the destinations, runs the real `VPNServer` in this process, drives two full
    handshakes with two different identity keys, and reads back which listener
    each peer's bytes actually reached.
    """

    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp()
        self.keys = Path(self.tmp) / "keys"
        km = KeyManager(self.keys)

        self.server_identity = km.generate_identity("server")
        self.alex = km.generate_identity("alex-mac")
        self.dad = km.generate_identity("dad-mac")
        self.guest = km.generate_identity("guest-mac")

        # Three destinations: one per attributed peer, and the shared forward
        # everybody else still lands on. Each announces which one it is, so the
        # assertion reads the same fact a local service would.
        self.alex_port = free_port()
        self.dad_port = free_port()
        self.shared_port = free_port()
        self.destinations = []
        for label, port in (("alex", self.alex_port), ("dad", self.dad_port),
                            ("shared", self.shared_port)):
            self.destinations.append(await self.destination(label, port))

        roster = Roster(str(self.keys), ["alex-mac", "dad-mac", "guest-mac"],
                        str(self.keys / "roster"))
        self.listen_port = free_port()
        self.vpn = VPNServer(
            identity=self.server_identity,
            roster=roster,
            listen_host="127.0.0.1",
            listen_port=self.listen_port,
            ssh_host="127.0.0.1",
            ssh_port=self.shared_port,
            peer_forwards={
                "alex-mac": ("127.0.0.1", self.alex_port),
                "dad-mac": ("127.0.0.1", self.dad_port),
            },
        )
        self.vpn.server = await asyncio.start_server(
            self.vpn.handle_client, "127.0.0.1", self.listen_port
        )

    async def asyncTearDown(self):
        for listener in [self.vpn.server, *self.destinations]:
            listener.close()
            # Bounded: `wait_closed` waits for every connection as well as the
            # listener, so a session the server failed to let go of would
            # otherwise hang the whole suite instead of failing one test.
            await asyncio.wait_for(listener.wait_closed(), timeout=10)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def destination(self, label: str, port: int):
        """
        A listener that says which one it is to whoever reaches it, then hangs
        up — the shape of a local service answering one request.
        """
        async def announce(reader, writer):
            writer.write(f"reached:{label}".encode())
            await writer.drain()
            writer.close()

        return await asyncio.start_server(announce, "127.0.0.1", port)

    async def dial(self, identity: IdentityKeys) -> str:
        """
        A full client session: handshake, one DATA packet, one answer.

        Deliberately not `client.py`: this drives the protocol directly so that a
        failure here is the server's, and so the test cannot be satisfied by the
        client and server sharing a mistake about where a session went.
        """
        reader, writer = await asyncio.open_connection("127.0.0.1", self.listen_port)
        try:
            protocol = SecureVPNProtocol(identity, self.server_identity.get_public_bytes())
            hello, state = protocol.create_client_hello()
            writer.write(frame_packet(hello))
            await writer.drain()

            buffer = b""

            async def next_packet():
                nonlocal buffer
                while True:
                    packet, remaining = parse_framed_packet(buffer)
                    if packet is not None:
                        buffer = remaining
                        return packet
                    chunk = await reader.read(4096)
                    if not chunk:
                        raise TunnelClosed("the tunnel closed before answering")
                    buffer += chunk

            session_keys = protocol.process_server_hello(await next_packet(), state)
            writer.write(frame_packet(protocol.create_client_auth(state, session_keys)))
            writer.write(frame_packet(protocol.create_data_packet(b"who am I?", session_keys)))
            await writer.drain()

            answer = protocol.parse_data_packet(await next_packet(), session_keys)
            return answer.decode()
        finally:
            writer.close()

    async def test_two_peers_come_out_of_two_different_listeners(self):
        """
        The whole point, proved rather than argued: the same tunnel, the same
        listening socket, two people, two destinations — and the destination is
        chosen by the identity the handshake proved.
        """
        alex = await asyncio.wait_for(self.dial(self.alex), timeout=10)
        dad = await asyncio.wait_for(self.dial(self.dad), timeout=10)

        self.assertEqual(alex, "reached:alex")
        self.assertEqual(dad, "reached:dad")

    async def test_a_peer_with_no_forward_still_lands_on_the_shared_one(self):
        """
        The migration property. A roster where only some people have been given a
        socket keeps working for everybody else, which is what allows this to be
        turned on for one person at a time on a tunnel nobody can afford to drop.
        """
        guest = await asyncio.wait_for(self.dial(self.guest), timeout=10)
        self.assertEqual(guest, "reached:shared")

    async def test_a_stranger_reaches_no_destination_at_all(self):
        """
        Admission is unchanged and still comes first: a key nobody holds fails the
        handshake, so there is no session to route and no port to be attributed.
        """
        stranger = IdentityKeys()
        with self.assertRaises(TunnelClosed):
            await asyncio.wait_for(self.dial(stranger), timeout=10)


class TestTheCommandLine(unittest.TestCase):
    """
    The flag as the selfhost daemon actually spells it.

    `crates/services/vpn/src/runner.rs` emits `--peer-forward <peer>=<socket>`,
    one per roster entry that declared a `forward_port`, and Python exits
    non-zero on an argument it does not recognise — so the two spellings agreeing
    is the difference between a tunnel that starts and one that does not.
    """

    def parse(self, argv):
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--peer", action="append")
        parser.add_argument("--peer-forward", action="append")
        return parser.parse_known_args(argv)

    def test_the_flag_the_daemon_emits_is_the_flag_this_server_accepts(self):
        parsed, unknown = self.parse([
            "--peer", "alex-mac", "--peer", "dad-mac",
            "--peer-forward", "alex-mac=127.0.0.1:9443",
        ])
        self.assertEqual(unknown, [], "an unrecognised argument stops the tunnel starting")
        self.assertEqual(parsed.peer, ["alex-mac", "dad-mac"])
        self.assertEqual(
            parse_peer_forwards(parsed.peer_forward),
            {"alex-mac": ("127.0.0.1", 9443)},
        )

    def test_the_shipped_program_advertises_the_flag(self):
        """
        The parser above is a copy and proves only the shape. This runs the real
        program's `--help`, which is the same `argparse` that would reject the
        argument at start-up — so a flag renamed here and not in the daemon fails
        this test instead of failing a tunnel.
        """
        import subprocess
        import sys

        helped = subprocess.run(
            [sys.executable, str(Path(server_module.__file__)), "--help"],
            capture_output=True, text=True, cwd=str(Path(server_module.__file__).parent),
        )
        self.assertEqual(helped.returncode, 0, helped.stderr)
        self.assertIn("--peer-forward", helped.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
