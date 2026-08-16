"""
Multi-peer roster tests.

The server used to hold exactly one client public key, so a second person could
only be admitted by handing them the first person's private key. It now holds a
roster — {name: public key} — and selects the entry by the identity key the
client presents in CLIENT_HELLO.

The whole security argument for that rests on one thing, and it is what these
tests exist to hold down: *selection is not authentication*. Choosing which
public key to check against by what the client presented is safe only because
possession of the matching private key is still proven afterwards, by the
Ed25519 signature over the handshake transcript in CLIENT_AUTH. So the tests
that matter here are the negative ones — an unknown key, and a key swapped
between the two steps.
"""

import unittest

from crypto_core import IdentityKeys
from protocol import SecureVPNProtocol, ProtocolError


def complete_handshake(client_identity, server_identity, server_roster):
    """
    Drive a full three-step handshake and return the server's handshake state.

    Raises whatever the protocol raises, which is what the negative tests read.
    """
    client = SecureVPNProtocol(client_identity, server_identity.get_public_bytes())
    server = SecureVPNProtocol(server_identity, peer_roster=server_roster)

    hello, client_state = client.create_client_hello()
    server_hello, server_state, server_keys = server.process_client_hello(hello)

    client_keys = client.process_server_hello(server_hello, client_state)
    auth = client.create_client_auth(client_state, client_keys)

    assert server.process_client_auth(auth, server_state, server_keys)
    return server_state


class TestRoster(unittest.TestCase):
    def setUp(self):
        self.server_identity = IdentityKeys()
        self.alex = IdentityKeys()
        self.dad = IdentityKeys()
        self.roster = {
            "client": self.alex.get_public_bytes(),
            "dad": self.dad.get_public_bytes(),
        }

    def test_every_roster_entry_can_connect(self):
        """Both authorised clients complete a handshake, on the same server."""
        for name, identity in (("client", self.alex), ("dad", self.dad)):
            with self.subTest(peer=name):
                state = complete_handshake(identity, self.server_identity, self.roster)
                self.assertEqual(state.peer_name, name)

    def test_the_handshake_names_the_peer_it_resolved(self):
        """
        The log line's fact is real: the state carries which entry matched, and
        it is the entry whose key the client actually holds — not the first in
        the roster, and not the one that was configured first.
        """
        state = complete_handshake(self.dad, self.server_identity, self.roster)
        self.assertEqual(state.peer_name, "dad")
        self.assertEqual(state.peer_identity_pubkey, self.dad.get_public_bytes())

    def test_a_key_nobody_holds_is_refused(self):
        """A client whose key is in no roster entry cannot get past CLIENT_HELLO."""
        stranger = IdentityKeys()
        with self.assertRaises(ProtocolError) as refusal:
            complete_handshake(stranger, self.server_identity, self.roster)
        self.assertIn("mismatch", str(refusal.exception))

    def test_removing_an_entry_revokes_that_person_and_nobody_else(self):
        """
        Revocation is deleting a roster entry. The person removed is refused; the
        other authorised client is unaffected. This is the property that makes
        one key per person worth the trouble.
        """
        reduced = {"client": self.roster["client"]}

        with self.assertRaises(ProtocolError):
            complete_handshake(self.dad, self.server_identity, reduced)

        state = complete_handshake(self.alex, self.server_identity, reduced)
        self.assertEqual(state.peer_name, "client")

    def test_a_key_swapped_between_hello_and_auth_is_refused(self):
        """
        The attack the roster creates and the state binding closes: present one
        authorised key in CLIENT_HELLO, then claim a *different* authorised key
        in CLIENT_AUTH. If the AUTH check consulted the roster rather than the
        key this handshake resolved to, this would pass, and any roster member
        could be impersonated by any other.
        """
        client = SecureVPNProtocol(self.dad, self.server_identity.get_public_bytes())
        server = SecureVPNProtocol(self.server_identity, peer_roster=self.roster)

        hello, client_state = client.create_client_hello()
        server_hello, server_state, server_keys = server.process_client_hello(hello)
        client_keys = client.process_server_hello(server_hello, client_state)

        # Dad signs the transcript honestly, but claims to be 'client' — an
        # identity that is genuinely in the roster.
        import struct
        sign_msg = (
            client_state.ephemeral_exchange.get_public_bytes()
            + client_state.peer_ephemeral_pubkey
            + struct.pack('<d', client_state.client_timestamp)
            + struct.pack('<d', client_state.server_timestamp)
        )
        forged = struct.pack(
            '<B32s64s',
            0x03,
            self.alex.get_public_bytes(),
            self.dad.sign(sign_msg),
        )

        with self.assertRaises(ProtocolError) as refusal:
            server.process_client_auth(client_keys.encrypt(forged), server_state, server_keys)
        self.assertIn("mismatch", str(refusal.exception))

    def test_a_stolen_public_key_still_proves_nothing(self):
        """
        Public keys are public. Presenting somebody else's — with no signature to
        back it — is refused at CLIENT_AUTH, which is where possession is proven.
        """
        impostor = IdentityKeys()
        client = SecureVPNProtocol(impostor, self.server_identity.get_public_bytes())
        server = SecureVPNProtocol(self.server_identity, peer_roster=self.roster)

        # Hand-build a CLIENT_HELLO carrying dad's public key instead of the
        # impostor's own, so the server resolves the handshake to 'dad'.
        import struct
        import time
        from crypto_core import KeyExchange

        kex = KeyExchange()
        timestamp = time.time()
        hello = struct.pack(
            '<BBd32s32s',
            0x01, 1, timestamp,
            kex.get_public_bytes(),
            self.dad.get_public_bytes(),
        )

        server_hello, server_state, server_keys = server.process_client_hello(hello)
        self.assertEqual(server_state.peer_name, "dad")  # selection succeeded...

        # ...and authentication does not: the impostor cannot sign as dad.
        sign_msg = (
            kex.get_public_bytes()
            + server_state.ephemeral_exchange.get_public_bytes()
            + struct.pack('<d', timestamp)
            + struct.pack('<d', server_state.server_timestamp)
        )
        forged = struct.pack('<B32s64s', 0x03, self.dad.get_public_bytes(), impostor.sign(sign_msg))
        shared = kex.derive_shared_secret(server_state.ephemeral_exchange.get_public_bytes())
        client_keys = kex.derive_session_keys(shared, is_client=True)

        with self.assertRaises(ProtocolError) as refusal:
            server.process_client_auth(client_keys.encrypt(forged), server_state, server_keys)
        self.assertIn("signature", str(refusal.exception).lower())

    def test_a_server_with_no_authorised_peer_refuses_to_exist(self):
        """
        An empty roster is a configuration error, not a server that rejects
        everybody: the second reads as a broken client and gets debugged from
        the wrong end.
        """
        with self.assertRaises(ValueError):
            SecureVPNProtocol(self.server_identity, peer_roster={})
        with self.assertRaises(ValueError):
            SecureVPNProtocol(self.server_identity)

    def test_the_single_peer_shape_is_unchanged(self):
        """
        The shape this deployment ran before rosters existed still behaves
        exactly as it did: one key, positional, admitted; anyone else refused.
        """
        server = SecureVPNProtocol(self.server_identity, self.alex.get_public_bytes())
        client = SecureVPNProtocol(self.alex, self.server_identity.get_public_bytes())
        hello, _ = client.create_client_hello()
        _, state, _ = server.process_client_hello(hello)
        self.assertEqual(state.peer_identity_pubkey, self.alex.get_public_bytes())
        self.assertIsNone(state.peer_name)

        stranger = SecureVPNProtocol(self.dad, self.server_identity.get_public_bytes())
        hello, _ = stranger.create_client_hello()
        with self.assertRaises(ProtocolError):
            server.process_client_hello(hello)




class TestRosterFile(unittest.TestCase):
    """
    The roster FILE — enrolling somebody without restarting the tunnel.

    This is the half that makes enrolment a product rather than an SSH session:
    a person is added by writing their key and their name, and the very next
    handshake honours it. Nobody's live tunnel is dropped to let a new one exist.
    """

    def setUp(self):
        import tempfile
        from pathlib import Path
        from key_manager import KeyManager
        import server

        self.tmp = tempfile.mkdtemp()
        self.keys = Path(self.tmp) / "keys"
        self.km = KeyManager(self.keys)
        self.km.generate_identity("client")
        self.roster_path = str(self.keys / "roster")
        self.Roster = server.Roster

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_pinned_peer_is_authorised_with_no_roster_file_at_all(self):
        roster = self.Roster(str(self.keys), ["client"], self.roster_path)
        self.assertEqual(sorted(roster.current()), ["client"])

    def test_a_name_written_to_the_roster_takes_effect_without_a_restart(self):
        roster = self.Roster(str(self.keys), ["client"], self.roster_path)
        self.assertEqual(sorted(roster.current()), ["client"], "dad is not in yet")

        # Enrolment: the two owner-only writes, on a server that never stopped.
        self.km.generate_identity("dad")
        with open(self.roster_path, "w", encoding="utf-8") as handle:
            handle.write("# people who may reach this box\ndad\n")

        self.assertEqual(
            sorted(roster.current()), ["client", "dad"],
            "the next handshake must see a person enrolled a moment ago"
        )

    def test_removing_a_name_from_the_roster_revokes_without_a_restart(self):
        self.km.generate_identity("dad")
        with open(self.roster_path, "w", encoding="utf-8") as handle:
            handle.write("dad\n")
        roster = self.Roster(str(self.keys), ["client"], self.roster_path)
        self.assertIn("dad", roster.current())

        with open(self.roster_path, "w", encoding="utf-8") as handle:
            handle.write("# dad revoked\n")
        self.assertNotIn("dad", roster.current(), "revocation must be immediate too")
        self.assertIn("client", roster.current(), "and must not touch anybody else")

    def test_comments_and_blank_lines_are_not_names(self):
        with open(self.roster_path, "w", encoding="utf-8") as handle:
            handle.write("\n# dad\n   \nclient # the owner\n")
        roster = self.Roster(str(self.keys), [], self.roster_path)
        self.assertEqual(sorted(roster.current()), ["client"])

    def test_a_name_with_no_key_is_skipped_and_does_not_take_the_tunnel_down(self):
        with open(self.roster_path, "w", encoding="utf-8") as handle:
            handle.write("client\nsomebody-with-no-key\n")
        roster = self.Roster(str(self.keys), [], self.roster_path)
        self.assertEqual(sorted(roster.current()), ["client"],
                         "one unreadable key must not lock everybody else out")

    def test_a_lost_roster_file_leaves_the_pinned_peer_authorised(self):
        # The operator's own client must survive the roster file being deleted;
        # the alternative is a lost file locking the owner out of their own box.
        with open(self.roster_path, "w", encoding="utf-8") as handle:
            handle.write("client\n")
        roster = self.Roster(str(self.keys), ["client"], self.roster_path)
        self.assertIn("client", roster.current())
        import os as _os
        _os.remove(self.roster_path)
        self.assertEqual(sorted(roster.current()), ["client"])

    def test_a_roster_written_by_a_windows_editor_with_a_byte_order_mark_parses(self):
        """
        PowerShell's `Set-Content -Encoding utf8` writes a BOM. Read as plain
        utf-8 it glued itself to the first line, turning a leading comment into a
        peer name no key existed for — seen for real on the box. Cosmetic, since
        the phantom entry was skipped, but a roster edited on Windows has to
        tolerate what Windows actually writes.
        """
        with open(self.roster_path, "w", encoding="utf-8-sig") as handle:
            handle.write("# people\nclient\n")
        roster = self.Roster(str(self.keys), [], self.roster_path)
        self.assertEqual(sorted(roster.current()), ["client"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
