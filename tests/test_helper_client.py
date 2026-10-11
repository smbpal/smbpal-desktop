"""The client side of the helper socket, which job A left unwritten.

**Tested against a fake server that speaks the real protocol**, because the real
one needs root: `helper.sock` is `0600 _smbpald` and its path is fixed on
purpose, so an ordinary user connecting gets `EACCES` -- confirmed on 11 October
2026, which is the socket guard working rather than a problem to route around.

So what is asserted here is the wire format and every refusal. The exact bytes
matter in both directions, and a second implementation of a protocol is the
thing that drifts from the first.
"""

from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from pathlib import Path

from smbpal.system.helper import Helper, HelperError


class FakeHelper:
    """A UNIX socket that records one frame and answers with what it was told."""

    def __init__(self, answer: bytes) -> None:
        self.answer = answer
        self.seen: bytes = b""
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "helper.sock")
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.path)
        self._sock.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            chunks = []
            while b"\nEND\n" not in b"".join(chunks):
                block = conn.recv(4096)
                if not block:
                    break
                chunks.append(block)
            self.seen = b"".join(chunks)
            try:
                conn.sendall(self.answer)
            except OSError:
                pass

    def close(self) -> None:
        self._sock.close()
        self._thread.join(timeout=2)
        self.tmp.cleanup()


class HelperClientCase(unittest.TestCase):
    def helper(self, answer: bytes) -> tuple[Helper, FakeHelper]:
        server = FakeHelper(answer)
        self.addCleanup(server.close)
        return Helper(path=server.path, timeout=5.0), server


class TestTheWireFormat(HelperClientCase):
    def test_a_read_sends_a_verb_and_nothing_else(self) -> None:
        client, server = self.helper(b"OK\n[]")
        self.assertEqual(client.share_list(), b"[]")
        self.assertEqual(server.seen, b"VERB share.list\nEND\n")

    def test_a_grant_travels_as_hex_in_its_own_line(self) -> None:
        client, server = self.helper(b"OK\n")
        self.assertTrue(client.check("app.smbpal.manage-shares", bytes(range(32))))
        self.assertEqual(
            server.seen,
            b"VERB auth.check\n"
            b"AUTH 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"
            b"ARG app.smbpal.manage-shares\n"
            b"END\n",
        )

    def test_an_empty_payload_is_not_an_error(self) -> None:
        """`auth.check` answers with the status line and nothing after it."""
        client, _ = self.helper(b"OK\n")
        self.assertEqual(client.call("auth.check", "r", auth=bytes(32)), b"")


class TestEveryRefusal(HelperClientCase):
    def test_a_refusal_token_reaches_the_caller(self) -> None:
        client, _ = self.helper(b"ERR denied\n")
        with self.assertRaises(HelperError) as caught:
            client.call("auth.check", "app.smbpal.manage-shares", auth=bytes(32))
        self.assertEqual(caught.exception.detail, "denied")

    def test_check_turns_every_refusal_into_false(self) -> None:
        """Not an exception: an authoriser answers yes or no, and "the helper is
        broken" is a no. The same rule `daemon/polkit.py` states for `pkcheck`."""
        for answer in (b"ERR denied\n", b"ERR frame\n", b"", b"nonsense\n"):
            with self.subTest(answer=answer):
                client, _ = self.helper(answer)
                self.assertFalse(client.check("app.smbpal.manage-shares", bytes(32)))

    def test_a_missing_socket_says_what_to_run(self) -> None:
        client = Helper(path="/var/run/smbpal/does-not-exist.sock")
        with self.assertRaises(HelperError) as caught:
            client.share_list()
        self.assertIn("smbpal setup", str(caught.exception.detail))

    def test_a_newline_in_an_argument_is_named_here(self) -> None:
        """The helper rejects it too, and that is the point -- it does not trust
        this side. Checking here as well turns "the helper said no" into a
        message that names the actual mistake."""
        client, _ = self.helper(b"OK\n")
        with self.assertRaises(HelperError) as caught:
            client.call("auth.check", "a\nARG b")
        self.assertIn("truncated frame", str(caught.exception.detail))

    def test_an_unrecognised_answer_is_not_treated_as_success(self) -> None:
        client, _ = self.helper(b"OKAY\n")
        with self.assertRaises(HelperError):
            client.share_list()

    def test_available_does_not_connect(self) -> None:
        """A probe that opens a connection to decide whether it can open a
        connection is a race with its own answer."""
        client, server = self.helper(b"OK\n")
        self.assertTrue(client.available())
        self.assertEqual(server.seen, b"")
