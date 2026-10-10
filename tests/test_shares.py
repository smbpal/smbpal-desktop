"""Listing a server's shares. Everything here runs without libsmbclient.

The ctypes layer has exactly one caller, so these tests inject a lister and
exercise the rules. `TestStructLayout` is the exception and the important one:
a wrong `struct smbc_dirent` declaration does not fail, it reads whatever is
at the wrong offset, so the offsets are pinned here and verified against the
installed header by `python3 -m smbpal.discovery.shares`.
"""

from __future__ import annotations

import ctypes
import unittest

from smbpal.discovery.shares import (
    SMBC_FILE_SHARE,
    SMBC_IPC_SHARE,
    SMBC_PRINTER_SHARE,
    Share,
    SmbcDirent,
    classify,
    interpret,
    list_shares,
    mountable,
    probe_layout,
    _write_into,
)
from smbpal.errors import Unavailable

# What a Mac answered on 10 October 2026, in the order libsmbclient reports it.
# The apostrophe is U+2019 and the name is macOS's own default: docs §6.19.
MAC_LISTING = [
    (SMBC_FILE_SHARE, "Luke H’s Public Folder", ""),
    (SMBC_IPC_SHARE, "IPC$", "IPC Service"),
    (SMBC_FILE_SHARE, "smbpal", ""),
]


class TestInterpret(unittest.TestCase):
    def test_disk_shares_come_first(self) -> None:
        # A listing is scanned by eye for the name you meant to type, and
        # `IPC$` is never that.
        kinds = [s.kind for s in interpret(MAC_LISTING)]
        self.assertEqual(kinds, ["disk", "disk", "ipc"])

    def test_names_sort_case_insensitively(self) -> None:
        rows = [(SMBC_FILE_SHARE, n, "") for n in ("zebra", "Apple", "beta")]
        self.assertEqual(
            [s.name for s in interpret(rows)], ["Apple", "beta", "zebra"]
        )

    def test_a_curly_apostrophe_survives(self) -> None:
        # The other half of the §6.19 pair: browse.py mangled this character
        # and the schema rejected it. A listing has to carry it exactly.
        names = [s.name for s in interpret(MAC_LISTING)]
        self.assertIn("Luke’s Public Folder".replace("Luke", "Luke H"), names)

    def test_dot_entries_are_dropped(self) -> None:
        rows = [(SMBC_FILE_SHARE, ".", ""), (SMBC_FILE_SHARE, "..", "")]
        self.assertEqual(interpret(rows), [])

    def test_comments_are_kept(self) -> None:
        share = interpret([(SMBC_PRINTER_SHARE, "HP", "the one upstairs")])[0]
        self.assertEqual((share.kind, share.comment), ("printer", "the one upstairs"))

    def test_an_unknown_type_is_named_rather_than_dropped(self) -> None:
        # A row we cannot classify is still a row somebody may be looking for.
        self.assertEqual(classify(99), "other")
        self.assertEqual(len(interpret([(99, "odd", "")])), 1)


class TestMountable(unittest.TestCase):
    def test_only_disk_shares_are_offered(self) -> None:
        # This feeds "did you mean", so offering IPC$ would be worse than
        # offering nothing.
        self.assertEqual(
            mountable(interpret(MAC_LISTING)),
            ["Luke H’s Public Folder", "smbpal"],
        )


class TestListShares(unittest.TestCase):
    def test_the_lister_is_called_with_the_credential(self) -> None:
        seen: list[tuple[str, str, str]] = []

        def lister(host: str, user: str, password: str) -> list[tuple[int, str, str]]:
            seen.append((host, user, password))
            return MAC_LISTING

        shares = list_shares(
            "mac.local", username="_smbpal", password="pw", lister=lister
        )
        self.assertEqual(seen, [("mac.local", "_smbpal", "pw")])
        self.assertEqual(shares[0].name, "Luke H’s Public Folder")

    def test_anonymous_by_default(self) -> None:
        seen: list[tuple[str, str, str]] = []

        def lister(host: str, user: str, password: str) -> list[tuple[int, str, str]]:
            seen.append((host, user, password))
            return []

        list_shares("mac.local", lister=lister)
        self.assertEqual(seen, [("mac.local", "", "")])

    def test_a_host_carrying_structure_is_refused(self) -> None:
        # The host becomes `smb://<host>`, so a slash or a space in it would
        # address something else entirely.
        for bad in ("", "host/share", "a b", "host\\share", "two\nlines"):
            with self.subTest(host=bad):
                with self.assertRaises(Unavailable):
                    list_shares(bad, lister=lambda *_a: [])


class TestStructLayout(unittest.TestCase):
    """Pinned offsets. A reordered field reads memory rather than failing."""

    def test_the_declared_layout_is_the_one_measured(self) -> None:
        self.assertEqual(
            probe_layout(),
            {
                "sizeof": 32,
                "smbc_type": 0,
                "dirlen": 4,
                "commentlen": 8,
                "comment": 16,
                "namelen": 24,
                "name": 28,
            },
        )

    def test_name_is_the_last_field(self) -> None:
        # It is a flexible array member, read from its offset for `namelen`
        # bytes. Anything after it would be read as part of a share name.
        self.assertEqual(SmbcDirent._fields_[-1][0], "name")


class TestCredentialBuffers(unittest.TestCase):
    """`_write_into` copies into buffers libsmbclient owns and sized."""

    def test_the_value_is_nul_terminated(self) -> None:
        buffer = ctypes.create_string_buffer(16)
        _write_into(buffer, 16, "_smbpal")
        self.assertEqual(buffer.value, b"_smbpal")

    def test_a_long_value_is_truncated_rather_than_overflowing(self) -> None:
        buffer = ctypes.create_string_buffer(8)
        _write_into(buffer, 8, "a" * 40)
        self.assertEqual(buffer.value, b"a" * 7)
        self.assertEqual(buffer.raw[7], 0)

    def test_a_refused_buffer_is_left_alone(self) -> None:
        # The library may offer no buffer at all; writing anyway would be a
        # segfault in a daemon.
        _write_into(None, 0, "pw")
        _write_into(ctypes.create_string_buffer(4), 0, "pw")


class TestShareWire(unittest.TestCase):
    def test_to_wire_is_the_three_fields_the_cli_renders(self) -> None:
        self.assertEqual(
            Share("smbpal", "disk", "").to_wire(),
            {"name": "smbpal", "kind": "disk", "comment": ""},
        )
