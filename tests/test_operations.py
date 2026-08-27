"""Structured config edits — the invariants, without a daemon or a socket."""

from __future__ import annotations

import unittest

from smbpal.config import empty_config
from smbpal.config import operations as ops
from smbpal.errors import AlreadyExists, ConfigInvalid, InvalidParams, NotFound


class TestIds(unittest.TestCase):
    def test_an_id_is_derived_from_the_name(self) -> None:
        self.assertEqual(ops.make_id("My Media!", set()), "my-media")

    def test_a_taken_id_gets_a_suffix(self) -> None:
        self.assertEqual(ops.make_id("Media", {"media"}), "media-2")
        self.assertEqual(ops.make_id("Media", {"media", "media-2"}), "media-3")

    def test_a_name_with_no_usable_characters_still_yields_a_legal_id(self) -> None:
        for name in ("!!!", "…", "1"):
            with self.subTest(name=name):
                derived = ops.make_id(name, set())
                doc, _ = ops.add_share(
                    empty_config(), name="X", path="/srv/x", id=derived
                )
                self.assertEqual(doc["shares"][0]["id"], derived)


class TestShares(unittest.TestCase):
    def test_add_then_list(self) -> None:
        doc, share = ops.add_share(empty_config(), name="Media", path="/srv/media")
        self.assertEqual(share["id"], "media")
        self.assertEqual(doc["shares"], [share])

    def test_the_input_document_is_not_mutated(self) -> None:
        original = empty_config()
        ops.add_share(original, name="Media", path="/srv/media")
        self.assertEqual(original["shares"], [])

    def test_a_name_colliding_only_in_case_is_refused(self) -> None:
        doc, _ = ops.add_share(empty_config(), name="Media", path="/srv/a")
        with self.assertRaises(AlreadyExists):
            ops.add_share(doc, name="media", path="/srv/b")

    def test_an_explicit_duplicate_id_is_refused(self) -> None:
        doc, _ = ops.add_share(empty_config(), name="A", path="/srv/a", id="x")
        with self.assertRaises(AlreadyExists):
            ops.add_share(doc, name="B", path="/srv/b", id="x")

    def test_a_bad_field_is_reported_without_an_array_index(self) -> None:
        # `shares[2].name` is an index the person who typed a share name never
        # saw. They get told about `name`.
        with self.assertRaises(ConfigInvalid) as caught:
            ops.add_share(empty_config(), name="bad\nname", path="/srv/x")
        detail = caught.exception.detail or ""
        self.assertIn("- name:", detail)
        self.assertNotIn("shares[", detail)
        self.assertIn("1 problem:", detail)

    def test_remove_by_id_or_by_name(self) -> None:
        doc, _ = ops.add_share(empty_config(), name="Media", path="/srv/media")
        by_name, _ = ops.remove_share(doc, "Media")
        by_id, _ = ops.remove_share(doc, "media")
        self.assertEqual(by_name["shares"], [])
        self.assertEqual(by_id["shares"], [])

    def test_remove_matches_a_name_case_insensitively(self) -> None:
        doc, _ = ops.add_share(empty_config(), name="Media", path="/srv/media")
        updated, removed = ops.remove_share(doc, "MEDIA")
        self.assertEqual(removed["id"], "media")
        self.assertEqual(updated["shares"], [])

    def test_removing_something_absent_says_so(self) -> None:
        with self.assertRaises(NotFound):
            ops.remove_share(empty_config(), "ghost")

    def test_an_id_is_matched_before_another_records_name(self) -> None:
        # A record whose id equals another record's name must stay reachable.
        doc, _ = ops.add_share(empty_config(), name="alpha", path="/srv/a", id="beta")
        doc, _ = ops.add_share(doc, name="beta", path="/srv/b", id="gamma")
        _, removed = ops.remove_share(doc, "beta")
        self.assertEqual(removed["id"], "beta")


class TestConnections(unittest.TestCase):
    def test_add_derives_an_id_from_host_and_share(self) -> None:
        _, connection = ops.add_connection(
            empty_config(),
            host="rivendell.local",
            share="Media",
            mountpoint="/mnt/nas",
        )
        self.assertEqual(connection["id"], "rivendell-local-media")

    def test_two_connections_on_one_mountpoint_are_refused(self) -> None:
        doc, _ = ops.add_connection(
            empty_config(), host="a", share="S", mountpoint="/mnt/x"
        )
        with self.assertRaises(AlreadyExists):
            ops.add_connection(doc, host="b", share="T", mountpoint="/mnt/x")

    def test_remove_by_mountpoint(self) -> None:
        doc, _ = ops.add_connection(
            empty_config(), host="a", share="S", mountpoint="/mnt/x"
        )
        updated, removed = ops.remove_connection(doc, "/mnt/x")
        self.assertEqual(removed["host"], "a")
        self.assertEqual(updated["connections"], [])


class TestIdsAreSharedAcrossKinds(unittest.TestCase):
    def test_a_connection_cannot_reuse_a_share_id(self) -> None:
        doc, _ = ops.add_share(empty_config(), name="Media", path="/srv/media")
        with self.assertRaises(AlreadyExists):
            ops.add_connection(
                doc, host="h", share="S", mountpoint="/mnt/x", id="media"
            )

    def test_a_derived_id_steps_around_one_taken_by_the_other_kind(self) -> None:
        # Ids are a single namespace across shares and connections, so deriving
        # one has to consider both or the save would fail validation.
        doc, _ = ops.add_share(
            empty_config(), name="X", path="/srv/x", id="rivendell-local-media"
        )
        _, connection = ops.add_connection(
            doc, host="rivendell.local", share="Media", mountpoint="/mnt/nas"
        )
        self.assertEqual(connection["id"], "rivendell-local-media-2")


class TestDerivedMountpoints(unittest.TestCase):
    """Where a connection goes when nobody says — 3h."""

    LINUX = ops.STYLES["linux"]
    MACOS = ops.STYLES["darwin"]

    def test_linux_lands_somewhere_the_file_manager_will_show(self) -> None:
        # /mnt is invisible to GIO however correct the mount is, so the whole
        # point of deriving is landing under one of the three prefixes it
        # admits. This test is the reason the function exists.
        path = ops.default_mountpoint("Media", "pi", set(), style=self.LINUX)
        self.assertEqual(path, "/media/pi/Media")
        self.assertTrue(path.startswith("/media/"))

    def test_macos_uses_volumes_and_has_no_user_level(self) -> None:
        path = ops.default_mountpoint("Media", "luke", set(), style=self.MACOS)
        self.assertEqual(path, "/Volumes/Media")

    def test_macos_needs_no_owner(self) -> None:
        # /Volumes is machine-wide, so a connection with no owner is still
        # placeable there. On Linux it is not, and saying so beats guessing.
        self.assertEqual(
            ops.default_mountpoint("Media", None, set(), style=self.MACOS),
            "/Volumes/Media",
        )

    def test_linux_without_an_owner_says_so_rather_than_guessing(self) -> None:
        with self.assertRaises(InvalidParams):
            ops.default_mountpoint("Media", None, set(), style=self.LINUX)

    def test_a_collision_disambiguates_by_host_not_by_number(self) -> None:
        # Two NASes both exporting `Media` is the common case, and the useful
        # question is which one.
        path = ops.default_mountpoint(
            "Media",
            "pi",
            {"/media/pi/Media"},
            host="rivendell.local",
            style=self.LINUX,
        )
        self.assertEqual(path, "/media/pi/Media on rivendell.local")

    def test_a_second_collision_falls_back_to_a_number(self) -> None:
        path = ops.default_mountpoint(
            "Media",
            "pi",
            {"/media/pi/Media", "/media/pi/Media on rivendell.local"},
            host="rivendell.local",
            style=self.LINUX,
        )
        self.assertEqual(path, "/media/pi/Media on rivendell.local 2")

    def test_a_leading_dot_is_stripped_because_it_would_hide_the_mount(self) -> None:
        # GIO hides any mount whose path contains "/." — deriving
        # /media/pi/.private would be the failure this all exists to prevent.
        self.assertEqual(
            ops.default_mountpoint(".private", "pi", set(), style=self.LINUX),
            "/media/pi/private",
        )

    def test_a_share_name_of_nothing_usable_still_yields_a_path(self) -> None:
        self.assertEqual(
            ops.default_mountpoint("...", "pi", set(), style=self.LINUX),
            "/media/pi/share",
        )

    def test_an_unknown_platform_falls_back_to_linux(self) -> None:
        # The daemon runs on Linux. A development Mac deriving a Linux path is
        # harmless; a Mac deriving /Volumes into a Pi's config would not be.
        self.assertEqual(ops.platform_style("plan9"), self.LINUX)
        self.assertEqual(ops.platform_style(None), self.LINUX)

    def test_add_connection_writes_the_derived_path_into_the_document(self) -> None:
        # Stored explicitly: a config whose mountpoint depends on which version
        # of the derivation last ran is not a record of anything.
        doc, connection = ops.add_connection(
            empty_config(), host="rivendell.local", share="Media", owner="pi"
        )
        self.assertEqual(connection["mountpoint"], "/media/pi/Media")
        self.assertEqual(doc["connections"][0]["mountpoint"], "/media/pi/Media")

    def test_an_explicit_mountpoint_still_wins(self) -> None:
        _, connection = ops.add_connection(
            empty_config(),
            host="rivendell.local",
            share="Media",
            mountpoint="/srv/backups",
            owner="pi",
        )
        self.assertEqual(connection["mountpoint"], "/srv/backups")

    def test_two_connections_to_the_same_share_name_do_not_collide(self) -> None:
        doc, first = ops.add_connection(
            empty_config(), host="rivendell.local", share="Media", owner="pi"
        )
        _, second = ops.add_connection(
            doc, host="moria.local", share="Media", owner="pi"
        )
        self.assertEqual(first["mountpoint"], "/media/pi/Media")
        self.assertEqual(second["mountpoint"], "/media/pi/Media on moria.local")


if __name__ == "__main__":
    unittest.main()
