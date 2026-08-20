"""Structured config edits — the invariants, without a daemon or a socket."""

from __future__ import annotations

import unittest

from smbpal.config import empty_config
from smbpal.config import operations as ops
from smbpal.errors import AlreadyExists, ConfigInvalid, NotFound


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


if __name__ == "__main__":
    unittest.main()
