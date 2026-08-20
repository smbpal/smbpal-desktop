"""The atomic store: what it writes, and what it refuses to overwrite."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from smbpal.config import ConfigStore, empty_config
from smbpal.errors import ConfigInvalid


class StoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.path = self.root / "config.json"
        self.store = ConfigStore(self.path)
        self.addCleanup(self._dir.cleanup)


class TestLoad(StoreTestCase):
    def test_a_missing_file_is_a_first_boot_not_an_error(self) -> None:
        self.assertEqual(self.store.load(), empty_config())

    def test_a_corrupt_file_raises_and_names_the_position(self) -> None:
        self.path.write_text('{"version": 1,,}', encoding="utf-8")
        with self.assertRaises(ConfigInvalid) as caught:
            self.store.load()
        self.assertIn("not valid JSON", caught.exception.message)
        self.assertIn("line 1", caught.exception.detail or "")

    def test_a_valid_json_file_that_fails_the_schema_raises(self) -> None:
        self.path.write_text(json.dumps({"version": 1, "shares": "no"}), encoding="utf-8")
        with self.assertRaises(ConfigInvalid):
            self.store.load()

    def test_a_corrupt_file_is_left_exactly_as_it_was(self) -> None:
        # It is the user's data. Loading must never be able to damage it.
        original = '{"version": 1,,}'
        self.path.write_text(original, encoding="utf-8")
        with self.assertRaises(ConfigInvalid):
            self.store.load()
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)


class TestSave(StoreTestCase):
    def test_round_trip(self) -> None:
        doc = {
            "version": 1,
            "shares": [{"type": "os", "id": "media", "name": "Media", "path": "/srv/m"}],
            "connections": [],
        }
        self.store.save(doc)
        self.assertEqual(self.store.load(), doc)

    def test_the_file_is_owner_read_write_only(self) -> None:
        self.store.save(empty_config())
        mode = stat.S_IMODE(self.path.stat().st_mode)
        self.assertEqual(mode, 0o600, f"expected 0600, got {mode:04o}")

    def test_an_invalid_document_never_reaches_the_disk(self) -> None:
        self.store.save(empty_config())
        before = self.path.read_text(encoding="utf-8")
        with self.assertRaises(ConfigInvalid):
            self.store.save({"version": 1, "shares": [{"type": "os"}]})
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_no_temporary_files_are_left_behind(self) -> None:
        self.store.save(empty_config())
        leftovers = [p.name for p in self.root.iterdir() if p.name != "config.json"]
        self.assertEqual(leftovers, [])

    def test_a_failed_save_leaves_no_temporary_file(self) -> None:
        with self.assertRaises(ConfigInvalid):
            self.store.save({"version": 99})
        self.assertEqual(list(self.root.iterdir()), [])

    def test_the_parent_directory_is_created_if_absent(self) -> None:
        nested = ConfigStore(self.root / "etc" / "smbpal" / "config.json")
        nested.save(empty_config())
        self.assertTrue(nested.path.exists())

    def test_replacement_is_atomic_by_rename_not_by_truncation(self) -> None:
        # Hold the old file open, overwrite, and read the handle: os.replace
        # swaps the directory entry, so the open handle still sees the old
        # bytes. A truncate-and-write would have destroyed them under us.
        self.store.save(empty_config())
        with open(self.path, encoding="utf-8") as handle:
            self.store.save(
                {
                    "version": 1,
                    "shares": [
                        {"type": "os", "id": "new", "name": "New", "path": "/srv/n"}
                    ],
                    "connections": [],
                }
            )
            self.assertNotIn("New", handle.read())
        self.assertIn("New", self.path.read_text(encoding="utf-8"))

    def test_the_written_file_ends_with_a_newline(self) -> None:
        self.store.save(empty_config())
        self.assertTrue(self.path.read_text(encoding="utf-8").endswith("\n"))


if __name__ == "__main__":
    unittest.main()
