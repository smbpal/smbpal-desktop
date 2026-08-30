"""Schema validation. Each rejection here is a bug that cannot reach smb.conf."""

from __future__ import annotations

import unittest

from smbpal.config.schema import SCHEMA_VERSION, empty_config, validate, validate_or_raise
from smbpal.errors import ConfigInvalid


def _share(**overrides: object) -> dict[str, object]:
    share = {
        "type": "os",
        "id": "media",
        "name": "Media",
        "path": "/srv/media",
        "read_only": False,
        "credential_ref": None,
        "enabled": True,
    }
    share.update(overrides)
    return share


def _connection(**overrides: object) -> dict[str, object]:
    connection = {
        "type": "os",
        "id": "nas",
        "host": "nas.local",
        "share": "Media",
        "mountpoint": "/mnt/nas",
        "credential_ref": "nas-creds",
        "auto_connect": "on_this_network",
    }
    connection.update(overrides)
    return connection


def _problems(doc: object) -> list[str]:
    return [p.where for p in validate(doc)]


class TestValid(unittest.TestCase):
    def test_empty_config_is_valid(self) -> None:
        self.assertEqual(validate(empty_config()), [])

    def test_a_full_record_is_valid(self) -> None:
        doc = {
            "version": SCHEMA_VERSION,
            "shares": [_share()],
            "connections": [_connection()],
        }
        self.assertEqual(validate(doc), [])

    def test_optional_fields_may_be_absent(self) -> None:
        doc = {
            "version": 1,
            "shares": [{"type": "os", "id": "a", "name": "A", "path": "/srv/a"}],
        }
        self.assertEqual(validate(doc), [])


class TestVersion(unittest.TestCase):
    def test_a_newer_version_says_so_rather_than_calling_it_invalid(self) -> None:
        problems = validate({"version": SCHEMA_VERSION + 1})
        self.assertEqual(len(problems), 1)
        self.assertIn("newer version", problems[0].message)

    def test_version_must_be_an_integer(self) -> None:
        self.assertEqual(_problems({"version": "1"}), ["version"])

    def test_version_is_required(self) -> None:
        self.assertIn("<document>", _problems({"shares": []}))


class TestShareName(unittest.TestCase):
    def test_a_newline_in_a_share_name_is_rejected(self) -> None:
        # The name lands in a section header. A newline in it is arbitrary
        # smb.conf, which is the whole reason this check exists.
        doc = {"version": 1, "shares": [_share(name="Media\n[evil]\npath = /")]}
        self.assertEqual(_problems(doc), ["shares[0].name"])

    def test_structural_characters_are_rejected(self) -> None:
        for bad in ("a/b", "a[b", "a]b", "a\\b", 'a"b', "a;b", "a%b"):
            with self.subTest(name=bad):
                doc = {"version": 1, "shares": [_share(name=bad)]}
                self.assertEqual(_problems(doc), ["shares[0].name"])

    def test_reserved_names_are_rejected_case_insensitively(self) -> None:
        for bad in ("global", "GLOBAL", "homes", "printers"):
            with self.subTest(name=bad):
                doc = {"version": 1, "shares": [_share(name=bad)]}
                self.assertEqual(_problems(doc), ["shares[0].name"])

    def test_names_colliding_only_in_case_are_rejected(self) -> None:
        doc = {
            "version": 1,
            "shares": [_share(id="a", name="Media"), _share(id="b", name="media")],
        }
        self.assertEqual(_problems(doc), ["shares[1].name"])

    def test_empty_name_is_rejected(self) -> None:
        self.assertEqual(
            _problems({"version": 1, "shares": [_share(name="")]}), ["shares[0].name"]
        )


class TestIdentifiers(unittest.TestCase):
    def test_an_id_that_could_escape_a_path_is_rejected(self) -> None:
        # Ids become systemd unit names and credential file names.
        for bad in ("../etc", "a/b", "a b", "a.b", "", "-leading", "a" * 65):
            with self.subTest(id=bad):
                doc = {"version": 1, "shares": [_share(id=bad)]}
                self.assertIn("shares[0].id", _problems(doc))

    def test_duplicate_ids_across_shares_and_connections_are_rejected(self) -> None:
        doc = {
            "version": 1,
            "shares": [_share(id="dup")],
            "connections": [_connection(id="dup")],
        }
        self.assertEqual(_problems(doc), ["connections[0].id"])


class TestPaths(unittest.TestCase):
    def test_relative_paths_are_rejected(self) -> None:
        self.assertEqual(
            _problems({"version": 1, "shares": [_share(path="srv/media")]}),
            ["shares[0].path"],
        )

    def test_dot_dot_components_are_rejected(self) -> None:
        self.assertEqual(
            _problems({"version": 1, "shares": [_share(path="/srv/../etc")]}),
            ["shares[0].path"],
        )

    def test_a_newline_in_a_path_is_rejected(self) -> None:
        self.assertEqual(
            _problems({"version": 1, "shares": [_share(path="/srv/a\nb")]}),
            ["shares[0].path"],
        )

    def test_shape_is_checked_but_the_filesystem_is_not(self) -> None:
        # /srv/does-not-exist is valid config. Whether it exists, and who owns
        # it, is M3's question (§3c) — and a USB disk not yet mounted must not
        # stop the daemon booting.
        doc = {"version": 1, "shares": [_share(path="/srv/does-not-exist")]}
        self.assertEqual(validate(doc), [])


class TestConnections(unittest.TestCase):
    def test_auto_connect_is_an_enum(self) -> None:
        doc = {"version": 1, "connections": [_connection(auto_connect="sometimes")]}
        self.assertEqual(_problems(doc), ["connections[0].auto_connect"])

    def test_a_host_carrying_a_path_is_rejected(self) -> None:
        doc = {"version": 1, "connections": [_connection(host="host/share")]}
        self.assertEqual(_problems(doc), ["connections[0].host"])


class TestStrictness(unittest.TestCase):
    def test_unknown_fields_are_rejected_not_ignored(self) -> None:
        # A silently dropped typo is a setting the user believes they have set.
        doc = {"version": 1, "shares": [_share(read_onlyy=True)]}
        self.assertEqual(_problems(doc), ["shares[0].read_onlyy"])

    def test_type_must_be_os_in_phase_1(self) -> None:
        doc = {"version": 1, "shares": [_share(type="app")]}
        self.assertEqual(_problems(doc), ["shares[0].type"])

    def test_every_problem_is_reported_not_just_the_first(self) -> None:
        doc = {"version": 1, "shares": [_share(name="", path="rel", id="!")]}
        self.assertEqual(len(validate(doc)), 3)


class TestRaising(unittest.TestCase):
    def test_validate_or_raise_names_the_source_and_every_problem(self) -> None:
        with self.assertRaises(ConfigInvalid) as caught:
            validate_or_raise({"version": 1, "shares": [_share(path="rel")]}, source="X")
        self.assertIn("X", caught.exception.message)
        self.assertIn("shares[0].path", caught.exception.detail or "")


if __name__ == "__main__":
    unittest.main()
