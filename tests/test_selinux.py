"""Asking SELinux about a directory, without libselinux and without acting.

Fedora, 27 September 2026: a share under /home mounted from a Pi,
authenticated, and refused every write. `/sys/fs/selinux` is a filesystem and a
context is an extended attribute, so every question here is answerable from the
standard library — which is what makes it safe to ask on every share on every
platform, including the ones with no SELinux at all.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from smbpal.system import selinux


class SelinuxTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        (self.root / "booleans").mkdir()

    def enforce(self, value: str) -> None:
        (self.root / "enforce").write_text(value)

    def boolean(self, name: str, value: str) -> None:
        # The kernel writes "current pending"; only the first is in force.
        (self.root / "booleans" / name).write_text(f"{value} {value}\n")

    def unserveable(self, kind: str | None, path: str = "/home/luke/Testshare"):
        with mock.patch.object(selinux, "context_type", return_value=kind):
            return selinux.unserveable(path, root=self.root)


class TestWhenNothingShouldBeSaid(SelinuxTestCase):
    def test_a_machine_with_no_selinux_says_nothing(self) -> None:
        # No /sys/fs/selinux at all: Debian, Ubuntu, Pi OS — most machines.
        self.assertIsNone(self.unserveable("user_home_t"))

    def test_permissive_says_nothing(self) -> None:
        # Permissive logs the denial and allows the write, so there is no
        # problem to describe.
        self.enforce("0")
        self.assertIsNone(self.unserveable("user_home_t"))

    def test_a_labelled_share_says_nothing(self) -> None:
        self.enforce("1")
        self.assertIsNone(self.unserveable("samba_share_t"))

    def test_the_public_content_types_are_accepted_too(self) -> None:
        self.enforce("1")
        self.assertIsNone(self.unserveable("public_content_rw_t"))
        self.assertIsNone(self.unserveable("public_content_t"))

    def test_export_all_rw_makes_the_label_moot(self) -> None:
        self.enforce("1")
        self.boolean(selinux.EXPORT_ALL, "1")
        self.assertIsNone(self.unserveable("user_home_t"))

    def test_home_dirs_on_covers_a_home_directory(self) -> None:
        self.enforce("1")
        self.boolean(selinux.HOME_DIRS, "1")
        self.assertIsNone(self.unserveable("user_home_t"))

    def test_a_path_with_no_context_says_nothing(self) -> None:
        # A filesystem that carries no labels at all, such as a mounted share.
        self.enforce("1")
        self.assertIsNone(self.unserveable(None))


class TestTheFedoraCase(SelinuxTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.enforce("1")

    def test_a_home_directory_is_reported_with_both_commands(self) -> None:
        problem = self.unserveable("user_home_t")
        assert problem is not None
        self.assertEqual(problem["type"], "user_home_t")
        self.assertEqual(problem["wanted"], "samba_share_t")
        self.assertIn("-t samba_share_t '/home/luke/Testshare(/.*)?'", problem["label"])
        self.assertIn("restorecon -Rv /home/luke/Testshare", problem["restore"])

    def test_home_dirs_off_still_reports_it(self) -> None:
        self.boolean(selinux.HOME_DIRS, "0")
        self.assertIsNotNone(self.unserveable("user_home_t"))

    def test_any_other_type_is_reported_too(self) -> None:
        # /srv and /opt are the other places people share from, and neither is
        # labelled for Samba by default.
        self.assertIsNotNone(self.unserveable("var_t", path="/srv/media"))


class TestPathsThatAreNotPlainWords(SelinuxTestCase):
    """The commands are built from a path somebody chose, not from a fixture.

    `semanage fcontext` takes a regular expression and `restorecon` takes a
    shell argument, and an ordinary folder name can be neither.
    """

    def setUp(self) -> None:
        super().setUp()
        self.enforce("1")

    def test_a_space_does_not_break_the_shell(self) -> None:
        problem = self.unserveable("user_home_t", path="/srv/media (old)")
        assert problem is not None
        self.assertEqual(
            problem["restore"], "sudo restorecon -Rv '/srv/media (old)'"
        )

    def test_regex_characters_are_escaped_not_just_quoted(self) -> None:
        # A quoted but unescaped pattern gives a command that runs and labels
        # something else, which is worse than one that fails.
        problem = self.unserveable("user_home_t", path="/srv/c++ backups")
        assert problem is not None
        self.assertIn(r"c\+\+", problem["label"])
        self.assertTrue(problem["label"].endswith("(/.*)?'"), problem["label"])

    def test_a_plain_path_is_left_readable(self) -> None:
        # Escaping must not make the ordinary case ugly: this is a line
        # somebody reads and types.
        problem = self.unserveable("user_home_t", path="/srv/media")
        assert problem is not None
        self.assertIn("'/srv/media(/.*)?'", problem["label"])
        self.assertEqual(problem["restore"], "sudo restorecon -Rv /srv/media")


if __name__ == "__main__":
    unittest.main()
