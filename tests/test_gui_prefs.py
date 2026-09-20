"""The dismissal file: the GUI's only writable state.

It is three functions and no dependency, so it would be easy to leave
untested. The reason not to is that everything it touches is somebody else's
directory, and the failure that matters — a home it cannot write to — must end
in a shrug rather than a traceback in front of a person who only wanted to
close a notice.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from smbpal.gui import model, prefs


class TestWhereItGoes(unittest.TestCase):
    def test_xdg_config_home_is_honoured(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": home}):
                self.assertEqual(prefs.config_dir(), Path(home) / "smbpal")

    def test_a_relative_xdg_config_home_is_ignored(self) -> None:
        """The spec says a relative value must be treated as unset.

        Honouring it would put the file wherever the window happened to be
        started from, which is both wrong and unfindable.
        """
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "relative/path"}):
            self.assertEqual(prefs.config_dir(), Path.home() / ".config" / "smbpal")

    def test_an_empty_xdg_config_home_is_ignored(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": ""}):
            self.assertEqual(prefs.config_dir(), Path.home() / ".config" / "smbpal")


class TestRememberingIt(unittest.TestCase):
    def setUp(self) -> None:
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        patched = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.home.name})
        patched.start()
        self.addCleanup(patched.stop)

    def test_nothing_is_dismissed_before_anything_is(self) -> None:
        self.assertEqual(prefs.dismissed(), frozenset())
        self.assertFalse(prefs.is_dismissed(model.NO_TRAY))

    def test_a_dismissal_survives(self) -> None:
        prefs.dismiss(model.NO_TRAY)
        self.assertTrue(prefs.is_dismissed(model.NO_TRAY))

    def test_dismissing_it_twice_writes_it_once(self) -> None:
        prefs.dismiss(model.NO_TRAY)
        prefs.dismiss(model.NO_TRAY)
        path = Path(self.home.name) / "smbpal" / prefs.FILE_NAME
        self.assertEqual(path.read_text(encoding="utf-8"), f"{model.NO_TRAY}\n")

    def test_a_second_key_does_not_lose_the_first(self) -> None:
        prefs.dismiss(model.NO_TRAY)
        prefs.dismiss("something-a-later-version-added")
        self.assertEqual(
            prefs.dismissed(),
            frozenset({model.NO_TRAY, "something-a-later-version-added"}),
        )

    def test_a_key_nobody_recognises_is_carried_not_dropped(self) -> None:
        """A downgrade must not silently un-dismiss what a newer version hid."""
        directory = Path(self.home.name) / "smbpal"
        directory.mkdir(parents=True)
        (directory / prefs.FILE_NAME).write_text("from-the-future\n", encoding="utf-8")
        prefs.dismiss(model.NO_TRAY)
        self.assertIn("from-the-future", prefs.dismissed())

    def test_blank_lines_are_not_keys(self) -> None:
        directory = Path(self.home.name) / "smbpal"
        directory.mkdir(parents=True)
        (directory / prefs.FILE_NAME).write_text("\n\n  \n", encoding="utf-8")
        self.assertEqual(prefs.dismissed(), frozenset())


class TestAHomeItCannotWrite(unittest.TestCase):
    """The window still opens, and the notice comes back next time."""

    def test_an_unwritable_config_home_is_not_a_crash(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            blocked = Path(parent) / "not-a-directory"
            blocked.write_text("", encoding="utf-8")
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(blocked)}):
                prefs.dismiss(model.NO_TRAY)
                self.assertFalse(prefs.is_dismissed(model.NO_TRAY))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
