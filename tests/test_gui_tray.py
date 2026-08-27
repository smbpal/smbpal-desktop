"""The tray's D-Bus surface, called the way GDBus calls it.

**This file is the exception to the suite's no-dependency rule, and it skips
rather than breaking it.** Everywhere else, `gi` is kept out so the tests run
on any machine with a bare Python. That split made every *decision* in M6
testable and left the plumbing completely unexercised — and the plumbing is
where the tray's first real bug lived: `_property_read` declared the `GError **`
that `GDBusInterfaceGetPropertyFunc` takes in C and PyGObject does not pass on,
so every property read raised `TypeError`. The item registered, announced
itself, and answered nothing. The panel drew no icon and said nothing about
why.

A real bus would be better and is not available here — macOS has no
`dbus-daemon`, so `Gio.TestDBus` cannot start one. What *is* available is
calling the vtable handlers with the exact arguments GDBus passes, which is the
thing that was wrong, and checking each returned variant against the type the
introspection XML promises.
"""

from __future__ import annotations

import pathlib
import unittest
import xml.etree.ElementTree as ET
from typing import Any

try:
    from gi.repository import Gio, GLib
except ImportError:  # pragma: no cover - a machine without python3-gi
    Gio = None
    GLib = None

if Gio is not None:
    from smbpal.gui import model
    from smbpal.gui.tray import ICONS, INTROSPECTION, ITEM_INTERFACE, ITEM_PATH, Tray


class FakeSession:
    """Enough of a Session for `Tray` to attach its callbacks to."""

    on_screen = None
    on_event = None
    on_error = None
    on_daemon_lost = None
    on_daemon_back = None

    def __init__(self) -> None:
        self.refreshed = 0

    def refresh(self) -> None:
        self.refreshed += 1


class FakeInvocation:
    def __init__(self) -> None:
        self.returned: list[Any] = []

    def return_value(self, value: Any) -> None:
        self.returned.append(value)


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestTheItemsProperties(unittest.TestCase):
    def setUp(self) -> None:
        self.session = FakeSession()
        self.launched: list[list[str]] = []
        self.tray = Tray(self.session, launch=["/bin/true"])
        self.tray.open_window = lambda: self.launched.append(["opened"])
        self.declared = Gio.DBusNodeInfo.new_for_xml(INTROSPECTION).interfaces[0]

    def read(self, name: str) -> Any:
        """Exactly the arguments GDBus passes: no GError, no user data."""
        return self.tray._property_read(None, ":1.2", ITEM_PATH, ITEM_INTERFACE, name)

    def test_every_declared_property_answers(self) -> None:
        """The bug this file exists for. Six parameters raised on all of them."""
        for prop in self.declared.properties:
            with self.subTest(property=prop.name):
                self.assertIsNotNone(
                    self.read(prop.name), f"{prop.name} is declared and unanswered"
                )

    def test_every_answer_matches_the_type_the_xml_promises(self) -> None:
        """A wrong signature is refused by the bus, not by Python."""
        for prop in self.declared.properties:
            with self.subTest(property=prop.name):
                self.assertEqual(
                    self.read(prop.name).get_type_string(), prop.signature
                )

    def test_a_property_nobody_declared_is_not_a_crash(self) -> None:
        self.assertIsNone(self.read("NotAThing"))

    def test_the_item_is_never_passive(self) -> None:
        """`Passive` hides the icon, and the empty case is when it is needed."""
        for screen in (
            model.Screen(),
            model.screen({"connections": [{"id": "a", "state": "idle"}]}),
            model.screen({"shares": [{"id": "s", "name": "S", "state": "serving"}]}),
        ):
            with self.subTest(screen=screen.problems):
                self.tray._screen_changed(screen)
                self.assertNotEqual(self.read("Status").get_string(), "Passive")

    def test_a_problem_reaches_the_panel_as_NeedsAttention(self) -> None:
        self.tray._screen_changed(
            model.screen(
                {"connections": [{"id": "a", "state": "unreachable", "message": "no"}]}
            )
        )
        self.assertEqual(self.read("Status").get_string(), "NeedsAttention")
        self.assertEqual(self.read("IconName").get_string(), ICONS[model.PROBLEM])

    def test_the_tooltip_carries_both_axes(self) -> None:
        self.tray._screen_changed(
            model.screen({"connections": [{"id": "a", "state": "connected"}]})
        )
        icon, pixmaps, title, body = self.read("ToolTip").unpack()
        self.assertEqual(title, "SMBPal")
        self.assertEqual(pixmaps, [])
        self.assertIn("Nothing shared from this computer", body)
        self.assertIn("1 share connected", body)
        self.assertTrue(icon)

    def test_left_click_is_not_a_menu(self) -> None:
        """`ItemIsMenu` true would make a panel open a menu we do not export."""
        self.assertFalse(self.read("ItemIsMenu").get_boolean())


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestTheItemsMethods(unittest.TestCase):
    def setUp(self) -> None:
        self.tray = Tray(FakeSession(), launch=["/bin/true"])
        self.opened: list[bool] = []
        self.tray.open_window = lambda: self.opened.append(True)

    def call(self, method: str) -> FakeInvocation:
        """The seven arguments `GDBusInterfaceMethodCallFunc` passes."""
        invocation = FakeInvocation()
        self.tray._method_called(
            None,
            ":1.2",
            ITEM_PATH,
            ITEM_INTERFACE,
            method,
            GLib.Variant("(ii)", (0, 0)),
            invocation,
        )
        return invocation

    def test_every_click_opens_the_window(self) -> None:
        """Including the right one: 3g has no context menu, and a right click
        that does nothing reads as a broken icon."""
        for method in ("Activate", "SecondaryActivate", "ContextMenu"):
            with self.subTest(method=method):
                self.opened.clear()
                self.call(method)
                self.assertEqual(len(self.opened), 1)

    def test_every_call_is_answered(self) -> None:
        """A method that never returns leaves the panel waiting on a timeout."""
        for method in [m.name for m in
                       Gio.DBusNodeInfo.new_for_xml(INTROSPECTION).interfaces[0].methods]:
            with self.subTest(method=method):
                self.assertEqual(self.call(method).returned, [None])

    def test_scrolling_does_not_open_anything(self) -> None:
        self.call("Scroll")
        self.assertEqual(self.opened, [])


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestWhatTheTrayDoesWithoutABus(unittest.TestCase):
    def test_state_changes_before_registration_do_not_raise(self) -> None:
        """The first `status` reply can beat the bus name being acquired."""
        tray = Tray(FakeSession())
        tray._screen_changed(model.screen({"shares": [{"id": "s", "name": "S"}]}))
        tray._event({"id": "s", "state": "connected"})
        self.assertTrue(tray.indicator.title)

    def test_a_daemon_that_stops_is_shown_as_a_problem(self) -> None:
        tray = Tray(FakeSession())

        class Gone(Exception):
            message = "the daemon closed the connection"

        tray._daemon_lost(Gone())
        self.assertEqual(tray.indicator.status, model.PROBLEM)
        self.assertIn("already up are unaffected", tray.indicator.detail)

    def test_recovery_asks_for_the_state_again(self) -> None:
        session = FakeSession()
        tray = Tray(session)
        tray._daemon_back()
        self.assertEqual(session.refreshed, 1)


class TestTheIconsExist(unittest.TestCase):
    """The one thing that made the tray look broken twice over.

    An icon name a theme cannot resolve makes some panels draw nothing at all,
    which is indistinguishable from the item never having registered. This ran
    for a whole hardware session that way. Nothing else connects the names in
    `ICONS` to the files in `packaging/icons`, and a rename on either side is
    silent — so this is the join.

    No `gi` needed, so it runs everywhere the rest of the suite does.
    """

    ICON_DIR = (
        pathlib.Path(__file__).resolve().parent.parent
        / "packaging/icons/hicolor/scalable/status"
    )

    def test_every_name_the_tray_asks_for_is_a_file_we_ship(self) -> None:
        # `model`, not `tray`: no gi, so this runs everywhere.
        from smbpal.gui.model import ICONS as names

        for status, name in names.items():
            with self.subTest(status=status):
                self.assertTrue(
                    (self.ICON_DIR / f"{name}.svg").is_file(),
                    f"the tray asks for {name!r} and nothing installs it",
                )

    def test_the_icons_are_valid_svg(self) -> None:
        for path in sorted(self.ICON_DIR.glob("*.svg")):
            with self.subTest(icon=path.name):
                ET.parse(path)  # raises on malformed XML

    def test_attention_is_distinguishable_without_colour(self) -> None:
        """A panel may render into a monochrome theme.

        The attention icon carries a badge — extra shapes — so it does not rely
        on being red. Counted rather than eyeballed, because "it looks
        different" is not something a test can hold.
        """
        def shapes(name: str) -> int:
            root = ET.parse(self.ICON_DIR / f"{name}.svg").getroot()
            return sum(1 for _ in root.iter() if _.tag.split("}")[-1]
                       in ("path", "rect", "circle"))

        self.assertGreater(shapes("smbpal-attention"), shapes("smbpal"))


if __name__ == "__main__":
    unittest.main()
