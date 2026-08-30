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

import os
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
    from smbpal.gui.tray import (
        ICONS,
        INTROSPECTION,
        ITEM_INTERFACE,
        ITEM_PATH,
        MENU_INTERFACE,
        MENU_INTROSPECTION,
        MENU_PATH,
        QUIT_ID,
        ROOT_ID,
        SINGLETON_NAME,
        Tray,
    )


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


class FakeConnection:
    """Enough of a `Gio.DBusConnection` to see whether we announced."""

    def __init__(self) -> None:
        self.announcements: list[str] = []

    def register_object(self, *_a: Any) -> int:
        return 1

    def call(self, _name: str, _path: str, _iface: str, method: str, *_a: Any) -> None:
        self.announcements.append(method)


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
        self.assertEqual(title, "1 share connected")
        self.assertEqual(pixmaps, [])
        self.assertIn("Nothing shared from this computer", body)
        self.assertIn("1 share connected", body)
        self.assertTrue(icon)

    def test_the_tooltip_title_is_the_summary_and_not_the_application_name(
        self,
    ) -> None:
        """The daemon-down tooltip, pinned where it went wrong.

        This slot used to be the constant "SMBPal", which the `Title`
        property already says, so the sentence written for a person to read
        never left the process. On the Pi that surfaced as a tooltip quoting
        the IPC layer at the user instead.
        """
        self.tray._offline = "the daemon closed the connection"
        self.tray._republish()
        _, _, title, body = self.read("ToolTip").unpack()
        self.assertEqual(title, "SMBPal's service is not running")
        self.assertIn("the daemon closed the connection", body)
        self.assertIn("already up are unaffected", body)
        self.assertNotEqual(title, self.read("Title").get_string())

    def test_the_attention_icon_is_the_attention_icon_from_the_start(self) -> None:
        """The grey-tray bug, pinned at the property that caused it.

        A host reads this once, at registration, and shows it for every
        `NeedsAttention` afterwards. At registration nothing is connected yet,
        so answering with "the icon we are showing now" handed the panel
        `smbpal-idle` and it drew that, calmly, through a failed mount and
        through a server that had stopped answering.
        """
        self.assertEqual(
            self.read("AttentionIconName").get_string(), ICONS[model.PROBLEM]
        )

    def test_the_attention_icon_does_not_move_with_the_state(self) -> None:
        for screen in (
            model.Screen(),
            model.screen({"connections": [{"id": "a", "state": "connected"}]}),
            model.screen({"connections": [{"id": "a", "state": "unreachable"}]}),
        ):
            with self.subTest(screen=screen.problems):
                self.tray._screen_changed(screen)
                self.assertEqual(
                    self.read("AttentionIconName").get_string(), ICONS[model.PROBLEM]
                )

    def test_a_forced_icon_still_wins(self) -> None:
        """`--icon` exists to tell "resolved to nothing" from "never
        registered", so it has to override both names or it proves nothing."""
        tray = Tray(FakeSession(), icon="folder-remote")
        self.assertEqual(tray.attention_icon_name, "folder-remote")
        self.assertEqual(tray.icon_name, "folder-remote")

    def test_left_click_is_not_a_menu(self) -> None:
        """`ItemIsMenu` true would make a panel open a menu we do not export."""
        self.assertFalse(self.read("ItemIsMenu").get_boolean())


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestWhatTheItemTellsTheHostToRereRead(unittest.TestCase):
    """A property nobody is told to re-read is a property nobody re-reads."""

    def setUp(self) -> None:
        self.tray = Tray(FakeSession())
        self.emitted: list[str] = []
        self.tray._connection = object()  # enough for _republish to emit
        self.tray._emit = lambda signal, parameters=None: self.emitted.append(signal)

    def test_a_new_problem_announces_both_icons(self) -> None:
        self.tray._screen_changed(
            model.screen({"connections": [{"id": "a", "state": "unreachable"}]})
        )
        self.assertIn("NewIcon", self.emitted)
        self.assertIn("NewAttentionIcon", self.emitted)

    def test_every_signal_it_emits_is_one_it_declares(self) -> None:
        declared = {
            s.name
            for s in Gio.DBusNodeInfo.new_for_xml(INTROSPECTION).interfaces[0].signals
        }
        self.tray._screen_changed(
            model.screen({"connections": [{"id": "a", "state": "unreachable"}]})
        )
        self.assertTrue(self.emitted)
        for signal in self.emitted:
            with self.subTest(signal=signal):
                self.assertIn(signal, declared)


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


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestAnnouncingToAWatcherThatMayNotBeThereYet(unittest.TestCase):
    """The login race, pinned.

    The tray announced once, from the callback that takes its bus name, and
    never again. Started by hand that always works, because the panel has
    been up for hours. Started from `~/.config/autostart` the panel and this
    process start together, so the watcher is often not on the bus yet: the
    call failed, a warning went to a log nobody was reading, and the tray sat
    there correct and invisible for the whole session. It took a Pi, a
    logout and a canary `.desktop` to see it, because every test until this
    one started the tray by hand.
    """

    def setUp(self) -> None:
        self.tray = Tray(FakeSession())
        self.connection = FakeConnection()

    def test_it_does_not_announce_to_a_watcher_that_is_not_there(self) -> None:
        self.tray.register(self.connection)
        self.assertEqual(self.connection.announcements, [])

    def test_it_announces_when_the_watcher_turns_up(self) -> None:
        self.tray.register(self.connection)
        self.tray.watcher_appeared()
        self.assertEqual(
            self.connection.announcements, ["RegisterStatusNotifierItem"]
        )

    def test_the_watcher_may_also_be_there_first(self) -> None:
        """The other order, which is just as likely and fails differently."""
        self.tray.watcher_appeared()
        self.assertEqual(self.connection.announcements, [])
        self.tray.register(self.connection)
        self.assertEqual(
            self.connection.announcements, ["RegisterStatusNotifierItem"]
        )

    def test_a_panel_that_restarts_gets_the_icon_back(self) -> None:
        self.tray.register(self.connection)
        self.tray.watcher_appeared()
        self.tray.watcher_vanished()
        self.tray.watcher_appeared()
        self.assertEqual(len(self.connection.announcements), 2)

    def test_the_ordinary_startup_announces_exactly_once(self) -> None:
        """Two announcements can mean two icons, which step 4 checks for."""
        self.tray.register(self.connection)
        self.tray.watcher_appeared()
        self.assertEqual(len(self.connection.announcements), 1)


# The in-arguments each dbusmenu method takes, so that "every method is
# answered" can call all of them. A method that never returns leaves the panel
# waiting on a D-Bus timeout with its menu half-open.
MENU_CALLS = {
    "GetLayout": GLib.Variant("(iias)", (0, -1, [])) if GLib else None,
    "GetGroupProperties": GLib.Variant("(aias)", ([0, 1], [])) if GLib else None,
    "GetProperty": GLib.Variant("(is)", (1, "label")) if GLib else None,
    "Event": (
        GLib.Variant("(isvu)", (1, "hovered", GLib.Variant("s", ""), 0))
        if GLib
        else None
    ),
    "EventGroup": GLib.Variant("(a(isvu))", ([],)) if GLib else None,
    "AboutToShow": GLib.Variant("(i)", (0,)) if GLib else None,
    "AboutToShowGroup": GLib.Variant("(ai)", ([0],)) if GLib else None,
}


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestTheMenusProperties(unittest.TestCase):
    """The same shape as the item's property tests, for the same reason.

    `_menu_property_read` is a second `GDBusInterfaceGetPropertyFunc` and takes
    the same five arguments the item's does — the six-argument version is the
    bug this whole file was written for, and adding an interface is exactly
    where it would come back.
    """

    def setUp(self) -> None:
        self.tray = Tray(FakeSession(), launch=["/bin/true"])
        self.declared = Gio.DBusNodeInfo.new_for_xml(MENU_INTROSPECTION).interfaces[0]

    def read(self, name: str) -> Any:
        return self.tray._menu_property_read(
            None, ":1.2", MENU_PATH, MENU_INTERFACE, name
        )

    def test_every_declared_property_answers(self) -> None:
        for prop in self.declared.properties:
            with self.subTest(property=prop.name):
                self.assertIsNotNone(
                    self.read(prop.name), f"{prop.name} is declared and unanswered"
                )

    def test_every_answer_matches_the_type_the_xml_promises(self) -> None:
        for prop in self.declared.properties:
            with self.subTest(property=prop.name):
                self.assertEqual(self.read(prop.name).get_type_string(), prop.signature)

    def test_a_property_nobody_declared_is_not_a_crash(self) -> None:
        self.assertIsNone(self.read("NotAThing"))

    def test_the_item_points_at_the_menu(self) -> None:
        """Without `Menu` the panel has nothing to ask, and there is no menu."""
        menu = self.tray._property_read(
            None, ":1.2", ITEM_PATH, ITEM_INTERFACE, "Menu"
        )
        self.assertEqual(menu.get_string(), MENU_PATH)

    def test_a_left_click_still_reaches_activate(self) -> None:
        """`ItemIsMenu` true would make every click open the menu instead.

        The menu is for the right click. Opening the window is what the icon is
        mostly for, and it must survive the menu being added.
        """
        item_is_menu = self.tray._property_read(
            None, ":1.2", ITEM_PATH, ITEM_INTERFACE, "ItemIsMenu"
        )
        self.assertFalse(item_is_menu.get_boolean())


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestTheMenusLayout(unittest.TestCase):
    def setUp(self) -> None:
        self.tray = Tray(FakeSession(), launch=["/bin/true"])
        self.declared = Gio.DBusNodeInfo.new_for_xml(MENU_INTROSPECTION).interfaces[0]

    def call(self, method: str, parameters: Any = None) -> FakeInvocation:
        invocation = FakeInvocation()
        self.tray._menu_method_called(
            None,
            ":1.2",
            MENU_PATH,
            MENU_INTERFACE,
            method,
            parameters if parameters is not None else MENU_CALLS[method],
            invocation,
        )
        return invocation

    def signature(self, method: str) -> str:
        """The out-arguments the XML promises, as one tuple signature."""
        info = next(m for m in self.declared.methods if m.name == method)
        return "(" + "".join(a.signature for a in info.out_args) + ")"

    def test_every_method_is_answered(self) -> None:
        for method in MENU_CALLS:
            with self.subTest(method=method):
                self.assertEqual(len(self.call(method).returned), 1)

    def test_every_answer_matches_the_type_the_xml_promises(self) -> None:
        """A wrong signature is refused by the bus, not by Python.

        The layout type is `(ia{sv}av)` and recursive, which PyGObject will not
        let you assemble from finished variants — nesting a built one inside a
        format string makes it descend into the variant instead of taking it
        whole, and raises `TypeError: Expected GLib.Variant, but got str` from
        four frames down in `overrides/GLib.py`. This is the test that says the
        one construction that does work is still the one being used.
        """
        for method in MENU_CALLS:
            with self.subTest(method=method):
                returned = self.call(method).returned[0]
                if returned is None:
                    continue
                self.assertEqual(returned.get_type_string(), self.signature(method))

    def layout(self, parameters: Any = None) -> Any:
        return self.call("GetLayout", parameters).returned[0].unpack()

    def test_the_menu_holds_exactly_one_item_and_it_is_quit(self) -> None:
        _revision, (item_id, _properties, children) = self.layout()
        self.assertEqual(item_id, ROOT_ID)
        self.assertEqual(len(children), 1)
        child_id, properties, grandchildren = children[0]
        self.assertEqual(child_id, QUIT_ID)
        self.assertEqual(grandchildren, [])
        self.assertIn("Quit", properties["label"])
        self.assertTrue(properties["enabled"])
        self.assertTrue(properties["visible"])

    def test_the_root_says_it_has_a_submenu(self) -> None:
        """Without `children-display` a panel draws the root and no children."""
        _revision, (_id, properties, _children) = self.layout()
        self.assertEqual(properties.get("children-display"), "submenu")

    def test_asking_for_the_item_alone_gets_the_item(self) -> None:
        _revision, (item_id, properties, children) = self.layout(
            GLib.Variant("(iias)", (QUIT_ID, -1, []))
        )
        self.assertEqual(item_id, QUIT_ID)
        self.assertEqual(children, [])
        self.assertIn("label", properties)

    def test_a_panel_that_asks_for_one_property_gets_one(self) -> None:
        _revision, (_id, _properties, children) = self.layout(
            GLib.Variant("(iias)", (0, -1, ["label"]))
        )
        self.assertEqual(list(children[0][1]), ["label"])

    def test_group_properties_answers_for_every_id_asked(self) -> None:
        answered = self.call("GetGroupProperties").returned[0].unpack()[0]
        self.assertEqual([item_id for item_id, _p in answered], [ROOT_ID, QUIT_ID])

    def test_a_property_nobody_has_is_an_empty_string_not_an_error(self) -> None:
        """Panels ask for `icon-name` and `toggle-type` on every item.

        Returning an error there is a menu that does not open. The C
        implementation answers empty, so this does.
        """
        value = self.call(
            "GetProperty", GLib.Variant("(is)", (QUIT_ID, "icon-name"))
        ).returned[0]
        self.assertEqual(value.unpack()[0], "")

    def test_the_menu_never_needs_rebuilding_before_it_opens(self) -> None:
        self.assertFalse(self.call("AboutToShow").returned[0].unpack()[0])


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestStopping(unittest.TestCase):
    """The tray had no way to be stopped from any interface SMBPal offered.

    Raised on a Pi on 29 August 2026 — *"i can't stop the tray icon without a
    terminal command"* — and `pkill` is not an answer for an end user, on a
    system with no Startup Applications UI to disable the autostart entry from
    either.
    """

    def setUp(self) -> None:
        self.tray = Tray(FakeSession(), launch=["/bin/true"])
        self.quits = 0

        def quit() -> None:
            self.quits += 1

        self.tray.on_quit = quit

    def event(self, item_id: int, name: str) -> None:
        self.tray._menu_method_called(
            None,
            ":1.2",
            MENU_PATH,
            MENU_INTERFACE,
            "Event",
            GLib.Variant("(isvu)", (item_id, name, GLib.Variant("s", ""), 0)),
            FakeInvocation(),
        )

    def test_clicking_quit_quits(self) -> None:
        self.event(QUIT_ID, "clicked")
        self.assertEqual(self.quits, 1)

    def test_hovering_over_quit_does_not(self) -> None:
        """Panels send `hovered` as the pointer crosses the item."""
        for name in ("hovered", "opened", "closed"):
            with self.subTest(event=name):
                self.event(QUIT_ID, name)
        self.assertEqual(self.quits, 0)

    def test_clicking_the_root_does_not(self) -> None:
        self.event(ROOT_ID, "clicked")
        self.assertEqual(self.quits, 0)

    def test_a_click_delivered_in_a_group_still_quits(self) -> None:
        self.tray._menu_method_called(
            None,
            ":1.2",
            MENU_PATH,
            MENU_INTERFACE,
            "EventGroup",
            GLib.Variant(
                "(a(isvu))",
                ([(QUIT_ID, "clicked", GLib.Variant("s", ""), 0)],),
            ),
            FakeInvocation(),
        )
        self.assertEqual(self.quits, 1)

    def test_losing_the_singleton_name_quits(self) -> None:
        """Last one wins, and the polarity is the decision.

        `KillUserProcesses=no` means a tray survives its own logout carrying
        the group set it had before `usermod`. First-one-wins hands the name to
        that survivor and exits the instance that can actually reach the
        daemon, leaving only the broken icon on the panel.
        """
        self.tray.name_lost(None, SINGLETON_NAME)
        self.assertEqual(self.quits, 1)

    def test_quitting_before_the_loop_exists_is_not_a_crash(self) -> None:
        Tray(FakeSession()).quit()


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestTheNameThatMakesItASingleton(unittest.TestCase):
    def test_the_singleton_name_is_not_the_item_name(self) -> None:
        """The bug that produced two icons, pinned.

        `org.kde.StatusNotifierItem-<pid>-1` is pid-scoped by the spec, so two
        trays never contend for it — they take one each and the panel draws
        two. A guard built on it can never fire, which is why the one that was
        there never did.
        """
        one, two = Tray(FakeSession()), Tray(FakeSession())
        self.assertNotEqual(SINGLETON_NAME, one.bus_name)
        self.assertNotIn(str(os.getpid()), SINGLETON_NAME)
        self.assertEqual(one.bus_name, two.bus_name)  # same process, same pid

    def test_it_is_a_valid_well_known_bus_name(self) -> None:
        self.assertTrue(Gio.dbus_is_name(SINGLETON_NAME))
        self.assertFalse(SINGLETON_NAME.startswith(":"))
