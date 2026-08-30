"""`smbpal-tray`: the icon, as StatusNotifierItem spoken directly over GDBus.

3g decided this and the shape follows from two facts. **A tray that exists only
while the window is open is pointless**, so it is a long-lived session process
with an XDG autostart entry — the fourth entry point and the third client of
the D4 socket. **And it cannot live in the daemon**, which runs as root: a tray
icon is a per-user session object and root cannot own one.

**No `libayatana-appindicator3`.** It is GTK3-linked, and GTK3 and GTK4 cannot
be loaded into one process. `python3-gi` already provides `Gio`, so speaking
`org.kde.StatusNotifierItem` by hand adds code and no dependency. It also keeps
this process free of GTK entirely: the tray imports `Gio` and `GLib`, never
`Gtk`, so it costs a session process that is mostly a socket and a timer.

What the icon shows is `model.indicator` and is decided there, under test. This
module is the D-Bus half: register, publish properties, emit the three change
signals, and turn a click into a running window.

**Clicking runs `smbpal-gui`.** That is not a shortcut around D-Bus activation
— the GUI is a `Gio.Application` with a fixed application id, so a second
launch raises the window the first one owns instead of starting another. 3g
called that part free, and this is where it is collected.
"""

from __future__ import annotations

import argparse
import logging
import os
import shlex
import shutil
import sys
from typing import Any

from gi.repository import Gio, GLib

from smbpal.gui import model
from smbpal.gui.session import Session
from smbpal.ipc.client import Client
from smbpal.ipc.server import DEFAULT_SOCKET_PATH

log = logging.getLogger(__name__)

WATCHER_NAME = "org.kde.StatusNotifierWatcher"
WATCHER_PATH = "/StatusNotifierWatcher"
ITEM_INTERFACE = "org.kde.StatusNotifierItem"
ITEM_PATH = "/StatusNotifierItem"
MENU_INTERFACE = "com.canonical.dbusmenu"
MENU_PATH = "/MenuBar"

# **The name that makes this a singleton, and it cannot be the item's.**
# `org.kde.StatusNotifierItem-<pid>-1` is PID-scoped by the spec, so two trays
# never contend for it — they each take their own and the panel draws two
# icons. That is what happened on the Pi on 29 August 2026 and why the
# "is a tray already running?" error had never once fired.
SINGLETON_NAME = "org.smbpal.Tray"

# **Evaluated at import, so that getting a name wrong is an ImportError.**
# `REPLACE` is GLib's spelling. The D-Bus wire protocol calls the same bit
# `DBUS_NAME_FLAG_REPLACE_EXISTING`, and writing that here cost a Pi login:
# `Gio.BusNameOwnerFlags.REPLACE_EXISTING` does not exist, `main` raised
# `AttributeError` before `loop.run`, and the packaged tray died at startup
# while two survivors from earlier logins went on drawing icons — which looks
# exactly like the guard failing rather than never running.
#
# ALLOW_REPLACEMENT lets a newer tray take the name from us; REPLACE takes it
# from whoever holds it now. Both, because this process is on both sides of
# that trade over its life.
SINGLETON_FLAGS = (
    Gio.BusNameOwnerFlags.ALLOW_REPLACEMENT | Gio.BusNameOwnerFlags.REPLACE
)

# dbusmenu item ids. 0 is the root by convention; the menu holds one item.
ROOT_ID = 0
QUIT_ID = 1

# Which icon for which status is `model.ICONS`, with the rest of the
# decisions. Re-exported so `from ...tray import ICONS` keeps working.
ICONS = model.ICONS

# `Passive` tells the panel to hide the item. It is never used: see
# `model.Indicator` for why an icon that disappears when nothing is configured
# disappears exactly when it is needed.
_SNI_STATUS = {model.PROBLEM: "NeedsAttention"}

# Only what the spec requires of an item without a menu. `ItemIsMenu` false is
# the part that makes a left click reach `Activate` rather than opening one.
INTROSPECTION = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <method name="Activate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="SecondaryActivate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="ContextMenu">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="Scroll">
      <arg name="delta" type="i" direction="in"/>
      <arg name="orientation" type="s" direction="in"/>
    </method>
    <signal name="NewIcon"/>
    <signal name="NewAttentionIcon"/>
    <signal name="NewStatus"><arg name="status" type="s"/></signal>
    <signal name="NewToolTip"/>
  </interface>
</node>
"""

# The menu, as a second interface on a second object path. All of it is owed
# for one item: on Wayland a client cannot place a popup at the panel's
# coordinates — it has no surface there — so the panel draws the menu and this
# is the only way to describe one to it. Plan §3g decided Quit as the only
# item; the interface cost is the same either way and the item count is not.
MENU_INTROSPECTION = """
<node>
  <interface name="com.canonical.dbusmenu">
    <property name="Version" type="u" access="read"/>
    <property name="TextDirection" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconThemePath" type="as" access="read"/>
    <method name="GetLayout">
      <arg name="parentId" type="i" direction="in"/>
      <arg name="recursionDepth" type="i" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="revision" type="u" direction="out"/>
      <arg name="layout" type="(ia{sv}av)" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg name="ids" type="ai" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="properties" type="a(ia{sv})" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg name="id" type="i" direction="in"/>
      <arg name="name" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="Event">
      <arg name="id" type="i" direction="in"/>
      <arg name="eventId" type="s" direction="in"/>
      <arg name="data" type="v" direction="in"/>
      <arg name="timestamp" type="u" direction="in"/>
    </method>
    <method name="EventGroup">
      <arg name="events" type="a(isvu)" direction="in"/>
      <arg name="idErrors" type="ai" direction="out"/>
    </method>
    <method name="AboutToShow">
      <arg name="id" type="i" direction="in"/>
      <arg name="needUpdate" type="b" direction="out"/>
    </method>
    <method name="AboutToShowGroup">
      <arg name="ids" type="ai" direction="in"/>
      <arg name="updatesNeeded" type="ai" direction="out"/>
      <arg name="idErrors" type="ai" direction="out"/>
    </method>
    <signal name="ItemsPropertiesUpdated">
      <arg name="updatedProps" type="a(ia{sv})"/>
      <arg name="removedProps" type="a(ias)"/>
    </signal>
    <signal name="LayoutUpdated">
      <arg name="revision" type="u"/>
      <arg name="parent" type="i"/>
    </signal>
    <signal name="ItemActivationRequested">
      <arg name="id" type="i"/>
      <arg name="timestamp" type="u"/>
    </signal>
  </interface>
</node>
"""


class Tray:
    """One StatusNotifierItem, fed by the same `Session` the window uses."""

    # The menu never changes, so the revision never has to. It exists in the
    # protocol for menus that rebuild themselves; this one is one item.
    menu_revision = 1

    def __init__(
        self,
        session: Session,
        *,
        launch: str | list[str] = "smbpal-gui",
        icon: str | None = None,
    ) -> None:
        self.session = session
        # An override for one name, used for every state. SMBPal's own icons do
        # not exist until M7 installs them under hicolor, and a panel that
        # cannot resolve a name may draw nothing at all — which is
        # indistinguishable from the item not being there. Pointing this at an
        # icon the theme certainly has separates the two.
        self.icon_override = icon
        # A list, always. Before M7 there is no `smbpal-gui` on PATH — the Pi
        # runs from a source tree because Trixie refuses `pip install` (PEP
        # 668) — so the command has to be able to be `python3 -m
        # smbpal.gui.app --socket …`, which is four words and not one.
        self.launch = [launch] if isinstance(launch, str) else list(launch)
        self.indicator = model.indicator(model.Screen())
        self._screen = model.Screen()
        self._connection: Gio.DBusConnection | None = None
        self._registration = 0
        self._menu_registration = 0
        self.bus_name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        # Set by `main`, so that both ways out of the process — the menu's Quit
        # and losing the singleton name to a newer tray — go through one place.
        self.on_quit: Any = None

        self._offline: str | None = None
        self._watcher_present = False

        session.on_screen = self._screen_changed
        session.on_event = self._event
        session.on_daemon_lost = self._daemon_lost
        session.on_daemon_back = self._daemon_back

    # --- state -------------------------------------------------------------

    def _screen_changed(self, screen: model.Screen) -> None:
        self._screen = screen
        self._republish()

    def _event(self, data: dict[str, Any]) -> None:
        # The point of M5, and the reason this process is worth running: a
        # mount that drops changes the icon without anybody asking it to.
        self._screen = model.Screen(
            shares=self._screen.shares,
            connections=model.apply_event(self._screen.connections, data),
            unaccounted=self._screen.unaccounted,
            daemon=self._screen.daemon,
        )
        self._republish()

    def _daemon_lost(self, exc: Any) -> None:
        self._offline = exc.message
        self._republish()

    def _daemon_back(self) -> None:
        self._offline = None
        self.session.refresh()

    def _republish(self) -> None:
        current = (
            model.offline_indicator(self._offline)
            if self._offline is not None
            else model.indicator(self._screen)
        )
        before, self.indicator = self.indicator, current
        if self._connection is None:
            return
        if before.status != self.indicator.status:
            self._emit("NewIcon")
            self._emit("NewAttentionIcon")
            self._emit("NewStatus", GLib.Variant("(s)", (self.sni_status,)))
        if (before.title, before.detail) != (
            self.indicator.title,
            self.indicator.detail,
        ):
            self._emit("NewToolTip")

    @property
    def sni_status(self) -> str:
        return _SNI_STATUS.get(self.indicator.status, "Active")

    @property
    def icon_name(self) -> str:
        if self.icon_override:
            return self.icon_override
        return ICONS.get(self.indicator.status, "smbpal")

    @property
    def attention_icon_name(self) -> str:
        """**A constant, and that is the whole point.**

        A host displays this one *instead of* `IconName` whenever `Status` is
        `NeedsAttention`, so the only state it is ever seen in is the problem
        state. Answering it with `icon_name` — whatever we happen to be showing
        — looked equivalent and was not: a panel reads it once at registration,
        when nothing is connected yet and `icon_name` is `smbpal-idle`, caches
        that, and then draws the cached grey icon for every problem thereafter.
        On the Pi that was a tray that went *grey* for a failed mount and again
        for a server that stopped answering, with the correct message in the
        tooltip both times — the one state that must look alarming was the one
        that looked calm.
        """
        if self.icon_override:
            return self.icon_override
        return ICONS[model.PROBLEM]

    # --- D-Bus -------------------------------------------------------------

    def register(self, connection: Gio.DBusConnection) -> None:
        self._connection = connection
        node = Gio.DBusNodeInfo.new_for_xml(INTROSPECTION)
        self._registration = connection.register_object(
            ITEM_PATH,
            node.interfaces[0],
            self._method_called,
            self._property_read,
            None,
        )
        if not self._registration:
            # Zero is the failure return. Without this the tray goes on to
            # announce itself to the watcher and then answers nothing, which
            # looks exactly like a panel that does not support SNI.
            log.error("could not export %s; the icon will not work", ITEM_PATH)
        menu_node = Gio.DBusNodeInfo.new_for_xml(MENU_INTROSPECTION)
        self._menu_registration = connection.register_object(
            MENU_PATH,
            menu_node.interfaces[0],
            self._menu_method_called,
            self._menu_property_read,
            None,
        )
        if not self._menu_registration:
            # Not fatal, unlike the item: the icon still works and clicking it
            # still opens the window. What is lost is the only way to stop the
            # tray from inside SMBPal, which is worth saying out loud.
            log.error("could not export %s; there will be no menu", MENU_PATH)
        self.announce()

    def watcher_appeared(self, *_a: Any) -> None:
        """The watcher is on the bus, which is not the same as it always was.

        At login the panel and this process start together and the ordering
        is a coin flip, so announcing once at startup registers with a
        watcher that may not exist yet and then never tries again. That is
        invisible when the tray is started by hand from a terminal, because
        by then the panel has been up for hours -- which is every way this
        was tested before a Pi ran it from `~/.config/autostart` and no icon
        appeared. A panel that restarts mid-session is the same fault with a
        different trigger, and this covers both.
        """
        self._watcher_present = True
        self.announce()

    def watcher_vanished(self, *_a: Any) -> None:
        self._watcher_present = False
        log.info("%s is not on the bus; waiting for it", WATCHER_NAME)

    def announce(self) -> None:
        """Tell the watcher we exist. Without this the panel never looks.

        Both conditions are guarded rather than assumed, because either can
        arrive first, and announcing exactly once per (bus name, watcher)
        pairing is what keeps a re-announce from becoming a second icon.
        """
        if self._connection is None or not self._watcher_present:
            return
        self._connection.call(
            WATCHER_NAME,
            WATCHER_PATH,
            WATCHER_NAME,
            "RegisterStatusNotifierItem",
            GLib.Variant("(s)", (self.bus_name,)),
            None,
            Gio.DBusCallFlags.NONE,
            -1,
            None,
            self._announced,
        )

    def _announced(self, source: Gio.DBusConnection, result: Gio.AsyncResult) -> None:
        try:
            source.call_finish(result)
        except GLib.Error as exc:
            # The watcher is on the bus and refused us, which is a different
            # thing from there being no watcher -- that case never reaches
            # here at all now, and is logged by watcher_vanished. Not fatal
            # and not silent: the tray is the only part of SMBPal that can
            # simply be absent on a working desktop, and somebody looking for
            # it deserves to find out why from the log.
            log.warning(
                "%s refused the registration, so there will be no tray icon: %s",
                WATCHER_NAME,
                exc.message,
            )
        else:
            log.info("registered with %s as %s", WATCHER_NAME, self.bus_name)

    def _emit(self, signal: str, parameters: GLib.Variant | None = None) -> None:
        if self._connection is None:
            return
        self._connection.emit_signal(
            None, ITEM_PATH, ITEM_INTERFACE, signal, parameters
        )

    def _property_read(
        self,
        _connection: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _interface: str,
        name: str,
    ) -> GLib.Variant | None:
        """Five arguments, not six.

        `GDBusInterfaceGetPropertyFunc` takes a `GError **` before the user
        data, but it is an out-parameter and PyGObject does not pass it into
        Python. Declaring it meant every property read on the item raised
        `TypeError`, so the panel could not read `Status` or `IconName` and
        drew nothing at all — a tray that registers successfully and is
        invisible. Pinned by a test that calls this the way GDBus does.
        """
        if name == "Category":
            return GLib.Variant("s", "SystemServices")
        if name == "Id":
            return GLib.Variant("s", "smbpal")
        if name == "Title":
            return GLib.Variant("s", "SMBPal")
        if name == "Status":
            return GLib.Variant("s", self.sni_status)
        if name == "IconName":
            return GLib.Variant("s", self.icon_name)
        if name == "AttentionIconName":
            return GLib.Variant("s", self.attention_icon_name)
        if name == "ItemIsMenu":
            # Still false, and the menu does not change it. False means a left
            # click reaches `Activate` and opens the window, which is what the
            # icon is mostly for; the menu is what a right click gets.
            return GLib.Variant("b", False)
        if name == "Menu":
            return GLib.Variant("o", MENU_PATH)
        if name == "ToolTip":
            # (icon name, pixmaps, title, body). The pixmap array stays empty:
            # a themed name is what M7 ships and what a panel can restyle.
            #
            # The title slot carries `indicator.title` and not the application
            # name. `Title` above is already the item's name and that is the
            # property panels use for it, so spending this slot on "SMBPal"
            # said it twice and dropped the summary entirely. It showed up on
            # the Pi as a daemon-down tooltip reading "the daemon closed the
            # connection" -- `ipc.client`'s words for itself -- where
            # `offline_indicator` had written "SMBPal's service is not
            # running" for a person to read. Some panels show only this slot.
            return GLib.Variant(
                "(sa(iiay)ss)",
                (self.icon_name, [], self.indicator.title, self.indicator.detail),
            )
        return None

    def _method_called(
        self,
        _connection: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _interface: str,
        method: str,
        _parameters: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        if method in ("Activate", "SecondaryActivate", "ContextMenu"):
            # A host that reads `Menu` draws the menu itself on a right click
            # and never calls `ContextMenu`. One that ignores `Menu` still
            # does, and there is no menu this process can draw for it — on
            # Wayland it has no surface at the panel's coordinates. Opening the
            # window is the honest answer for that host; a right click that
            # does nothing reads as the icon being broken.
            self.open_window()
        invocation.return_value(None)

    # --- the menu ----------------------------------------------------------

    def _menu_properties(self, item_id: int) -> dict[str, Any]:
        """One item's properties, in dbusmenu's vocabulary."""
        if item_id == ROOT_ID:
            return {"children-display": GLib.Variant("s", "submenu")}
        if item_id == QUIT_ID:
            return {
                "label": GLib.Variant("s", "Quit SMBPal"),
                "enabled": GLib.Variant("b", True),
                "visible": GLib.Variant("b", True),
            }
        return {}

    def _filtered(self, item_id: int, wanted: list[str]) -> dict[str, Any]:
        """`propertyNames` empty means all of them, which is what panels send."""
        properties = self._menu_properties(item_id)
        if not wanted:
            return properties
        return {k: v for k, v in properties.items() if k in wanted}

    def menu_layout(self, parent: int, wanted: list[str]) -> Any:
        """The `(u(ia{sv}av))` GetLayout answers with.

        **Built in one call and not assembled from finished variants.** A
        `GLib.Variant` already built cannot be nested inside another by format
        string — PyGObject descends into it with the remaining format instead
        of taking it whole, and raises `TypeError: Expected GLib.Variant, but
        got str` from somewhere several levels down that names nothing in this
        file. The one exception is an `av` element, which is boxed correctly
        from a built variant and has to be, because the layout type is
        recursive and there is no other way to express a child.
        """
        if parent == QUIT_ID:
            return GLib.Variant(
                "(u(ia{sv}av))",
                (self.menu_revision, (QUIT_ID, self._filtered(QUIT_ID, wanted), [])),
            )
        child = GLib.Variant(
            "(ia{sv}av)", (QUIT_ID, self._filtered(QUIT_ID, wanted), [])
        )
        return GLib.Variant(
            "(u(ia{sv}av))",
            (self.menu_revision, (ROOT_ID, self._filtered(ROOT_ID, wanted), [child])),
        )

    def _menu_property_read(
        self,
        _connection: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _interface: str,
        name: str,
    ) -> GLib.Variant | None:
        """Five arguments, for the same reason `_property_read` takes five."""
        if name == "Version":
            return GLib.Variant("u", 3)
        if name == "TextDirection":
            return GLib.Variant("s", "ltr")
        if name == "Status":
            # dbusmenu's Status, which is "normal" or "notice" and is about the
            # menu wanting attention. Nothing to do with the item's Status.
            return GLib.Variant("s", "normal")
        if name == "IconThemePath":
            return GLib.Variant("as", [])
        return None

    def _menu_method_called(
        self,
        _connection: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _interface: str,
        method: str,
        parameters: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        args = parameters.unpack()
        if method == "GetLayout":
            parent, _depth, wanted = args
            invocation.return_value(self.menu_layout(parent, list(wanted)))
            return
        if method == "GetGroupProperties":
            ids, wanted = args
            asked = list(ids) or [ROOT_ID, QUIT_ID]
            invocation.return_value(
                GLib.Variant(
                    "(a(ia{sv}))",
                    ([(i, self._filtered(i, list(wanted))) for i in asked],),
                )
            )
            return
        if method == "GetProperty":
            item_id, name = args
            value = self._menu_properties(item_id).get(name)
            # A property nobody has is answered with an empty string rather
            # than an error: it is what the C implementation does, and a panel
            # that asks for `icon-name` should get a menu, not an exception.
            invocation.return_value(
                GLib.Variant("(v)", (value or GLib.Variant("s", ""),))
            )
            return
        if method == "Event":
            item_id, event, _data, _timestamp = args
            self._menu_event(item_id, event)
            invocation.return_value(None)
            return
        if method == "EventGroup":
            for item_id, event, _data, _timestamp in args[0]:
                self._menu_event(item_id, event)
            invocation.return_value(GLib.Variant("(ai)", ([],)))
            return
        if method == "AboutToShow":
            # The menu is one static item, so it never needs rebuilding before
            # it opens. False is the answer that says so.
            invocation.return_value(GLib.Variant("(b)", (False,)))
            return
        if method == "AboutToShowGroup":
            invocation.return_value(GLib.Variant("(aiai)", ([], [])))
            return
        invocation.return_value(None)

    def _menu_event(self, item_id: int, event: str) -> None:
        """`clicked` on the one item is the only event that does anything.

        Hosts also send `hovered` and `opened`/`closed`, and quitting on a
        hover would be memorable. The event name is checked, not just the id.
        """
        if item_id == QUIT_ID and event == "clicked":
            log.info("quitting: the menu asked")
            self.quit()

    # --- stopping ----------------------------------------------------------

    def quit(self) -> None:
        if self.on_quit is None:
            log.warning("asked to quit with nothing to quit; ignoring")
            return
        self.on_quit()

    def name_lost(self, *_a: Any) -> None:
        """A newer tray took `SINGLETON_NAME`, so this one is the old one.

        **Last one wins, and the polarity is the whole decision.** The Pi grew
        two icons on 29 August 2026 because Debian ships logind with
        `KillUserProcesses=no`: the tray from the previous session survived the
        logout carrying the group set it had before `usermod`, and autostart
        started a second one that could actually reach the daemon. First-one-
        wins would hand the name to the survivor and exit the working
        instance, leaving only the broken icon. The newest instance is always
        the one holding the current session's credentials.
        """
        log.info("a newer tray took %s; quitting", SINGLETON_NAME)
        self.quit()

    # --- the click ---------------------------------------------------------

    def open_window(self) -> None:
        argv = list(self.launch)
        argv[0] = shutil.which(argv[0]) or argv[0]
        try:
            Gio.Subprocess.new(argv, Gio.SubprocessFlags.NONE)
        except GLib.Error as exc:
            log.error("could not start %s: %s", " ".join(argv), exc.message)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="smbpal-tray", description="SMBPal's tray icon (session process)"
    )
    parser.add_argument("--socket", default=str(DEFAULT_SOCKET_PATH))
    parser.add_argument(
        "--gui",
        default="smbpal-gui",
        help="the command a click runs, as a shell-style string. Defaults to "
        "the installed entry point; before M7 there is not one, so a source "
        "tree needs the whole line: "
        "--gui 'python3 -m smbpal.gui.app --socket /run/smbpald.sock'",
    )
    parser.add_argument(
        "--icon",
        help="use this themed icon name for every state, instead of SMBPal's "
        "own. SMBPal's are installed by M7; until then a panel that cannot "
        "resolve a name may draw nothing, which looks the same as the item "
        "not being registered. Try --icon folder-remote.",
    )
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    loop = GLib.MainLoop()
    session = Session(
        lambda: Client(args.socket),
        to_main_thread=lambda callback: GLib.idle_add(
            lambda: (callback(), GLib.SOURCE_REMOVE)[1]
        ),
    )
    tray = Tray(session, launch=shlex.split(args.gui), icon=args.icon)

    tray.on_quit = loop.quit

    def owned(connection: Gio.DBusConnection, _name: str) -> None:
        tray.register(connection)

    Gio.bus_own_name(
        Gio.BusType.SESSION,
        tray.bus_name,
        Gio.BusNameOwnerFlags.NONE,
        owned,
        None,
        # Not "is one already running?": the item name carries this process's
        # pid and nothing else can hold it. Reaching here means the session bus
        # refused it, which is a bus problem and not another tray.
        lambda *_a: log.error("the session bus refused %s", tray.bus_name),
    )
    # **The singleton, and it is a separate name on purpose.** See
    # SINGLETON_NAME: the item's name is pid-scoped and can never collide, so
    # the guard cannot be built on it. The flags are SINGLETON_FLAGS, resolved
    # at import rather than here, for the reason written above them. The
    # acquired callback is deliberately empty — owning the name is not what
    # starts the icon, and tying registration to it would mean a bus that
    # refused the name left the tray with no icon rather than a duplicate.
    Gio.bus_own_name(
        Gio.BusType.SESSION,
        SINGLETON_NAME,
        SINGLETON_FLAGS,
        None,
        None,
        tray.name_lost,
    )
    # Held for the life of the process: the watcher can come and go, and the
    # icon has to come back with it.
    Gio.bus_watch_name(
        Gio.BusType.SESSION,
        WATCHER_NAME,
        Gio.BusNameWatcherFlags.NONE,
        tray.watcher_appeared,
        tray.watcher_vanished,
    )

    session.start()
    session.refresh()
    try:
        loop.run()
    except KeyboardInterrupt:
        pass
    finally:
        session.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
