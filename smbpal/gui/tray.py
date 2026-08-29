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


class Tray:
    """One StatusNotifierItem, fed by the same `Session` the window uses."""

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
        self.bus_name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"

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
            return GLib.Variant("b", False)
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
            # Every click opens the window, including the right one. 3g decided
            # against a context menu, and a right click that does nothing reads
            # as the icon being broken.
            self.open_window()
        invocation.return_value(None)

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

    def owned(connection: Gio.DBusConnection, _name: str) -> None:
        tray.register(connection)

    Gio.bus_own_name(
        Gio.BusType.SESSION,
        tray.bus_name,
        Gio.BusNameOwnerFlags.NONE,
        owned,
        None,
        lambda *_a: log.error("could not take the bus name; is a tray already running?"),
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
