"""`smbpal-gui`: a GTK application that is a third client of the D4 socket.

**Not a second daemon.** It holds no state the daemon does not hold, writes no
config, and touches no unit file. The one file it does write is
`smbpal.gui.prefs`, which remembers nothing about the machine — only that
somebody told a notice to stop appearing. Everything it does is a method the CLI can
call too, which is why every behaviour it has could be found by driving the CLI
first — the working method the Pi runs have justified twice now.

`GLib.idle_add` is the whole of the threading contract: `Session` runs the
sockets on its own threads and calls back through whatever function it is
given, and this is the one place that function is GTK's.
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
from typing import Callable

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gio, GLib, Gtk  # noqa: E402

from smbpal.gui import APP_ID, model  # noqa: E402
from smbpal.gui.session import Session  # noqa: E402
from smbpal.gui.window import Window, install_css  # noqa: E402
from smbpal.ipc.client import Client  # noqa: E402
from smbpal.ipc.server import DEFAULT_SOCKET_PATH  # noqa: E402


log = logging.getLogger(__name__)

# Application actions that open the window with a form already up, keyed by
# the command-line flag's spelling, valued by the window action behind the
# header bar's Add button. The tray's New Share and New Connection items run
# `smbpal-gui --new-share` and `--new-connection`.
FORMS = {"new-share": "add-share", "new-connection": "add-connection"}

# The same name `smbpal.gui.tray` registers with. Nobody owning it means no
# tray icon can appear, from SMBPal or anyone.
WATCHER_NAME = "org.kde.StatusNotifierWatcher"

# How long to let the desktop finish starting before believing there is no
# tray. A panel that starts after the window would otherwise flash a notice
# and take it away again, which is worse than either answer on its own.
SETTLE_SECONDS = 3


def installer() -> str | None:
    """Which package manager to name in a notice, or none to name.

    By what is on `PATH`, not by reading `/etc/os-release`: a derivative can
    call itself anything and still be apt, and a machine with neither should
    be told to install the extension without being told a lie about how.
    """
    for name in ("apt", "dnf"):
        if shutil.which(name):
            return name
    return None


def to_main_thread(callback: Callable[[], None]) -> None:
    """Run it on the GTK main loop.

    `idle_add` re-queues while the callback returns True, so the explicit
    `GLib.SOURCE_REMOVE` matters: without it a callback that happened to return
    a truthy value would run forever.
    """
    GLib.idle_add(lambda: (callback(), GLib.SOURCE_REMOVE)[1])


class Application(Gtk.Application):
    def __init__(self, socket_path: str) -> None:
        super().__init__(
            application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE
        )
        self.socket_path = socket_path
        self.session: Session | None = None
        self._watch = 0
        self._tray_host = True

    def do_startup(self) -> None:  # noqa: N802 - GObject vfunc name
        Gtk.Application.do_startup(self)
        install_css()
        for name, form in FORMS.items():
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", self._open_form, form)
            self.add_action(action)

    def _open_form(self, _action: Gio.SimpleAction, _param: object, form: str) -> None:
        """The window first, then its form — the same one the Add button opens.

        Through the window's own action rather than building the dialog here,
        so a second request raises the form already open instead of stacking
        another: `add_menu` keeps that one-per-kind rule and this reuses it.
        """
        self.activate()
        window = self.get_active_window()
        action = window.lookup_action(form) if window is not None else None
        if action is None:
            log.error("no window action %s to open", form)
            return
        action.activate(None)

    def do_activate(self) -> None:  # noqa: N802 - GObject vfunc name
        window = self.get_active_window()
        if window is not None:
            window.present()
            return
        self.session = Session(
            lambda: Client(self.socket_path), to_main_thread=to_main_thread
        )
        window = Window(self, self.session)
        window.present()
        self._watch_tray_host(window)
        self.session.start()
        # After the window is on screen, not before: the first `status` reply
        # has nowhere to go until there is something to draw it on.
        self.session.refresh()

    # --- is anything hosting tray icons ------------------------------------

    def _watch_tray_host(self, window: Window) -> None:
        """Tell the window when this desktop turns out to have no tray.

        Here rather than in `Window` because it needs the session bus, and the
        window is deliberately testable without one. A watch, not a one-off
        question, so that a panel starting late takes the notice away again.
        """
        try:
            self._watch = Gio.bus_watch_name(
                Gio.BusType.SESSION,
                WATCHER_NAME,
                Gio.BusNameWatcherFlags.NONE,
                lambda *_a: self._tray_host_is(window, True),
                lambda *_a: self._tray_host_is(window, False),
            )
        except GLib.Error as exc:  # pragma: no cover - needs a broken bus
            log.debug("cannot watch %s: %s", WATCHER_NAME, exc)

    def _tray_host_is(self, window: Window, present: bool) -> None:
        self._tray_host = present
        if present:
            window.show_notice(None)
            return
        GLib.timeout_add_seconds(SETTLE_SECONDS, self._no_tray_host, window)

    def _no_tray_host(self, window: Window) -> bool:
        if not self._tray_host:
            log.info("nothing on this desktop is hosting tray icons")
            window.show_notice(
                model.tray_notice(
                    desktop=os.environ.get("XDG_CURRENT_DESKTOP", ""),
                    installer=installer(),
                )
            )
        return GLib.SOURCE_REMOVE

    def do_shutdown(self) -> None:  # noqa: N802 - GObject vfunc name
        if self._watch:
            Gio.bus_unwatch_name(self._watch)
            self._watch = 0
        if self.session is not None:
            self.session.stop()
            self.session = None
        Gtk.Application.do_shutdown(self)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="smbpal-gui", description="SMBPal")
    parser.add_argument(
        "--socket",
        default=str(DEFAULT_SOCKET_PATH),
        help="path to the daemon's socket (for testing against a second daemon)",
    )
    parser.add_argument("--debug", action="store_true", help="log at debug level")
    forms = parser.add_mutually_exclusive_group()
    for name in FORMS:
        forms.add_argument(
            f"--{name}",
            dest="form",
            action="store_const",
            const=name,
            help=f"open the window with the {name.replace('-', ' ')} form up",
        )
    args, rest = parser.parse_known_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    application = Application(args.socket)
    if args.form is None:
        return application.run([sys.argv[0], *rest])
    # **Registered first, because a flag is not something `run` forwards.**
    # With `FLAGS_NONE` a second launch sends the running instance a bare
    # Activate and exits, so `--new-share` would only raise the window. An
    # action is forwarded: on a remote instance `activate_action` is a D-Bus
    # call to the primary, which runs the handler there.
    application.register(None)
    if application.get_is_remote():
        application.activate_action(args.form, None)
        # The call is queued, not sent; exiting now can drop it.
        connection = application.get_dbus_connection()
        if connection is not None:
            connection.flush_sync(None)
        return 0
    GLib.idle_add(
        lambda: (application.activate_action(args.form, None), GLib.SOURCE_REMOVE)[1]
    )
    return application.run([sys.argv[0], *rest])


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
