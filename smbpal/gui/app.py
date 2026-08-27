"""`smbpal-gui`: a GTK application that is a third client of the D4 socket.

**Not a second daemon.** It holds no state the daemon does not hold, writes no
config, and touches no unit file. Everything it does is a method the CLI can
call too, which is why every behaviour it has could be found by driving the CLI
first — the working method the Pi runs have justified twice now.

`GLib.idle_add` is the whole of the threading contract: `Session` runs the
sockets on its own threads and calls back through whatever function it is
given, and this is the one place that function is GTK's.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Callable

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gio, GLib, Gtk  # noqa: E402

from smbpal.gui.session import Session  # noqa: E402
from smbpal.gui.window import Window, install_css  # noqa: E402
from smbpal.ipc.client import Client  # noqa: E402
from smbpal.ipc.server import DEFAULT_SOCKET_PATH  # noqa: E402

# Provisional until M7 settles the packaging identity: this string ends up in
# the .desktop file name, the icon name and the tray's bus name, and changing
# it after those exist is three coordinated renames.
APP_ID = "org.smbpal.Smbpal"

log = logging.getLogger(__name__)


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

    def do_startup(self) -> None:  # noqa: N802 - GObject vfunc name
        Gtk.Application.do_startup(self)
        install_css()

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
        self.session.start()
        # After the window is on screen, not before: the first `status` reply
        # has nowhere to go until there is something to draw it on.
        self.session.refresh()

    def do_shutdown(self) -> None:  # noqa: N802 - GObject vfunc name
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
    args, rest = parser.parse_known_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    return Application(args.socket).run([sys.argv[0], *rest])


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
