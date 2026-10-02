"""smbpal-agent entry point.

Deliberately shaped like `smbpald`'s: parse, bind, serve, and remove the socket
on the way out. What differs is everything the daemon needs because it acts for
everyone — no polkit, no group on the socket, no config store — and the
difference is the point rather than an economy.

**The socket is the user's and the mode says so.** `0600` under the user's own
Application Support directory, which is per-user and survives a reboot in a way
`$TMPDIR` does not. `ipc/peer.py` then checks the caller's uid from the kernel,
so the file mode and the check agree rather than one standing in for the other.

**It runs on Linux and refuses to do anything**, because CI is Linux and an
entry point that cannot be imported is worse than one that explains itself.

**And it installs itself**, with `--install` writing the LaunchAgent plist and
loading it. That belongs to the program rather than to the packaging for a
reason `agent/launchd.py` gives in full: the path launchd must run depends on
the Homebrew prefix, so the plist cannot be a static file the way
`smbpald.service` is.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from pathlib import Path
from types import FrameType

from smbpal import __version__, version_banner
from smbpal.agent.handlers import AgentDispatcher
from smbpal.agent import launchd
from smbpal.errors import SmbpalError
from smbpal.ipc.server import UnixSocketTransport
from smbpal.mounts import netfs

log = logging.getLogger(__name__)


def default_socket_path() -> Path:
    """Per-user, stable across reboots, and somewhere a person can find it."""
    return (
        Path.home() / "Library" / "Application Support" / "SMBPal" / "agent.sock"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smbpal-agent",
        description="Mounts shares in this user's session (macOS).",
    )
    parser.add_argument("--version", action="store_true")
    parser.add_argument(
        "--socket",
        type=Path,
        default=None,
        help="socket path (default: this user's Application Support)",
    )
    # One of these or none: each inspects or changes the installation and then
    # exits, so asking for two is asking for two different things at once.
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--check",
        action="store_true",
        help="say whether this platform is supported, and exit",
    )
    actions.add_argument(
        "--install",
        action="store_true",
        help="write the LaunchAgent plist, load it, and start mounting for this "
        "user at every login",
    )
    actions.add_argument(
        "--uninstall",
        action="store_true",
        help="unload the LaunchAgent and remove its plist",
    )
    actions.add_argument(
        "--status",
        action="store_true",
        help="say whether the LaunchAgent is installed, loaded, and still "
        "pointing at this copy of the program",
    )
    parser.add_argument(
        "--program",
        type=Path,
        default=None,
        help="the path to write into the plist (default: this program). Needed "
        "only when installing from a checkout rather than from an install.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.version:
        print(version_banner("smbpal-agent"), end="")
        return 0

    if args.check:
        print(
            "supported"
            if netfs.available()
            else f"not supported on {sys.platform}: mounting here is the daemon's"
        )
        return 0 if netfs.available() else 1

    if not netfs.available():
        # The rule from netfs.py, restated where somebody would meet it: say
        # what is wrong *and* what this platform uses instead (D14). It covers
        # --install too: there is no launchd here, and the thing that does this
        # job on Linux is `systemctl enable --now smbpald`.
        print(
            f"smbpal-agent: this is {sys.platform}, where mounting belongs to "
            "smbpald and needs no agent. The equivalent of --install here is "
            "`sudo systemctl enable --now smbpald`.",
            file=sys.stderr,
        )
        return 1

    path = args.socket or default_socket_path()

    if args.install or args.uninstall or args.status:
        try:
            return _manage(args, path)
        except SmbpalError as exc:
            print(f"smbpal-agent: {exc.message}", file=sys.stderr)
            if exc.detail:
                print(f"  {exc.detail}", file=sys.stderr)
            return 1

    path.parent.mkdir(parents=True, exist_ok=True)
    # The directory too: a 0600 socket inside a world-readable directory still
    # tells anyone who looks that this user runs SMBPal and what they mount.
    os.chmod(path.parent, 0o700)

    dispatcher = AgentDispatcher()
    transport = UnixSocketTransport(path, group=None, mode=0o600)

    try:
        transport.bind()
    except SmbpalError as exc:
        print(f"smbpal-agent: {exc.message}", file=sys.stderr)
        return 1
    except OSError as exc:
        # The transport raises OSError with a sentence in it, and smbpald's main
        # catches it exactly here. Without this clause the agent's only output on
        # a bind failure is a Python traceback in a log file — which is how
        # `AF_UNIX path too long` was found on 2 October 2026, under launchd,
        # where there is no terminal for it to go to.
        print(f"smbpal-agent: cannot bind {path}: {exc}", file=sys.stderr)
        return 2

    _install_signal_handlers(transport)
    log.info("smbpal-agent %s listening on %s (uid %s)", __version__, path, os.getuid())
    try:
        transport.serve_forever(dispatcher.handle)
    finally:
        transport.shutdown()
    return 0


def _problem(line: str) -> None:
    """A diagnostic on stderr, after whatever is already on stdout.

    The flush is not decoration. stdout is block-buffered as soon as it is a
    pipe rather than a terminal, so without it every one of these lines jumps
    above the block it is about — in exactly the case where the output is being
    saved or sent to somebody.
    """
    sys.stdout.flush()
    print(line, file=sys.stderr)


def _manage(args: argparse.Namespace, socket: Path) -> int:
    """--install, --uninstall and --status, which all report and exit."""
    if args.install:
        done = launchd.install(program=args.program, socket=socket)
        print(f"installed {done['label']}")
        print(f"  plist   {done['plist']}")
        print(f"  program {done['program']}")
        print(f"  socket  {done['socket']}")
        print(f"  log     {done['log']}")
        if done["replaced"]:
            print("  replaced the copy that was already loaded")
        # "started", not "running": a pid is what launchd reported at that
        # instant, and a program that dies a moment later does not make it a
        # lie -- but calling it "running" would claim a state nothing has
        # checked. `--status` is the thing that answers that question.
        print(f"  started as pid {done['pid']}" if done["pid"] else "  not running yet")
        return 0

    if args.uninstall:
        done = launchd.uninstall(socket=socket)
        if not done["was_loaded"] and not done["plist_existed"]:
            # Not an error: `--uninstall` twice should be quiet the second
            # time, and so should it on a machine that never installed.
            print(f"{done['label']} was not installed")
            return 0
        print(f"removed {done['label']}")
        if done["was_loaded"]:
            print("  unloaded it from launchd")
        if done["plist_existed"]:
            print(f"  deleted {done['plist']}")
        if done["socket_removed"]:
            print("  removed the socket it was holding")
        return 0

    state = launchd.status(socket=socket, program=args.program)
    print(state["label"])
    print(f"  plist   {state['plist']}" if state["installed"] else "  not installed")
    if state["installed"]:
        print(f"  program {state['program']}")
        print(
            f"  socket  {state['socket']}"
            f"{'' if state['socket_present'] else ' (not there yet)'}"
        )
    print(f"  log     {state['log']}")
    if not state["loaded"]:
        print("  launchd does not have it loaded")
        print("  install it with: smbpal-agent --install")
    elif state["failing"]:
        _problem(f"  launchd has it, and {state['failing']}")
    else:
        print(f"  running as pid {state['pid'] or '-'}")
    for problem in state["stale"]:
        # The other half of what --status is for: a job launchd describes
        # perfectly well and cannot actually start, because what it names has
        # moved.
        _problem(f"  stale: {problem}")
    if state["stale"]:
        _problem("  fix it with: smbpal-agent --install")
    return 0 if state["ok"] else 1


def _install_signal_handlers(transport: UnixSocketTransport) -> None:
    def stop(_signum: int, _frame: FrameType | None) -> None:
        transport.shutdown()

    for received in (signal.SIGINT, signal.SIGTERM):
        signal.signal(received, stop)


if __name__ == "__main__":
    raise SystemExit(main())
