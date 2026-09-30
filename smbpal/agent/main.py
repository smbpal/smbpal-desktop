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
    parser.add_argument(
        "--check",
        action="store_true",
        help="say whether this platform is supported, and exit",
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
        # what is wrong *and* what this platform uses instead (D14).
        print(
            f"smbpal-agent: this is {sys.platform}, where mounting belongs to "
            "smbpald and needs no agent",
            file=sys.stderr,
        )
        return 1

    path = args.socket or default_socket_path()
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

    _install_signal_handlers(transport)
    log.info("smbpal-agent %s listening on %s (uid %s)", __version__, path, os.getuid())
    try:
        transport.serve_forever(dispatcher.handle)
    finally:
        transport.shutdown()
    return 0


def _install_signal_handlers(transport: UnixSocketTransport) -> None:
    def stop(_signum: int, _frame: FrameType | None) -> None:
        transport.shutdown()

    for received in (signal.SIGINT, signal.SIGTERM):
        signal.signal(received, stop)


if __name__ == "__main__":
    raise SystemExit(main())
