"""smbpald entry point.

M1: start, load the config, hold the socket, and do nothing else. The value is
in what it refuses to do — it will not start on a config it cannot parse, it
will not start on a socket another daemon owns, and it removes the socket on the
way out.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import sys
from pathlib import Path
from types import FrameType

from smbpal import __version__
from smbpal.config import ConfigStore
from smbpal.config.store import DEFAULT_CONFIG_PATH
from smbpal.daemon.handlers import Dispatcher
from smbpal.errors import SmbpalError
from smbpal.ipc.server import (
    DEFAULT_SOCKET_GROUP,
    DEFAULT_SOCKET_PATH,
    UnixSocketTransport,
)

log = logging.getLogger("smbpald")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smbpald", description="SMBPal daemon (system service, runs as root)"
    )
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_CONFIG_PATH, help="config file path"
    )
    parser.add_argument(
        "--socket", type=Path, default=DEFAULT_SOCKET_PATH, help="socket path"
    )
    parser.add_argument(
        "--socket-group",
        default=DEFAULT_SOCKET_GROUP,
        help="group given access to the socket; empty string to leave it alone",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=("debug", "info", "warning", "error"),
        help="logging verbosity",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the config and exit without binding anything",
    )
    parser.add_argument("--version", action="version", version=f"smbpald {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.log_level)

    store = ConfigStore(args.config)
    try:
        config = store.load()
    except SmbpalError as exc:
        # Refusing to start is the point. Starting with an empty config looks
        # exactly like "all your shares are gone", and the next save would make
        # that true.
        log.error("%s", exc.message)
        if exc.detail:
            log.error("%s", exc.detail)
        return 2

    log.info(
        "config %s: %d share(s), %d connection(s)",
        args.config,
        len(config.get("shares", [])),
        len(config.get("connections", [])),
    )
    if args.check:
        log.info("config is valid")
        return 0

    transport = UnixSocketTransport(
        args.socket, group=args.socket_group or None
    )
    try:
        transport.bind()
    except OSError as exc:
        log.error("cannot bind %s: %s", args.socket, exc)
        return 2

    dispatcher = Dispatcher(store)
    log.info("%s", dispatcher.authoriser.policy_note())
    _install_signal_handlers(transport)
    _sd_notify("READY=1")
    log.info("smbpald %s ready", __version__)

    try:
        transport.serve_forever(dispatcher.handle)
    finally:
        _sd_notify("STOPPING=1")
        transport.shutdown()
    return 0


def _configure_logging(level: str) -> None:
    # No timestamps: under systemd the journal supplies them, and duplicating
    # them makes every line harder to read.
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _install_signal_handlers(transport: UnixSocketTransport) -> None:
    def stop(signum: int, _frame: FrameType | None) -> None:
        log.info("received %s, shutting down", signal.Signals(signum).name)
        transport.shutdown()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)


def _sd_notify(state: str) -> None:
    """Tell systemd we are ready, if it is listening.

    Type=notify means `systemctl start` returns when the socket is actually
    accepting, so a CLI invoked straight afterwards cannot race the daemon.
    Twelve lines of stdlib rather than a dependency on python3-systemd.
    """
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):  # abstract namespace
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(state.encode("utf-8"))
    except OSError as exc:
        log.debug("sd_notify(%s) failed: %s", state, exc)


if __name__ == "__main__":
    raise SystemExit(main())
