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
from smbpal.daemon.handlers import Authoriser, Dispatcher
from smbpal.discovery.advertise import DEFAULT_SERVICE_FILE, Advertiser
from smbpal.errors import SmbpalError
from smbpal.mounts.apply import Mounter
from smbpal.mounts.credentials import DEFAULT_CREDENTIALS_DIR, CredentialsStore
from smbpal.mounts.systemd import DEFAULT_UNIT_DIR
from smbpal.ipc.protocol import encode_event
from smbpal.samba.apply import DEFAULT_SMB_CONF, DEFAULT_SMBPAL_CONF, Applier
from smbpal.state.monitor import DEFAULT_INTERVAL, StateMonitor
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
    parser.add_argument(
        "--watch-interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="seconds between connection state checks (default %(default)s)",
    )
    parser.add_argument(
        "--no-apply",
        action="store_true",
        help="never touch Samba or Avahi; hold config only. For development on "
        "a machine without Samba installed.",
    )
    parser.add_argument(
        "--smb-conf", type=Path, default=DEFAULT_SMB_CONF, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--smbpal-conf", type=Path, default=DEFAULT_SMBPAL_CONF, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--avahi-service", type=Path, default=DEFAULT_SERVICE_FILE, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--unit-dir", type=Path, default=DEFAULT_UNIT_DIR, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--credentials-dir",
        type=Path,
        default=DEFAULT_CREDENTIALS_DIR,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--authorisation",
        default="polkit",
        choices=Authoriser.POLICIES,
        help="who may perform a mutating method. 'polkit' (default) asks polkit "
        "for the peer, which is what the package ships. 'root' allows uid 0 and "
        "refuses everyone else. 'group' allows anyone the socket let through, "
        "which is no authorisation at all and exists for development on a "
        "machine with no polkit; the daemon says so at startup.",
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

    applier: Applier | None = None
    mounter: Mounter | None = None
    if not args.no_apply:
        mounter = Mounter(
            unit_dir=args.unit_dir,
            credentials=CredentialsStore(args.credentials_dir),
        )
        applier = Applier(
            smb_conf=args.smb_conf,
            smbpal_conf=args.smbpal_conf,
            advertiser=Advertiser(args.avahi_service),
        )
        # §3f: reconcile at startup rather than trusting what is on disk. A
        # daemon that died with shares active leaves the service file behind,
        # and a stale record advertises a machine that may no longer be sharing.
        try:
            applier.advertiser.reconcile(
                len([s for s in config.get("shares", []) if s.get("enabled", True)])
            )
        except SmbpalError as exc:
            log.warning("could not reconcile the mDNS record: %s", exc.message)
    else:
        log.info("--no-apply: holding config only, not touching Samba or Avahi")

    monitor: StateMonitor | None = None
    if mounter is not None:
        monitor = StateMonitor(
            store,
            mounter,
            # D4's push channel, finally used: clients are told when a
            # connection changes rather than asking repeatedly.
            broadcast=lambda event, data: transport.broadcast(encode_event(event, data)),
            interval=args.watch_interval,
        )

    dispatcher = Dispatcher(
        store,
        authoriser=Authoriser(policy=args.authorisation),
        applier=applier,
        mounter=mounter,
        monitor=monitor,
    )
    # Logged at every start, not only when it is interesting. A line saying
    # which rules are in force is worth nothing if it only appears when they
    # are the weak ones, because then nobody has ever seen it and nobody reads
    # for its absence.
    log.info("%s", dispatcher.authoriser.policy_note())
    if args.authorisation == "group":
        log.warning(
            "authorisation is disabled: any process that can open the socket "
            "can change what this machine shares. Do not run this on a machine "
            "anyone else uses."
        )
    _install_signal_handlers(transport)
    if monitor is not None:
        monitor.start()
    _sd_notify("READY=1")
    log.info("smbpald %s ready", __version__)

    try:
        transport.serve_forever(dispatcher.handle)
    finally:
        _sd_notify("STOPPING=1")
        if monitor is not None:
            monitor.stop()
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
