"""`smbpal` — a client of the daemon, never a second writer of config (D12).

Every command is one IPC call. Nothing here reads or writes `/etc/smbpal`
directly, because two writers to one file is the bug D12 pays a round trip to
never have.

Exit codes, so scripts can tell the cases apart:

    0  it worked
    1  the daemon refused or failed
    2  the command line was wrong (argparse's own code)
    3  no daemon
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Callable

from smbpal import __version__
from smbpal.cli.format import render_json, render_table
from smbpal.errors import DaemonUnreachable, SmbpalError
from smbpal.ipc.client import Client
from smbpal.ipc.server import DEFAULT_SOCKET_PATH

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_DAEMON = 3

_AUTO_CONNECT = ("always", "on_this_network", "never")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smbpal", description="Manage SMB shares and connections."
    )
    parser.add_argument(
        "--socket", type=Path, default=DEFAULT_SOCKET_PATH, help="daemon socket path"
    )
    parser.add_argument(
        "--json", action="store_true", help="machine-readable output"
    )
    parser.add_argument("--version", action="version", version=f"smbpal {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    commands.required = True

    commands.add_parser("status", help="what is configured, and its state")
    commands.add_parser("ping", help="check the daemon is answering")

    browse = commands.add_parser("browse", help="find SMB servers on this network")
    browse.add_argument(
        "--timeout", type=float, default=5.0, help="seconds to listen (default 5)"
    )

    share = commands.add_parser("share", help="shares this machine serves")
    share_cmds = share.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")
    share_cmds.required = True
    share_cmds.add_parser("list", help="list configured shares")

    share_add = share_cmds.add_parser("add", help="define a share")
    share_add.add_argument("name", help="the share name clients will see")
    share_add.add_argument("path", help="the folder to share")
    share_add.add_argument("--id", help="stable id (derived from the name if omitted)")
    share_add.add_argument("--read-only", action="store_true", help="serve read-only")
    share_add.add_argument(
        "--disabled", action="store_true", help="define it without serving it"
    )
    share_add.add_argument("--credential", help="reference to a stored credential")

    share_remove = share_cmds.add_parser("remove", help="remove a share")
    share_remove.add_argument("ref", help="share id or name")

    connection = commands.add_parser(
        "connection", help="remote shares this machine mounts"
    )
    connection_cmds = connection.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")
    connection_cmds.required = True
    connection_cmds.add_parser("list", help="list configured connections")

    connection_add = connection_cmds.add_parser("add", help="define a connection")
    connection_add.add_argument("host", help="hostname or address of the server")
    connection_add.add_argument("share", help="share name on that server")
    connection_add.add_argument("mountpoint", help="where to mount it locally")
    connection_add.add_argument("--id", help="stable id (derived if omitted)")
    connection_add.add_argument(
        "--auto",
        choices=_AUTO_CONNECT,
        default="on_this_network",
        help="when to connect (default on_this_network)",
    )
    connection_add.add_argument("--credential", help="reference to a stored credential")

    connection_remove = connection_cmds.add_parser("remove", help="remove a connection")
    connection_remove.add_argument("ref", help="connection id or mountpoint")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = _COMMANDS[(args.command, getattr(args, "subcommand", None))]
    try:
        with Client(args.socket) as client:
            return handler(client, args)
    except DaemonUnreachable as exc:
        _fail(exc)
        return EXIT_NO_DAEMON
    except SmbpalError as exc:
        _fail(exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130


# --- commands --------------------------------------------------------------


def _cmd_ping(client: Client, args: argparse.Namespace) -> int:
    result = client.call("ping")
    return _emit(args, result, lambda: "the daemon is answering")


def _cmd_status(client: Client, args: argparse.Namespace) -> int:
    status = client.call("status")

    def human() -> str:
        daemon = status["daemon"]
        blocks = [
            f"smbpald {daemon['version']} (protocol {daemon['protocol']}), "
            f"pid {daemon['pid']}",
            f"config {daemon['config']}",
            "",
            _section(
                "Shares",
                status["shares"],
                ("id", "name", "path", "read_only", "enabled", "state"),
                "no shares configured",
            ),
            "",
            _section(
                "Connections",
                status["connections"],
                ("id", "host", "share", "mountpoint", "auto_connect", "state"),
                "no connections configured",
            ),
        ]
        return "\n".join(blocks)

    return _emit(args, status, human)


def _cmd_browse(client: Client, args: argparse.Namespace) -> int:
    machines = client.call("browse", {"timeout": args.timeout})

    def human() -> str:
        if not machines:
            return "no SMB servers found on this network"
        # Name is a name, not an address: `RASPBERRYPI` is Samba's NetBIOS name
        # and NetBIOS resolution is not available here (§3e). The columns keep
        # that distinction visible.
        return render_table(machines, ("name", "hostname", "addresses", "running_smbpal"))

    return _emit(args, machines, human)


def _cmd_share_list(client: Client, args: argparse.Namespace) -> int:
    shares = client.call("share.list")
    return _emit(
        args,
        shares,
        lambda: render_table(shares, ("id", "name", "path", "read_only", "enabled"))
        or "no shares configured",
    )


def _cmd_share_add(client: Client, args: argparse.Namespace) -> int:
    share = client.call(
        "share.add",
        {
            "name": args.name,
            # Resolved here, against the caller's working directory, because
            # that is whose `./media` it is — the daemon's cwd is not the
            # user's. The schema then rejects anything still not absolute.
            "path": _resolve(args.path),
            "id": args.id,
            "read_only": args.read_only,
            "enabled": not args.disabled,
            "credential_ref": args.credential,
        },
    )
    return _emit(
        args,
        share,
        lambda: f"added share {share['name']!r} ({share['id']}) at {share['path']}",
    )


def _cmd_share_remove(client: Client, args: argparse.Namespace) -> int:
    share = client.call("share.remove", {"ref": args.ref})
    return _emit(args, share, lambda: f"removed share {share['name']!r} ({share['id']})")


def _cmd_connection_list(client: Client, args: argparse.Namespace) -> int:
    connections = client.call("connection.list")
    return _emit(
        args,
        connections,
        lambda: render_table(
            connections, ("id", "host", "share", "mountpoint", "auto_connect")
        )
        or "no connections configured",
    )


def _cmd_connection_add(client: Client, args: argparse.Namespace) -> int:
    connection = client.call(
        "connection.add",
        {
            "host": args.host,
            "share": args.share,
            "mountpoint": _resolve(args.mountpoint),
            "id": args.id,
            "auto_connect": args.auto,
            "credential_ref": args.credential,
        },
    )
    return _emit(
        args,
        connection,
        lambda: f"added connection {connection['id']}: "
        f"//{connection['host']}/{connection['share']} -> {connection['mountpoint']}",
    )


def _cmd_connection_remove(client: Client, args: argparse.Namespace) -> int:
    connection = client.call("connection.remove", {"ref": args.ref})
    return _emit(args, connection, lambda: f"removed connection {connection['id']}")


# --- plumbing --------------------------------------------------------------

Handler = Callable[[Client, argparse.Namespace], int]

_COMMANDS: dict[tuple[str, str | None], Handler] = {
    ("ping", None): _cmd_ping,
    ("status", None): _cmd_status,
    ("browse", None): _cmd_browse,
    ("share", "list"): _cmd_share_list,
    ("share", "add"): _cmd_share_add,
    ("share", "remove"): _cmd_share_remove,
    ("connection", "list"): _cmd_connection_list,
    ("connection", "add"): _cmd_connection_add,
    ("connection", "remove"): _cmd_connection_remove,
}


def _resolve(path: str) -> str:
    # expanduser first: the shell expands `~` but only unquoted, and a quoted
    # "~/media" reaching us as a literal should still mean the home directory.
    return str(Path(path).expanduser().resolve())


def _section(
    title: str, rows: list[dict[str, Any]], columns: tuple[str, ...], empty: str
) -> str:
    body = render_table(rows, columns) if rows else f"  {empty}"
    if rows:
        body = "\n".join(f"  {line}" for line in body.splitlines())
    return f"{title}:\n{body}"


def _emit(args: argparse.Namespace, value: Any, human: Callable[[], str]) -> int:
    print(render_json(value) if args.json else human())
    return EXIT_OK


def _fail(exc: SmbpalError) -> None:
    # No traceback, ever. D12: "it must produce a clear error, not a stack trace."
    print(f"smbpal: {exc.message}", file=sys.stderr)
    if exc.detail:
        for line in exc.detail.splitlines():
            print(f"  {line}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
