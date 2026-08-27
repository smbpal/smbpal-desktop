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
import getpass
import os
import sys
from pathlib import Path
from typing import Any, Callable

from smbpal import __version__
from smbpal.cli.format import render_json, render_table
from smbpal.errors import DaemonUnreachable, NotFound, SmbpalError
from smbpal.ipc.client import Client
from smbpal.ipc.server import DEFAULT_SOCKET_PATH
from smbpal.samba.passwd import posix_user_exists

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
    share_add.add_argument(
        "--user",
        dest="credential",
        help="the system account this share is served as (§3b). Without it the "
        "share has no 'valid users' line and SMBPal cannot check whether the "
        "folder is writable.",
    )

    share_remove = share_cmds.add_parser("remove", help="remove a share")
    share_remove.add_argument("ref", help="share id or name")

    writable = share_cmds.add_parser(
        "make-writable",
        help="give the share's folder to its user so the share can be written",
    )
    writable.add_argument("ref", help="share id or name")

    commands.add_parser(
        "apply",
        help="re-apply the whole config: Samba's shares and the mount units both",
    )

    teardown = commands.add_parser(
        "teardown",
        help="undo everything SMBPal put outside its config, keeping the config",
    )
    teardown.add_argument(
        "--yes", action="store_true", help="do not ask for confirmation"
    )

    credential = commands.add_parser("credential", help="SMB passwords")
    credential_cmds = credential.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")
    credential_cmds.required = True
    credential_cmds.add_parser("list", help="list SMB accounts")
    credential_set = credential_cmds.add_parser("set", help="set an SMB password")
    credential_set.add_argument("username", help="an existing system account")
    credential_set.add_argument(
        "--stdin", action="store_true", help="read the password from stdin"
    )
    credential_remove = credential_cmds.add_parser(
        "remove", help="remove an SMB account, leaving the system account alone"
    )
    credential_remove.add_argument("username")

    connection = commands.add_parser(
        "connection", help="remote shares this machine mounts"
    )
    connection_cmds = connection.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")
    connection_cmds.required = True
    connection_cmds.add_parser("list", help="list configured connections")

    connection_add = connection_cmds.add_parser("add", help="define a connection")
    connection_add.add_argument("host", help="hostname or address of the server")
    connection_add.add_argument("share", help="share name on that server")
    connection_add.add_argument(
        "mountpoint",
        nargs="?",
        help="where to mount it locally. Omit and SMBPal picks a place the "
        "file manager will show it, named after the share.",
    )
    connection_add.add_argument("--id", help="stable id (derived if omitted)")
    connection_add.add_argument(
        "--auto",
        choices=_AUTO_CONNECT,
        default="on_this_network",
        help="when to connect (default on_this_network)",
    )
    connection_add.add_argument(
        "--user", help="username on the remote server (you will be asked for the password)"
    )
    connection_add.add_argument(
        "--owner",
        help="local account the mounted files belong to (defaults to you, or to "
        "$SUDO_USER when run under sudo)",
    )
    connection_add.add_argument("--domain", help="Windows domain, if the server wants one")
    connection_add.add_argument(
        "--fallback",
        help="address to fall back to if the host name stops resolving. Recorded "
        "only — SMBPal never switches to it on its own, because the address may "
        "since belong to a different machine.",
    )
    connection_add.add_argument(
        "--stdin-password", action="store_true", help="read the password from stdin"
    )

    connection_remove = connection_cmds.add_parser("remove", help="remove a connection")
    connection_remove.add_argument("ref", help="connection id or mountpoint")

    connection_connect = connection_cmds.add_parser(
        "connect", help="mount now, without waiting for first access"
    )
    connection_connect.add_argument("ref", help="connection id or mountpoint")
    connection_disconnect = connection_cmds.add_parser(
        "disconnect", help="unmount now (the automount will remount on next access)"
    )
    connection_disconnect.add_argument("ref", help="connection id or mountpoint")

    connection_cmds.add_parser(
        "live",
        help="mounts and units on this machine that the config does not describe",
    )

    use_fallback = connection_cmds.add_parser(
        "use-fallback", help="swap the host for its recorded fallback address"
    )
    use_fallback.add_argument("ref", help="connection id or mountpoint")

    watch = commands.add_parser(
        "watch", help="follow connection state as it changes"
    )
    watch.add_argument(
        "--once", action="store_true", help="print the current state and exit"
    )

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
                ("id", "name", "path", "enabled", "state"),
                "no shares configured",
            ),
            "",
            _section(
                "Connections",
                status["connections"],
                ("id", "host", "share", "mountpoint", "state"),
                "no connections configured",
            ),
        ]
        blocks.extend(connection_notes(status["connections"]))
        blocks.extend(unaccounted_notes(status.get("unaccounted", [])))
        return "\n".join(blocks)

    return _emit(args, status, human)


def connection_notes(connections: list[dict[str, Any]]) -> list[str]:
    """The sentence behind each one-word state, for the states that need one.

    M0 §4's whole point: `No such device` is not a reason. The table's state
    column is one word, so anything a person has to act on gets its sentence
    underneath.

    **`read_only` is here as well as `is_problem`.** A read-only mount is not a
    failure — it is `connected`, correctly — but the one word alone hides the
    only thing the person needs to know, and they will go looking at the
    mountpoint's ownership instead. Same reason §3c labels a read-only share
    with *why* rather than just showing it as served.
    """
    notes: list[str] = []
    for connection in connections:
        if not (connection.get("is_problem") or connection.get("read_only")):
            continue
        notes.append(f"  ! {connection['id']}: {connection['message']}")
        if connection.get("hint"):
            notes.append(f"    {connection['hint']}")
    return notes


def unaccounted_notes(findings: list[dict[str, Any]]) -> list[str]:
    """What is on the machine that the config does not describe.

    **Printed by `status` rather than waiting to be asked for.** The Pi run
    that produced this had an empty config, a correct `connection list`, and a
    share mounting on access — and the only reason it was noticed was that the
    person already knew the mountpoint. A report you have to suspect something
    to run is not a report.
    """
    if not findings:
        return []
    lines = ["", f"Not in the config ({len(findings)}):"]
    for finding in findings:
        source = finding.get("source") or "nothing mounted"
        lines.append(f"  ! {finding['mountpoint']} <- {source}")
        lines.append(f"    {finding['message']}")
    return lines


def _cmd_connection_live(client: Client, args: argparse.Namespace) -> int:
    findings = client.call("connection.live")

    def human() -> str:
        if not findings:
            return "nothing on this machine is unaccounted for"
        return "\n".join(unaccounted_notes(findings)).lstrip("\n")

    return _emit(args, findings, human)


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


def _cmd_apply(client: Client, args: argparse.Namespace) -> int:
    report = client.call("apply")

    def human() -> str:
        served = ", ".join(report["served"]) or "nothing"
        lines = [f"serving {served}"]
        if report["advertising"]:
            lines.append("advertising _smbpal._tcp")
        # Apply does both halves. Reporting only the Samba one made `serving
        # nothing` look like "did nothing" on a machine with two connections
        # mounted, which is how the missing half was found.
        summary = _connection_summary(report.get("connections", []))
        if summary:
            lines.append(summary)
        lines.extend(_read_only_notes(report["shares"]))
        return "\n".join(lines)

    return _emit(args, report, human)


_TEARDOWN_WARNING = """\
This removes SMBPal's include block from smb.conf, the smbpal.conf it
generates, its mount units and mountpoints, and its mDNS record.

Your configuration is kept — `smbpal apply` puts all of it back."""


def _confirm(prompt: str) -> bool:
    try:
        answer = input(f"{prompt} [y/N] ")
    except EOFError:
        # Piped in with nothing to say. Silence is not consent for this one.
        return False
    return answer.strip().lower() in {"y", "yes"}


def _cmd_teardown(client: Client, args: argparse.Namespace) -> int:
    if not args.yes:
        print(_TEARDOWN_WARNING)
        if not _confirm("Continue?"):
            print("cancelled; nothing was changed")
            return EXIT_OK
    result = client.call("teardown")

    def human() -> str:
        lines = []
        if result.get("include_removed"):
            lines.append(f"removed the include block from {result['smb_conf']}")
        if result.get("smbpal_conf_removed"):
            lines.append("removed the generated smbpal.conf")
        for unit in result.get("units_removed", []):
            lines.append(f"removed {unit}")
        # Naming the files is the point: "done" is not something anyone can
        # check, and `diff` against a pristine smb.conf is.
        return "\n".join(lines) or "nothing to undo"

    return _emit(args, result, human)


def _connection_summary(connections: list[dict[str, Any]]) -> str:
    """`connections: 2 mounted` — counted by state, or nothing to say.

    Counts rather than names, because the states are what a person is checking
    after an apply and `status` is where the per-connection detail lives.
    """
    if not connections:
        return ""
    counts: dict[str, int] = {}
    for connection in connections:
        state = connection.get("state") or "unknown"
        counts[state] = counts.get(state, 0) + 1
    parts = [f"{count} {state}" for state, count in sorted(counts.items())]
    return "connections: " + ", ".join(parts)


def _cmd_share_make_writable(client: Client, args: argparse.Namespace) -> int:
    result = client.call("share.make_writable", {"ref": args.ref})

    def human() -> str:
        # Report the resulting state rather than claiming a change: the owner
        # is often already right and only the mode moved.
        directory = result["directory"]
        lines = [
            f"{directory['path']} is writable by the share's user "
            f"(owner {directory['owner']}, mode {directory['mode']})"
        ]
        if result.get("note"):
            lines.append(f"  {result['note']}")
        return "\n".join(lines)

    return _emit(args, result, human)


def _cmd_credential_list(client: Client, args: argparse.Namespace) -> int:
    users = client.call("credential.list")
    return _emit(
        args,
        users,
        lambda: "\n".join(users) if users else "no SMB accounts",
    )


def _cmd_credential_set(client: Client, args: argparse.Namespace) -> int:
    # §3b: check the account exists *before* asking for anything. smbpasswd
    # prompts twice and only then fails, so without this the user types a
    # password that is thrown away and gets an error too late to mean anything.
    # Checked here rather than over IPC because the CLI is on the same host by
    # construction — it is a Unix socket — so it is reading the same passwd.
    if not posix_user_exists(args.username):
        _fail(
            NotFound(
                f"there is no system account called {args.username!r}",
                detail="Samba attaches an SMB password to an existing POSIX "
                "account; it cannot create one. Phase 1 shares as an existing "
                "user (§3b).",
            )
        )
        return EXIT_ERROR

    if args.stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        # getpass, so it is never echoed, never in the shell history and never
        # in argv (M0 §9).
        password = getpass.getpass(f"New SMB password for {args.username}: ")
        if password != getpass.getpass("Retype: "):
            print("smbpal: the passwords did not match", file=sys.stderr)
            return EXIT_ERROR
    if not password:
        print("smbpal: the password must not be empty", file=sys.stderr)
        return EXIT_ERROR

    result = client.call(
        "credential.set", {"username": args.username, "password": password}
    )
    return _emit(args, result, lambda: f"set the SMB password for {args.username}")


def _cmd_credential_remove(client: Client, args: argparse.Namespace) -> int:
    result = client.call("credential.remove", {"username": args.username})
    return _emit(
        args,
        result,
        lambda: f"removed the SMB account for {args.username} "
        "(the system account is untouched)",
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
    def human() -> str:
        lines = [f"added share {share['name']!r} ({share['id']}) at {share['path']}"]
        if share.get("note"):
            lines.append(f"  {share['note']}")
        lines.extend(_read_only_notes([share]))
        return "\n".join(lines)

    return _emit(args, share, human)


def _cmd_share_remove(client: Client, args: argparse.Namespace) -> int:
    share = client.call("share.remove", {"ref": args.ref})
    return _emit(args, share, lambda: f"removed share {share['name']!r} ({share['id']})")


def _cmd_connection_list(client: Client, args: argparse.Namespace) -> int:
    connections = client.call("connection.list")
    return _emit(
        args,
        connections,
        lambda: render_table(
            connections, ("id", "host", "share", "mountpoint", "owner", "auto_connect")
        )
        or "no connections configured",
    )


def _cmd_connection_add(client: Client, args: argparse.Namespace) -> int:
    connection = client.call(
        "connection.add",
        {
            "host": args.host,
            "share": args.share,
            # Left out entirely when the user did not give one, so the daemon
            # derives it. Resolving None here would invent a path from the
            # CLI's working directory.
            "mountpoint": _resolve(args.mountpoint) if args.mountpoint else None,
            "id": args.id,
            "auto_connect": args.auto,
            # The daemon can read the peer uid, but a CLI run under sudo arrives
            # as root — and mounting a NAS as root-owned is almost never meant.
            # $SUDO_USER is the only place the real user survives.
            "owner": args.owner or os.environ.get("SUDO_USER") or getpass.getuser(),
            "fallback_host": args.fallback,
        },
    )
    lines = [
        f"added connection {connection['id']}: "
        f"//{connection['host']}/{connection['share']} -> {connection['mountpoint']}"
    ]

    if args.user:
        password = _read_password(args, f"Password for {args.user}@{args.host}: ")
        if password is None:
            return EXIT_ERROR
        client.call(
            "connection.set_credentials",
            {
                "ref": connection["id"],
                "username": args.user,
                "password": password,
                "domain": args.domain,
            },
        )
        lines.append(f"  credentials stored for {args.user}")
    else:
        lines.append("  no credentials: it will mount as a guest")
    lines.append("  it will mount on first access")
    return _emit(args, connection, lambda: "\n".join(lines))


def _cmd_connection_use_fallback(client: Client, args: argparse.Namespace) -> int:
    connection = client.call("connection.use_fallback", {"ref": args.ref})
    return _emit(
        args,
        connection,
        lambda: f"{connection['id']} now connects to {connection['host']} "
        f"({connection['fallback_host']} kept as the fallback)",
    )


def _cmd_watch(client: Client, args: argparse.Namespace) -> int:
    states = client.call("connection.watch")
    if args.json:
        print(render_json(states))
    else:
        print(render_table(states, ("id", "state", "message")) or "nothing to watch")
    if args.once:
        return EXIT_OK

    # Everything after this arrives unasked: the daemon pushes, we do not poll.
    print("\nwatching — ^C to stop")
    try:
        for event in client.events():
            if event.get("event") != "state.changed":
                continue
            data = event["data"]
            marker = "!" if data.get("is_problem") else " "
            print(f"{marker} {data['id']}: {data['state']} — {data['message']}")
            if data.get("hint"):
                print(f"    {data['hint']}")
    except KeyboardInterrupt:
        return 130
    except DaemonUnreachable as exc:
        _fail(exc)
        return EXIT_NO_DAEMON
    return EXIT_OK


def _cmd_connection_connect(client: Client, args: argparse.Namespace) -> int:
    result = client.call("connection.connect", {"ref": args.ref})
    return _emit(args, result, lambda: f"mounted {result['id']} ({result['unit']})")


def _cmd_connection_disconnect(client: Client, args: argparse.Namespace) -> int:
    result = client.call("connection.disconnect", {"ref": args.ref})
    return _emit(
        args,
        result,
        lambda: f"unmounted {result['id']}; it will remount on next access",
    )


def _read_password(args: argparse.Namespace, prompt: str) -> str | None:
    if getattr(args, "stdin_password", False):
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass(prompt)
    if not password:
        print("smbpal: the password must not be empty", file=sys.stderr)
        return None
    return password


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
    ("share", "make-writable"): _cmd_share_make_writable,
    ("apply", None): _cmd_apply,
    ("credential", "list"): _cmd_credential_list,
    ("credential", "set"): _cmd_credential_set,
    ("credential", "remove"): _cmd_credential_remove,
    ("connection", "list"): _cmd_connection_list,
    ("connection", "add"): _cmd_connection_add,
    ("connection", "remove"): _cmd_connection_remove,
    ("connection", "connect"): _cmd_connection_connect,
    ("connection", "disconnect"): _cmd_connection_disconnect,
    ("connection", "use-fallback"): _cmd_connection_use_fallback,
    ("connection", "live"): _cmd_connection_live,
    ("teardown", None): _cmd_teardown,
    ("watch", None): _cmd_watch,
}


def _read_only_notes(shares: list[dict[str, Any]]) -> list[str]:
    """§3c: say *why* something is read-only, because only one reason has a fix."""
    notes = []
    for share in shares:
        reason = share.get("read_only_reason")
        if not reason:
            continue
        notes.append(f"  {reason}")
        # Offer the fix from the structured flag, not by matching words in our
        # own message — a reworded reason should not silently drop the hint.
        if (share.get("directory") or {}).get("writable") is False:
            notes.append(f"  run: smbpal share make-writable {share['id']}")
    return notes


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
