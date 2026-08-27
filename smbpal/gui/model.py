"""What the window shows, decided without importing GTK.

**Every decision in M6 lives here and nothing here can draw.** The reason is a
property worth keeping: the suite has 328 tests and no non-stdlib dependency,
and `gi` is a Debian package (D11), so a GUI that put its rules in the widgets
would put them somewhere no test on a development machine can reach. The view
is left with layout and event plumbing.

Three findings from the Pi runs are answered in this module rather than in a
callback:

- **3h.** An armed automount is invisible to the file manager until something
  touches it. So a connection that is configured and correctly not mounted has
  to be a *row in this window*, present and calm — `idle` is healthy, and
  painting it as a fault would train people to ignore the colour that matters.
- **3c.** A read-only share says *why*, and carries the explicit action that
  changes it. Never a silent `chown`.
- **The eject button.** A file manager cannot unmount a systemd mount — it
  fails with `must be superuser`. So disconnect is a first-class action on the
  row here, because this is the only place it can work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Tones, not colours. The view decides what "attention" looks like in a theme
# we do not control.
OK = "ok"
BUSY = "busy"
IDLE = "idle"
ATTENTION = "attention"
PROBLEM = "problem"
MUTED = "muted"

CONNECT = "connect"
DISCONNECT = "disconnect"
REMOVE = "remove"
USE_FALLBACK = "use_fallback"
MAKE_WRITABLE = "make_writable"
SET_CREDENTIALS = "set_credentials"

SHARE = "share"
CONNECTION = "connection"
UNACCOUNTED = "unaccounted"

# What the button says. Prose belongs here with the rest of the decisions; a
# view that chose its own wording would be a second place to look when the
# wording is wrong.
ACTION_LABELS = {
    CONNECT: "Connect",
    DISCONNECT: "Disconnect",
    REMOVE: "Remove\u2026",
    USE_FALLBACK: "Use the fallback address",
    MAKE_WRITABLE: "Make writable\u2026",
    SET_CREDENTIALS: "Set password\u2026",
}

# Everything that changes the machine and cannot be undone by pressing it again.
NEEDS_CONFIRMING = frozenset({REMOVE, MAKE_WRITABLE})

_METHODS = {
    (CONNECTION, CONNECT): "connection.connect",
    (CONNECTION, DISCONNECT): "connection.disconnect",
    (CONNECTION, REMOVE): "connection.remove",
    (CONNECTION, USE_FALLBACK): "connection.use_fallback",
    (CONNECTION, SET_CREDENTIALS): "connection.set_credentials",
    (SHARE, REMOVE): "share.remove",
    (SHARE, MAKE_WRITABLE): "share.make_writable",
}

# What each connection state looks like, and what it says when the daemon has
# not said anything better. **Two vocabularies meet here.** A connection the
# state monitor has looked at carries one of `smbpal.state.machine`'s words; a
# connection it has not looked at yet — one added a moment ago — carries the
# planner's, straight from the mount table. Both reach this window, so both are
# in this table, and a test pins that.
#
# `idle` is deliberately neither OK nor a problem. It is the state a healthy
# connection spends most of its life in, and M0 §4 is why: the mount happens on
# first access, 80 s after boot in that measurement.
_READY = "ready — it will connect when you open it"

_CONNECTION_PRESENTATION: dict[str, tuple[str, str]] = {
    # From the state monitor.
    "connected": (OK, "mounted"),
    "connecting": (BUSY, "mounting"),
    "reconnecting": (BUSY, "it failed, and systemd is trying again"),
    "idle": (IDLE, _READY),
    "disabled": (MUTED, "not connected automatically"),
    "unknown": (MUTED, "SMBPal cannot tell whether this is connected"),
    "failed": (PROBLEM, "it did not connect"),
    "auth_failed": (PROBLEM, "the server refused the username or password"),
    "unreachable": (PROBLEM, "the server did not answer"),
    "unresolved": (PROBLEM, "that name did not resolve to an address"),
    # From the planner, before the monitor has had a look.
    "mounted": (OK, "mounted"),
    "not mounted": (IDLE, _READY),
    "checking": (BUSY, "checking"),
    "mountpoint in use": (
        PROBLEM,
        "something else is mounted here, and SMBPal will not mount on top of it",
    ),
    "no credentials": (PROBLEM, "no password is stored for this connection"),
    # From the daemon itself.
    "not applied": (MUTED, "in the config; this daemon is not mounting anything"),
}

_CONNECTED = frozenset({"connected", "mounted"})

# Where offering Connect is honest. Not `mountpoint in use` — pressing it would
# fail for a reason the button cannot fix — and not `no credentials`, which
# wants the password first.
_NOT_CONNECTED = frozenset(
    {
        "idle",
        "not mounted",
        "failed",
        "auth_failed",
        "unreachable",
        "unresolved",
        "unknown",
    }
)

# States where the password is the thing to change. `auth_failed` because
# retrying will reproduce the refusal; `no credentials` because there is
# nothing to retry with.
_WANTS_CREDENTIALS = frozenset({"auth_failed", "no credentials"})

# What each share state looks like, and what it says. **A table rather than a
# chain of `elif`s with an `else`**, because the else was the bug: a state the
# presenter had not been told about came out red, with the raw state token as
# its own explanation. Neither half of that was true — `unknown` means we could
# not ask Samba, which is not the share being broken, and "not served" is not a
# sentence.
_SHARE_PRESENTATION: dict[str, tuple[str, str]] = {
    "serving": (OK, "shared"),
    "read-only": (ATTENTION, ""),  # §3c fills this in; it has a reason to give
    "not served": (
        PROBLEM,
        "in the config, but Samba is not serving it — run `smbpal apply`",
    ),
    "disabled": (MUTED, "switched off; still in the config, but not shared"),
    "unknown": (
        MUTED,
        "SMBPal could not ask Samba what it is serving, so this may or may not "
        "be shared",
    ),
    "unmanaged": (MUTED, "not created by SMBPal, and not modified by it"),
    "not applied": (
        MUTED,
        "this daemon is holding the config only and is not serving anything",
    ),
}

# What a state nobody planned for looks like. Public so a test can assert that
# nothing the daemon emits lands on it.
UNRECOGNISED = (
    MUTED,
    "SMBPal does not recognise this state, so it cannot say what it means",
)


@dataclass(frozen=True)
class Row:
    """One line in the window. Everything the view needs, nothing it decides."""

    id: str
    title: str
    subtitle: str
    state: str
    message: str
    tone: str = MUTED
    actions: tuple[str, ...] = ()
    hint: str | None = None
    # Which list this row came from. `Remove` means two different daemon
    # methods depending on the answer, and the view must not be the thing that
    # knows which.
    section: str = CONNECTION

    @property
    def needs_attention(self) -> bool:
        return self.tone in (PROBLEM, ATTENTION)


@dataclass(frozen=True)
class Screen:
    """The whole window's content, in the order it is shown."""

    shares: list[Row] = field(default_factory=list)
    connections: list[Row] = field(default_factory=list)
    unaccounted: list[Row] = field(default_factory=list)
    daemon: str = ""

    @property
    def problems(self) -> list[Row]:
        """Everything a person has to act on, across every section.

        The tray (3g) shows one icon for two axes — is anything shared, is
        anything mounted — and this is the list it reduces.
        """
        return [
            row
            for section in (self.shares, self.connections, self.unaccounted)
            for row in section
            if row.needs_attention
        ]


@dataclass(frozen=True)
class Indicator:
    """What the tray shows: one icon, one line, and the detail behind it.

    **3g's open question, answered.** SMBPal has two axes — is anything shared,
    is anything mounted — and 3h added a third state that is neither: a
    connection configured and correctly not mounted. One icon cannot encode
    three things, and the version that tries needs four icons and still cannot
    say *which* half is wrong.

    So the icon answers one question only: **does anything need you?** The
    tooltip answers *what*, with the two axes spelled out separately. The
    plan's worry — that a healthy share with a broken mount looks the same as a
    broken share — stops being a worry once that is the icon's job: the answer
    to "does anything need you" is yes in both cases, and the tooltip is where
    they differ.

    It is never hidden. SNI's `Passive` would hide the icon when nothing is
    configured, which is exactly when somebody needs a way in.
    """

    status: str
    title: str
    detail: str

    @property
    def needs_attention(self) -> bool:
        return self.status == PROBLEM


_SERVING = frozenset({"serving", "read-only"})


def indicator(screen: Screen) -> Indicator:
    """Reduce a whole screen to what a tray icon can carry."""
    problems = screen.problems
    shared = [r for r in screen.shares if r.state in _SERVING]
    mounted = [r for r in screen.connections if r.state in _CONNECTED]

    if problems:
        status = PROBLEM
        title = (
            problems[0].message
            if len(problems) == 1
            else f"{len(problems)} things need attention"
        )
    elif shared or mounted:
        status = OK
        title = " \u00b7 ".join(
            part
            for part in (
                _count(len(shared), "folder", "shared"),
                _count(len(mounted), "share", "connected"),
            )
            if part
        )
    elif screen.shares or screen.connections:
        # Configured and nothing live. Calm, and it says so rather than looking
        # like a failure — 3h's rule, one layer up.
        status = IDLE
        title = "ready; nothing connected yet"
    else:
        status = MUTED
        title = "nothing set up yet"

    return Indicator(status=status, title=title, detail=_detail(screen, problems))


def offline_indicator(message: str) -> Indicator:
    """What the tray shows when the daemon is not answering.

    A problem, and stated as one. The shares and mounts on this machine may
    well still be up — systemd is holding them, not us — but nothing is
    watching them, so the one thing the tray exists to do is not happening. An
    icon that stayed calm about that would be calm about being blind.
    """
    return Indicator(
        status=PROBLEM,
        title="SMBPal's service is not running",
        detail=(
            f"{message}\nShares and mounts already up are unaffected, but "
            f"nothing is watching them and no changes can be made."
        ),
    )


def _count(number: int, noun: str, verb: str) -> str:
    if not number:
        return ""
    return f"{number} {noun if number == 1 else noun + 's'} {verb}"


def _detail(screen: Screen, problems: list[Row]) -> str:
    """Both axes, always, and then what is wrong.

    Stated separately even when one of them is empty: "nothing shared" is a
    fact somebody may be surprised by, and a line that disappears cannot
    surprise anybody.
    """
    shared = len([r for r in screen.shares if r.state in _SERVING])
    mounted = len([r for r in screen.connections if r.state in _CONNECTED])
    lines = [
        _count(shared, "folder", "shared") or "Nothing shared from this computer",
        _count(mounted, "share", "connected") or "No shares connected",
    ]
    lines.extend(f"{row.title}: {row.message}" for row in problems)
    return "\n".join(lines)


def connection_row(connection: dict[str, Any]) -> Row:
    """One connection, as the window shows it."""
    state = connection.get("state") or "unknown"
    tone, default = _CONNECTION_PRESENTATION.get(state, UNRECOGNISED)
    host = connection.get("host", "?")
    share = connection.get("share", "?")
    return Row(
        id=connection.get("id", ""),
        title=f"//{host}/{share}",
        subtitle=connection.get("mountpoint", ""),
        state=state,
        # The daemon's own message wins when it has one: it has read the unit
        # and, where that failed, the journal. This table is what a row falls
        # back to, never a second opinion competing with the first.
        message=connection.get("message") or default,
        tone=tone,
        actions=_connection_actions(connection, state),
        hint=connection.get("hint"),
        section=CONNECTION,
    )


def method_for(row: Row, action: str) -> str:
    """The daemon method one of a row's buttons calls."""
    try:
        return _METHODS[(row.section, action)]
    except KeyError:
        raise ValueError(f"{action!r} is not an action on a {row.section}") from None


def confirmation(row: Row, action: str) -> str | None:
    """What to ask before doing it, or None when there is nothing to ask.

    Named as the consequence rather than as the verb. "Are you sure?" tells
    somebody nothing they did not already know when they pressed the button.
    """
    if action == REMOVE and row.section == SHARE:
        return (
            f"Stop sharing {row.title}?\n\nThe folder and everything in it "
            f"stays exactly where it is. Anyone connected to it now will lose "
            f"the connection."
        )
    if action == REMOVE and row.section == CONNECTION:
        return (
            f"Remove {row.title}?\n\nIt will be unmounted and will no longer "
            f"appear at {row.subtitle}. Nothing on the server is changed."
        )
    if action == MAKE_WRITABLE:
        return (
            f"Allow writing to {row.title}?\n\nThis changes who owns "
            f"{row.subtitle} on this computer. It cannot be undone by SMBPal."
        )
    return None


def _default_message(state: str) -> str:
    """What a row says when the event or reply carried no message of its own."""
    return _CONNECTION_PRESENTATION.get(state, UNRECOGNISED)[1]


def _connection_actions(connection: dict[str, Any], state: str) -> tuple[str, ...]:
    actions: list[str] = []
    if state in _WANTS_CREDENTIALS:
        # First, because it is the only one of these that changes the outcome.
        # A Connect button here would reproduce the failure and look like the
        # app not listening.
        actions.append(SET_CREDENTIALS)
    if state in _CONNECTED:
        # The only place this works. A file manager's eject cannot unmount a
        # systemd mount: it runs `umount` as the user and the kernel refuses.
        actions.append(DISCONNECT)
    elif state in _NOT_CONNECTED:
        actions.append(CONNECT)
    if state == "unresolved" and connection.get("fallback_host"):
        # §3e: offered, never taken automatically — the address may since
        # belong to a different machine.
        actions.append(USE_FALLBACK)
    actions.append(REMOVE)
    return tuple(actions)


def share_row(share: dict[str, Any]) -> Row:
    """One share, with §3c's reason attached rather than implied."""
    state = share.get("state") or "unknown"
    read_only = bool(share.get("read_only")) or state == "read-only"
    tone, message = _SHARE_PRESENTATION.get(state, UNRECOGNISED)

    if state == "unmanaged":
        # §8 parks adopting these. Visible, marked, and no action offered —
        # there is nothing SMBPal may correctly do to it.
        return Row(
            id=share.get("id", "-"),
            title=share.get("name", "?"),
            subtitle=share.get("path", ""),
            state=state,
            message=message,
            tone=tone,
            section=SHARE,
        )

    actions: list[str] = []
    if read_only:
        # Read-only is not a failure — it is §3c working — but it is the one
        # thing about the share a person needs told, so it asks for attention
        # without claiming to be broken.
        tone = ATTENTION
        message = share.get("read_only_reason") or (
            "shared read-only because the folder belongs to someone else"
        )
        if share.get("credential_ref"):
            actions.append(MAKE_WRITABLE)
    actions.append(REMOVE)

    return Row(
        id=share.get("id", "-"),
        title=share.get("name", "?"),
        subtitle=share.get("path", ""),
        state=state,
        message=message,
        tone=tone,
        actions=tuple(actions),
        section=SHARE,
    )


def unaccounted_row(finding: dict[str, Any]) -> Row:
    """A mount or unit the config does not describe."""
    orphaned = finding.get("kind") == "orphaned"
    return Row(
        id=finding.get("connection_id") or finding.get("mountpoint", ""),
        title=finding.get("mountpoint", ""),
        subtitle=finding.get("source") or "nothing mounted",
        state=finding.get("kind", "unknown"),
        message=finding.get("message", ""),
        # An orphan is ours and is still mounting on access with nothing in the
        # config saying so. Somebody else's mount is information, not a task.
        tone=ATTENTION if orphaned else MUTED,
        section=UNACCOUNTED,
    )


def screen(status: dict[str, Any]) -> Screen:
    """Turn one `status` reply into everything the window draws."""
    daemon = status.get("daemon") or {}
    return Screen(
        shares=[share_row(s) for s in status.get("shares", [])],
        connections=[connection_row(c) for c in status.get("connections", [])],
        unaccounted=[unaccounted_row(f) for f in status.get("unaccounted", [])],
        daemon=f"smbpald {daemon.get('version', '?')} · {daemon.get('config', '')}",
    )


def apply_event(rows: list[Row], data: dict[str, Any]) -> list[Row]:
    """Fold a pushed `state.changed` into the rows already on screen.

    **The push channel is the point of M5 and this is where it lands.** A GUI
    that re-fetched `status` on every event would poll by another name, and the
    event carries everything a row needs.
    """
    updated = []
    for row in rows:
        if row.id != data.get("id"):
            updated.append(row)
            continue
        state = data.get("state") or row.state
        updated.append(
            Row(
                id=row.id,
                title=row.title,
                subtitle=data.get("mountpoint") or row.subtitle,
                state=state,
                message=data.get("message") or _default_message(state),
                tone=_CONNECTION_PRESENTATION.get(state, UNRECOGNISED)[0],
                actions=_connection_actions(
                    {"fallback_host": None, **data}, state
                ),
                hint=data.get("hint"),
                section=row.section,
            )
        )
    return updated
