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

# `idle` is deliberately not OK and not a problem. It is the state a healthy
# connection spends most of its life in, and M0 §4 is why: the mount happens on
# first access, 80 s after boot in that measurement.
_CONNECTION_TONES = {
    "connected": OK,
    "connecting": BUSY,
    "reconnecting": BUSY,
    "idle": IDLE,
    "disabled": MUTED,
    "unknown": MUTED,
    "failed": PROBLEM,
    "auth_failed": PROBLEM,
    "unreachable": PROBLEM,
    "unresolved": PROBLEM,
}

_NOT_CONNECTED = frozenset(
    {"idle", "failed", "auth_failed", "unreachable", "unresolved", "unknown"}
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


def connection_row(connection: dict[str, Any]) -> Row:
    """One connection, as the window shows it."""
    state = connection.get("state") or "unknown"
    host = connection.get("host", "?")
    share = connection.get("share", "?")
    return Row(
        id=connection.get("id", ""),
        title=f"//{host}/{share}",
        subtitle=connection.get("mountpoint", ""),
        state=state,
        message=connection.get("message") or _default_message(state),
        tone=_CONNECTION_TONES.get(state, MUTED),
        actions=_connection_actions(connection, state),
        hint=connection.get("hint"),
    )


def _default_message(state: str) -> str:
    # `status` carries a message for every state the monitor derived. A row
    # built from `connection.list` has none, and a blank second line reads as
    # missing information rather than as nothing to say.
    return {
        "idle": "ready — it will connect when you open it",
        "connected": "mounted",
        "disabled": "not connected automatically",
    }.get(state, state)


def _connection_actions(connection: dict[str, Any], state: str) -> tuple[str, ...]:
    actions: list[str] = []
    if state == "connected":
        # The only place this works. A file manager's eject cannot unmount a
        # systemd mount: it runs `umount` as the user and the kernel refuses.
        actions.append(DISCONNECT)
    elif state in _NOT_CONNECTED:
        actions.append(CONNECT)
    if state == "auth_failed":
        # Retrying will not help; the password is the thing to change, so offer
        # that rather than a Connect button that reproduces the failure.
        actions.insert(0, SET_CREDENTIALS)
    if state == "unresolved" and connection.get("fallback_host"):
        # §3e: offered, never taken automatically — the address may since
        # belong to a different machine.
        actions.append(USE_FALLBACK)
    actions.append(REMOVE)
    return tuple(actions)


def share_row(share: dict[str, Any]) -> Row:
    """One share, with §3c's reason attached rather than implied."""
    state = share.get("state") or "unknown"
    read_only = bool(share.get("read_only"))
    actions: list[str] = []
    message = state

    if state == "unmanaged":
        # §8 parks adopting these. Visible, marked, and no action offered —
        # there is nothing SMBPal may correctly do to it.
        message = "not created by SMBPal, and not modified by it"
        return Row(
            id=share.get("id", "-"),
            title=share.get("name", "?"),
            subtitle=share.get("path", ""),
            state=state,
            message=message,
            tone=MUTED,
        )

    if read_only or state == "read-only":
        message = share.get("read_only_reason") or (
            "shared read-only because the folder belongs to someone else"
        )
        if share.get("credential_ref"):
            actions.append(MAKE_WRITABLE)
    elif state == "serving":
        message = "shared"
    elif state == "not served":
        message = "configured, but Samba is not serving it"

    actions.append(REMOVE)
    return Row(
        id=share.get("id", "-"),
        title=share.get("name", "?"),
        subtitle=share.get("path", ""),
        state=state,
        message=message,
        # Read-only is not a failure — it is §3c working — but it is the one
        # thing about the share a person needs told, so it asks for attention
        # without claiming to be broken.
        tone=ATTENTION if (read_only or state == "read-only") else
        {"serving": OK, "disabled": MUTED}.get(state, PROBLEM),
        actions=tuple(actions),
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
                tone=_CONNECTION_TONES.get(state, MUTED),
                actions=_connection_actions(
                    {"fallback_host": None, **data}, state
                ),
                hint=data.get("hint"),
            )
        )
    return updated
