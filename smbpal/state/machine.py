"""What state a connection is in, derived from what systemd and the kernel say.

The states, and the one that is easy to get wrong:

    idle          armed and not mounted — **this is healthy**
    connecting    a mount is in progress
    connected     mounted
    reconnecting  failed for a reason that may pass; systemd will try again
    unreachable   the server is off, or the network is
    unresolved    the name did not resolve (see the fallback note in §3e)
    auth_failed   the credentials were refused; retrying will not help
    failed        something else, and we say what
    disabled      auto_connect is "never"
    unknown       we cannot tell

**`idle` is not `disconnected`.** M0 §4 found the mount happening on first
access, 80 seconds after boot — an automount that has never been triggered is
working exactly as designed. Painting that red would make a healthy machine look
broken, and would train people to ignore the one colour that matters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from smbpal.state.translate import Cause, describe_exit

IDLE = "idle"
CONNECTING = "connecting"
CONNECTED = "connected"
RECONNECTING = "reconnecting"
UNREACHABLE = "unreachable"
UNRESOLVED = "unresolved"
AUTH_FAILED = "auth_failed"
FAILED = "failed"
DISABLED = "disabled"
UNKNOWN = "unknown"

# The states a person should be shown as a problem. Everything else is either
# working or on its way there.
PROBLEM_STATES = frozenset({UNREACHABLE, UNRESOLVED, AUTH_FAILED, FAILED})

# `systemctl show` reports this once a unit has failed to start too often for
# systemd to keep trying. See systemd.reset_failed.
START_LIMIT_HIT = "start-limit-hit"


def _latched(message: str, identifier: str) -> str:
    return (
        f"{message}. systemd has stopped retrying after repeated failures, so "
        f"nothing will happen on access until it is cleared — run "
        f"`smbpal connection connect {identifier}`"
    )


@dataclass(frozen=True)
class ConnectionState:
    id: str
    state: str
    message: str
    errno: int | None = None
    retryable: bool = False
    # True only when the mount itself is read-only. Never True to mean "the
    # server might refuse a write" — see MountProbe.is_read_only.
    read_only: bool = False

    @property
    def is_problem(self) -> bool:
        return self.state in PROBLEM_STATES

    def to_wire(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state,
            "message": self.message,
            "errno": self.errno,
            "retryable": self.retryable,
            "read_only": self.read_only,
            "is_problem": self.is_problem,
        }


def derive(
    connection: dict[str, Any],
    *,
    mounted: bool | None,
    unit: dict[str, str] | None,
    cause: Cause | None = None,
    armed: bool | None = None,
    read_only: bool | None = None,
) -> ConnectionState:
    """Work out the state from the mount table, the unit, and the journal.

    `mounted` comes from the kernel's mount table, never from stat()ing the
    mountpoint (M0 §4). `unit` is `systemctl show` output. `cause` is only read
    when the unit says it failed, so the journal is not consulted on every poll.
    """
    identifier = connection["id"]

    if connection.get("auto_connect") == "never":
        return ConnectionState(identifier, DISABLED, "not connected automatically")

    if mounted:
        if read_only:
            return ConnectionState(
                identifier,
                CONNECTED,
                "mounted read-only — writes will be refused",
                read_only=True,
            )
        # Not "mounted, writable". Whether a write succeeds is the server's
        # decision and we have not asked it; saying so would be a claim we
        # cannot back up.
        return ConnectionState(identifier, CONNECTED, "mounted")

    if unit is None:
        return ConnectionState(identifier, UNKNOWN, "no information about the unit")

    active = unit.get("ActiveState", "")
    result = unit.get("Result", "")

    if active == "activating":
        return ConnectionState(identifier, CONNECTING, "mounting", retryable=True)

    if active == "failed" or (result and result != "success"):
        # `start-limit-hit` is not a reason the mount failed — it is systemd
        # refusing to try any more. The journal still holds the real cause, so
        # report that, and say plainly that nothing will retry on its own.
        latched = result == START_LIMIT_HIT
        if cause is not None:
            state = cause.state
            if state == CONNECTING:
                state = CONNECTING
            elif cause.retryable and state == FAILED:
                state = RECONNECTING
            if latched:
                # Whatever the cause, it will not be retried, so the connection
                # is not "reconnecting" — nothing is.
                state = AUTH_FAILED if state == AUTH_FAILED else FAILED
            return ConnectionState(
                identifier,
                state,
                _latched(cause.message, identifier) if latched else cause.message,
                errno=cause.errno,
                retryable=False if latched else cause.retryable,
            )
        message = describe_exit(unit.get("ExecMainStatus"))
        return ConnectionState(
            identifier,
            FAILED,
            _latched(message, identifier) if latched else message,
            retryable=not latched,
        )

    if armed is False:
        # Not mounted, not failed, and no autofs trigger on the mountpoint —
        # so nothing will happen when someone looks at it. Saying "ready" here
        # would be the same mistake as counting an armed automount as mounted:
        # claiming a state we cannot back up.
        return ConnectionState(
            identifier,
            FAILED,
            "the automount is not running, so nothing will mount on access — "
            "try `smbpal apply`",
        )

    # Not mounted, not failed, trigger in place: the automount is armed and
    # waiting for someone to look at the directory. Healthy.
    return ConnectionState(identifier, IDLE, "ready; it will mount on first access")
