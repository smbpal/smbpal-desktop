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


@dataclass(frozen=True)
class ConnectionState:
    id: str
    state: str
    message: str
    errno: int | None = None
    retryable: bool = False

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
            "is_problem": self.is_problem,
        }


def derive(
    connection: dict[str, Any],
    *,
    mounted: bool | None,
    unit: dict[str, str] | None,
    cause: Cause | None = None,
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
        return ConnectionState(identifier, CONNECTED, "mounted")

    if unit is None:
        return ConnectionState(identifier, UNKNOWN, "no information about the unit")

    active = unit.get("ActiveState", "")
    result = unit.get("Result", "")

    if active == "activating":
        return ConnectionState(identifier, CONNECTING, "mounting", retryable=True)

    if active == "failed" or (result and result != "success"):
        if cause is not None:
            state = cause.state
            if state == CONNECTING:
                state = CONNECTING
            elif cause.retryable and state == FAILED:
                state = RECONNECTING
            return ConnectionState(
                identifier,
                state,
                cause.message,
                errno=cause.errno,
                retryable=cause.retryable,
            )
        return ConnectionState(
            identifier,
            FAILED,
            describe_exit(unit.get("ExecMainStatus")),
            retryable=True,
        )

    # Not mounted, not failed: the automount is armed and waiting for someone to
    # look at the directory. Healthy.
    return ConnectionState(identifier, IDLE, "ready; it will mount on first access")
