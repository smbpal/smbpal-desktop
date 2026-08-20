"""Turning a mount failure into a reason.

**This module is M0 §4's finding made into code.** A rejected password reaches
the user as:

    ls: cannot open directory '/mnt/m0': No such device

which is the automount's response to a failed mount unit and says nothing at all
about the cause. The cause is in the unit's journal:

    mount[2824]: mount error(13): Permission denied
    mnt-m0.mount: Mount process exited, code=exited, status=32/n/a

`No such device` sends someone hunting for a missing disk. `Permission denied`
tells them to check the password. Reading the journal and reporting the second
is the entire job here, and it is the difference between an error message that
helps and one that misdirects.

`systemctl show` gives that the unit failed and with what exit status; only the
journal gives the errno. So both are read, and the journal only on a transition
into failure — never on every poll.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# `mount error(13): Permission denied`, and the resolution failure that has no
# errno at all.
_MOUNT_ERROR = re.compile(r"mount error\((\d+)\)", re.IGNORECASE)
_UNRESOLVED = re.compile(
    r"could not resolve address|unable to find suitable address|"
    r"name or service not known",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Cause:
    """Why a mount failed, and whether trying again could ever help."""

    state: str
    message: str
    errno: int | None = None
    # M0 §4 watched the kernel make this distinction already: an unreachable
    # host produced seven attempts at five-second intervals, a wrong password
    # produced exactly one. Retrying a rejected credential is how accounts get
    # locked out, and the daemon's job is to reflect that split rather than
    # invent a policy on top of it.
    retryable: bool = False


# errno -> (state, message, retryable). The messages are what a person sees, so
# they say what to do rather than what the kernel called it.
_ERRNO: dict[int, tuple[str, str, bool]] = {
    1: ("auth_failed", "the server refused the credentials", False),
    13: (
        "auth_failed",
        "the username or password was refused by the server",
        False,
    ),
    2: (
        "failed",
        "the server has no share by that name",
        False,
    ),
    5: ("failed", "the server reported an I/O error", True),
    6: ("failed", "the server has no share by that name", False),
    101: ("unreachable", "the network is unreachable", True),
    110: ("unreachable", "the server did not answer in time", True),
    111: ("unreachable", "the server refused the connection", True),
    112: ("unreachable", "the server is switched off or unreachable", True),
    113: ("unreachable", "there is no route to the server", True),
    115: ("connecting", "still connecting", True),
}


def translate_journal(text: str) -> Cause | None:
    """Read the most recent mount failure out of a unit's journal.

    Returns None when the journal carries no failure we recognise — which is
    not the same as "it worked", and the caller must not treat it as such.
    """
    if not text:
        return None

    # Last match wins: a unit that failed, was fixed and failed again should
    # report the most recent reason, not the first one ever recorded.
    errno: int | None = None
    for match in _MOUNT_ERROR.finditer(text):
        errno = int(match.group(1))

    if errno is not None:
        state, message, retryable = _ERRNO.get(
            errno, ("failed", f"the mount failed with error {errno}", True)
        )
        return Cause(state=state, message=message, errno=errno, retryable=retryable)

    if _UNRESOLVED.search(text):
        return Cause(
            state="unresolved",
            message="the server's name could not be resolved",
            retryable=True,
        )
    return None


def describe_exit(status: str | None) -> str:
    """A last resort when the journal says nothing recognisable."""
    if status and status not in ("0", ""):
        # 32 is mount(8)'s generic failure. Saying so beats printing a bare
        # number, but it is still an admission that we do not know why.
        suffix = " (mount(8) reports a generic failure)" if status == "32" else ""
        return f"the mount command exited with status {status}{suffix}"
    return "the mount failed for a reason not recorded in its journal"
