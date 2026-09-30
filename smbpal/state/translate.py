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

**Everything here reads Linux.** The input is a systemd journal and the errno in
it is `mount.cifs`'s, so the table below is Linux's numbering and says so. A
second platform does not reuse it: it has a different source for the failure and
a different numbering, and it will want its own. See the comment on the table.
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


# **These are Linux's numbers, and they must stay literal.** They are not local
# `errno` values: they are the number `mount.cifs` printed into a systemd
# journal on the machine that failed, parsed back out of text. The only caller
# is `translate_journal`, and its only input is `journalctl` output.
#
# **Do not "fix" this by keying on `errno.ECONNREFUSED` and friends.** It reads
# like an improvement and it is a defect. errno numbering is not portable above
# the POSIX-fixed range of 1 to 34: `ECONNREFUSED` is 111 on Linux and 61 on
# macOS, `EHOSTUNREACH` 113 against 65, `ETIMEDOUT` 110 against 60. Substituting
# symbols would leave this table correct only while the interpreter happens to
# run on the same kind of system that wrote the log — and the whole point of the
# journal path is that the text can be read anywhere, including from a Mac over
# SSH. The numbers below describe the *sender*, not the reader.
#
# Measured 30 September 2026 while proving D13's mount path, which is also where
# the macOS side of this is written up: `phase-2-porting-surface.md` §6.9. macOS
# has auth errnos Linux has no name for at all — `EAUTH` 80 and `ENEEDAUTH` 81 —
# so that platform needs its own table, fed by its own source, not this one
# rearranged.
#
# errno -> (state, message, retryable). The messages are what a person sees, so
# they say what to do rather than what the kernel called it.
_LINUX_MOUNT_ERRNO: dict[int, tuple[str, str, bool]] = {
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
    # D14. `ECONNREFUSED` is the symptom of two opposite causes -- Samba
    # stopped, or its port blocked -- and nothing in the refusal says which,
    # which is why fedora.md §6a closed with a finding rather than a fix. The
    # rule's second clause applies: where the daemon cannot distinguish, it
    # says what would. `smbpal status` on the server answers it in one line,
    # and SMBPal is running there too.
    111: (
        "unreachable",
        "the server refused the connection: either SMBPal's sharing is "
        "stopped there, or a firewall is blocking it. `smbpal status` on that "
        "machine says which",
        True,
    ),
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
        state, message, retryable = _LINUX_MOUNT_ERRNO.get(
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
