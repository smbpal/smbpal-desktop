"""Asking polkit whether a peer may act, which is D4's *may talk is not may act*.

**Why `pkcheck` and not the D-Bus API.** polkit's authority lives on the system
bus, and talking to it properly means a D-Bus client. The daemon does not have
one and should not grow one: `python3-gi` is a `Recommends` of this package,
not a `Depends`, on purpose — the CLI and the daemon work on a machine with no
GTK on it — so importing `gi` here would either break that or make every
headless install pull the toolkit. `pkcheck` ships with polkit itself, is the
supported way to ask this question from a program that is not a bus client, and
keeps the root process free of a large dependency it needs for nothing else.
The cost is a fork and exec per mutating call, which is a human-paced event.

**The subject is `(pid, start-time, uid)`, and the middle field is the whole
point.** A pid on its own is not an identity: the process can exit between
`connect()` and the check, the number can be reused, and polkit would then be
asked about somebody else entirely. The start time from `/proc/<pid>/stat`
makes the pair unique for as long as the kernel runs, so a reused number no
longer matches. The uid is passed as well, because polkit re-derives it and
refuses the check if the two disagree — the daemon is not trusted about who its
peer is any more than the peer is.

**Anything but a clean yes is a no.** `pkcheck` exiting non-zero, failing to
run, timing out, or not being installed all reach the caller as "not
authorised". There is deliberately no path where a broken or missing polkit
means everything is permitted; the daemon is root, and the failure mode of
guessing wrong in that direction is not recoverable by the person it happens
to.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

from smbpal.ipc.peer import PeerCredentials

log = logging.getLogger(__name__)
# The same logger handlers.py audits mutations to, so an authorisation and the
# change it permitted end up in one place and one order.
audit = logging.getLogger("smbpal.audit")

# The action ids in packaging/polkit/org.smbpal.policy. Duplicated in two files
# by necessity — one is XML read by polkit, one is Python read by us — and
# pinned together by a test that parses the policy file.
MANAGE_SHARES = "org.smbpal.manage-shares"
MANAGE_CONNECTIONS = "org.smbpal.manage-connections"
USE_CONNECTIONS = "org.smbpal.use-connections"

ACTIONS = (MANAGE_SHARES, MANAGE_CONNECTIONS, USE_CONNECTIONS)

# Long enough for someone to find the password dialog that just appeared over
# whatever they were doing, short enough that walking away from it does not
# leave a thread and a `pkcheck` parked for the life of the daemon. The client
# is blocked for this long too, and is meant to be: it asked.
DEFAULT_TIMEOUT = 120.0


def start_time(pid: int) -> int:
    """Field 22 of `/proc/<pid>/stat`, in clock ticks since boot.

    Parsed from the last `)` rather than by splitting the line, because field 2
    is the executable name and the kernel does not escape it: a program called
    `evil ) 0 0 0` would otherwise get to choose its own start time and become
    any process it liked.
    """
    with open(f"/proc/{pid}/stat", "rb") as handle:
        data = handle.read()
    tail = data[data.rindex(b")") + 2 :].split()
    # Fields 1 and 2 are gone with the `)`, so `tail[0]` is field 3.
    return int(tail[22 - 3])


class Polkit:
    """The real authority. One method, so the fake in the tests is one method."""

    def __init__(
        self,
        *,
        pkcheck: str = "pkcheck",
        timeout: float = DEFAULT_TIMEOUT,
        allow_interaction: bool = True,
    ) -> None:
        self.pkcheck = pkcheck
        self.timeout = timeout
        self.allow_interaction = allow_interaction

    def executable(self) -> str | None:
        return shutil.which(self.pkcheck)

    def check(self, peer: PeerCredentials, action: str) -> bool:
        if peer.pid is None:
            # macOS: `getpeereid` has no pid to give, so no subject can be
            # built. The daemon is a Linux service; this is the development
            # fallback saying so rather than inventing an answer.
            log.warning(
                "cannot ask polkit about %s: the peer has no pid on this platform",
                action,
            )
            return False
        try:
            since_boot = start_time(peer.pid)
        except (OSError, ValueError, IndexError) as exc:
            # Gone, or unreadable. Either way there is nobody left to authorise.
            log.warning("no start time for pid %s: %s", peer.pid, exc)
            return False

        command = [
            self.pkcheck,
            "--action-id",
            action,
            "--process",
            f"{peer.pid},{since_boot},{peer.uid}",
        ]
        if self.allow_interaction:
            command.append("--allow-user-interaction")

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError:
            log.error(
                "%s is not installed, so nothing can be authorised: %s denied",
                self.pkcheck,
                action,
            )
            return False
        except subprocess.TimeoutExpired:
            log.warning(
                "no answer to %s for %s within %ss; treating it as a refusal",
                action,
                peer.describe(),
                self.timeout,
            )
            return False
        except OSError as exc:
            log.error("could not run %s: %s", self.pkcheck, exc)
            return False

        if completed.returncode == 0:
            # info, not debug. A refusal explains itself to the person it
            # happened to; a grant is silent, and a gate whose successes leave
            # no trace cannot be told apart from a gate that is not running.
            # That is exactly the question asked on 30 August 2026 when a
            # mutation went through without a prompt and there was nothing in
            # the journal to say whether polkit had been consulted at all.
            audit.info("polkit allowed %s for %s", action, peer.describe())
            return True
        # Every other code is a refusal. They are distinguished in the log and
        # nowhere else: "not authorised", "dismissed the dialog" and "polkit is
        # broken" are the same answer to the question that was asked, and a
        # caller that could tell them apart would be tempted to treat one of
        # them as a yes.
        audit.info(
            "polkit refused %s for %s (%s exited %s%s)",
            action,
            peer.describe(),
            self.pkcheck,
            completed.returncode,
            f": {completed.stderr.strip()}" if completed.stderr.strip() else "",
        )
        return False
