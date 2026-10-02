"""The daemon's view of a per-user agent.

**The direction is daemon to agent, and that was not obvious.** The agent is
the privileged-looking half in every way except the one that matters: it runs
unprivileged, in one session, and it is the only thing on a Mac that can mount.
So the root daemon is the client here, and it connects into the session of
whoever asked it — `connection.peer.uid`, which every mutating method already
receives.

**It passes a username and never a password.** Not an oversight:
`CredentialsStore.username_for` exists and there is deliberately no
`password_for`, because that file is written for `mount.cifs` to read and the
daemon has no business reading it back. On macOS the credential belongs to the
session anyway (D13) — in the login Keychain, which the agent can read and root
cannot. A share whose credential the Keychain already holds mounts; one whose
credential nobody holds fails with an authentication status the agent
translates. **What is missing is SMBPal writing that Keychain item**, and the
honest version of this seam is the one where it does.

**An agent that is not running is a sentence, not a stack trace.** It is the
most likely failure here by a distance: the plist is per-user and installed by
the person, so a fresh Mac has a daemon and no agent. The message names that
person and the command, because "connection refused" names neither.
"""

from __future__ import annotations

import logging
import pwd
import sys
from pathlib import Path
from typing import Any

from smbpal.errors import SmbpalError
from smbpal.ipc.client import Client, DaemonUnreachable

log = logging.getLogger(__name__)

# The same path `agent/main.py` builds from `Path.home()`, expressed relative to
# a home directory so the daemon can build it for somebody else's.
SOCKET_RELATIVE_PATH = Path("Library/Application Support/SMBPal/agent.sock")

DEFAULT_TIMEOUT = 5.0
# A mount reaches the network, and an unreachable server is the slow case the
# state machine is built around: M0 §4 watched one retry for 35 seconds. This is
# the agent's budget to answer, not the mount's budget to succeed.
MOUNT_TIMEOUT = 60.0


class AgentUnreachable(SmbpalError):
    code = "agent_unreachable"


def username_for_uid(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid {uid}"


def socket_path_for(uid: int) -> Path:
    """Where that user's agent listens.

    From the password database rather than from `/Users/<name>`: a home
    directory is not required to be under `/Users`, and on a Mac bound to a
    directory service it frequently is not.
    """
    try:
        home = pwd.getpwuid(uid).pw_dir
    except KeyError as exc:
        raise AgentUnreachable(
            f"there is no user with uid {uid} on this machine",
            detail="the request came from a uid the password database does not know",
        ) from exc
    return Path(home) / SOCKET_RELATIVE_PATH


class AgentClient:
    """One connection to one user's agent, opened per call and closed after.

    Deliberately not a pooled connection. The agent serves one person, calls
    are rare and human-paced, and a held socket across a `launchctl bootout`
    would make the next mount fail for a reason that has nothing to do with it.
    """

    def __init__(self, uid: int, *, path: Path | None = None) -> None:
        self.uid = uid
        self.path = path or socket_path_for(uid)

    # --- the four methods --------------------------------------------------

    def ping(self) -> dict[str, Any]:
        return self._call("agent.ping", timeout=DEFAULT_TIMEOUT)

    def mount(self, url: str, *, user: str | None = None) -> str:
        result = self._call(
            "agent.mount",
            {"url": url, "user": user} if user else {"url": url},
            timeout=MOUNT_TIMEOUT,
        )
        return str(result["mountpoint"])

    def unmount(self, mountpoint: str) -> bool:
        """True if something was unmounted, False if nothing was mounted."""
        result = self._call(
            "agent.unmount", {"mountpoint": mountpoint}, timeout=MOUNT_TIMEOUT
        )
        return bool(result.get("unmounted", True))

    def remount_url(self, mountpoint: str) -> str | None:
        result = self._call(
            "agent.remount_url", {"mountpoint": mountpoint}, timeout=DEFAULT_TIMEOUT
        )
        url = result.get("url")
        return str(url) if url else None

    # --- the wire ----------------------------------------------------------

    def _call(
        self, method: str, params: dict[str, Any] | None = None, *, timeout: float
    ) -> Any:
        client = Client(self.path, timeout=DEFAULT_TIMEOUT, reply_timeout=timeout)
        try:
            client.connect()
        except DaemonUnreachable as exc:
            raise self._not_running(exc) from exc
        try:
            # No params are logged, here or in the agent: the method and the
            # mountpoint are safe, and keeping the rule at the boundary is
            # cheaper than remembering which fields are which.
            log.info("asking %s's agent to %s", username_for_uid(self.uid), method)
            return client.call(method, params)
        finally:
            client.close()

    def _not_running(self, _exc: DaemonUnreachable) -> AgentUnreachable:
        who = username_for_uid(self.uid)
        if sys.platform != "darwin":
            # Reachable only in development, and it would otherwise produce the
            # most confusing message in the program: a Linux daemon explaining
            # that a macOS agent is not running.
            return AgentUnreachable(
                "mounting through an agent was asked for on a platform that "
                "does not have one",
                detail=(
                    f"this is {sys.platform}, where the daemon mounts through "
                    "systemd. Start it without --mount-via agent."
                ),
            )
        # **Not `exc.message`.** `ipc/client.py` says "no SMBPal daemon is
        # listening on <path>", which is right for its own case and wrong for
        # this one twice over: the thing not listening is the agent, and the
        # daemon *is* listening, elsewhere. Forwarding it told a Mac user their
        # daemon was down while it was the process printing the message.
        return AgentUnreachable(
            f"{who} has no SMBPal agent running, so nothing can mount for them",
            detail=(
                f"nothing is listening on {self.path}. Mounting on macOS "
                f"happens in the user's own session, so {who} starts it with "
                "`smbpal-agent --install`, and it then starts at every login."
            ),
        )


class AgentClients:
    """One of these per daemon, handing out a client for whoever asked.

    A level of indirection worth its keep twice: the dispatcher holds one
    object rather than a dictionary it has to manage, and the suite can
    substitute the whole mechanism without a socket.
    """

    def __init__(self, *, directory: Path | None = None) -> None:
        # Set in tests and in a development run: every agent socket under one
        # directory, named by uid, instead of inside real home directories.
        self.directory = directory

    def for_uid(self, uid: int) -> AgentClient:
        if self.directory is not None:
            return AgentClient(uid, path=self.directory / f"agent-{uid}.sock")
        return AgentClient(uid)
