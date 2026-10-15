"""The daemon's view of a per-user agent.

**Superseded in part, 15 October 2026: the agent now dials the daemon** — see
`AgentLinks` at the end of this module for why. `AgentClient` below still
connects into an agent's socket, and is what a development daemon given
`--agent-socket-dir` uses; an installed one uses the link. What follows is the
original reasoning, which still holds for everything but the direction.

**The direction is daemon to agent, and that was not obvious.** The agent is
the privileged-looking half in every way except the one that matters: it runs
unprivileged, in one session, and it is the only thing on a Mac that can mount.
So the root daemon is the client here, and it connects into the session of
whoever asked it — `connection.peer.uid`, which every mutating method already
receives.

**One call carries a password, and only one.** `credential_set` does, because
something has to put it in the Keychain and only the session can. `mount` does
not, which is the point of having done so: once the credential is in the
Keychain, NetAuthAgent supplies it and the daemon never holds it again. The
rest of this paragraph is why `mount` was built that way:
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

import itertools
import logging
import pwd
import sys
import threading
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

    def mount(
        self, url: str, *, user: str | None = None, host: str | None = None
    ) -> str:
        """Mount in that user's session. Still no password on this call.

        The agent fetches it from the Keychain itself, because NetFS will not
        under `NoUI` — so this stays the call that carries no secret, and
        `credential_set` stays the only one that does. `host` is the key the
        credential was stored under, which the agent cannot safely infer.
        """
        params: dict[str, Any] = {"url": url}
        if user:
            params["user"] = user
        if host:
            params["host"] = host
        result = self._call("agent.mount", params, timeout=MOUNT_TIMEOUT)
        return str(result["mountpoint"])

    def unmount(self, mountpoint: str, *, url: str | None = None) -> bool:
        """True if something was unmounted, False if nothing was mounted.

        With `url`, the agent finds the share in the mount table rather than
        trusting `mountpoint`, which is only where it was last seen.
        """
        params: dict[str, Any] = {"mountpoint": mountpoint}
        if url:
            params["url"] = url
        result = self._call("agent.unmount", params, timeout=MOUNT_TIMEOUT)
        return bool(result.get("unmounted", True))

    def remount_url(self, mountpoint: str) -> str | None:
        result = self._call(
            "agent.remount_url", {"mountpoint": mountpoint}, timeout=DEFAULT_TIMEOUT
        )
        url = result.get("url")
        return str(url) if url else None

    # --- the credential ----------------------------------------------------

    def credential_set(self, host: str, account: str, password: str) -> str:
        """Store it in that user's login Keychain. "created" or "replaced".

        **The one call on this link that carries a secret**, and the only one
        that ever will: a mount does not, because the Keychain is where the
        credential comes from once this has run. The daemon holds the password
        for the length of the request that brought it and writes it nowhere —
        on Linux it would have gone into a 0600 file for `mount.cifs`; here it
        goes into a session root cannot read, which is the better place and the
        reason D13 put mounting there.
        """
        result = self._call(
            "agent.credential_set",
            {"host": host, "account": account, "password": password},
            timeout=DEFAULT_TIMEOUT,
        )
        return str(result["outcome"])

    def credential_present(self, host: str, account: str) -> bool:
        result = self._call(
            "agent.credential_present",
            {"host": host, "account": account},
            timeout=DEFAULT_TIMEOUT,
        )
        return bool(result["present"])

    def credential_forget(self, host: str, account: str) -> bool:
        """Remove it. False if there was nothing to remove.

        Whether SMBPal *may* is not asked here: the Keychain item carries no
        mark of ours, so the answer lives in the config's
        `keychain_credential`, and the daemon checks it before calling this.
        """
        result = self._call(
            "agent.credential_forget",
            {"host": host, "account": account},
            timeout=DEFAULT_TIMEOUT,
        )
        return bool(result["removed"])

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


# --- the link the agent dials (macOS since the daemon left root) -------------


class _Pending:
    def __init__(self, connection: Any) -> None:
        self.connection = connection
        self.done = threading.Event()
        self.message: dict[str, Any] | None = None


class AgentLinks:
    """Agents that dialled in, one per user, and the requests waiting on them.

    **Why the direction reversed.** The first form of this module connected
    into the agent's socket, which is `0600` inside a `0700` directory under
    the person's home and admits its owner and root. That worked while the
    daemon was root. Since the helper work it runs as `_smbpald`, which can
    open neither, so every connect, disconnect and stored password failed on
    an installed Mac. Rather than widen the agent's door, the agent now dials
    the daemon's socket, which members of `smbpal` can already reach, and
    holds the connection open; the daemon sends its requests down it.

    **Which session is still the kernel's answer.** An agent is registered
    under the uid `getpeereid(2)` reported for its connection, so one person
    cannot register as another, and a request for uid N goes only to the
    connection uid N opened. A reply is accepted only from the connection its
    request went to, so nobody else can answer for an agent.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_uid: dict[int, Any] = {}
        self._pending: dict[str, _Pending] = {}
        self._counter = itertools.count(1)

    def register(self, connection: Any) -> None:
        uid = connection.peer.uid
        with self._lock:
            replaced = self._by_uid.get(uid)
            self._by_uid[uid] = connection
        log.info(
            "%s's agent connected%s",
            username_for_uid(uid),
            " (replacing an earlier connection)" if replaced is not None else "",
        )

    def drop(self, connection: Any) -> None:
        """The connection closed: forget it, and fail what was waiting on it."""
        with self._lock:
            for uid, registered in list(self._by_uid.items()):
                if registered is connection:
                    del self._by_uid[uid]
                    log.info("%s's agent disconnected", username_for_uid(uid))
            waiting = [p for p in self._pending.values() if p.connection is connection]
        for pending in waiting:
            pending.done.set()

    def connected(self, uid: int) -> bool:
        with self._lock:
            return uid in self._by_uid

    def reply(self, connection: Any, params: dict[str, Any]) -> None:
        rid = params.get("rid")
        with self._lock:
            pending = self._pending.get(rid) if isinstance(rid, str) else None
            if pending is None or pending.connection is not connection:
                raise SmbpalError(
                    "no request with that id is waiting on this connection"
                )
        pending.message = params
        pending.done.set()

    def request(
        self, uid: int, method: str, params: dict[str, Any] | None, *, timeout: float
    ) -> Any:
        from smbpal.ipc.protocol import encode_event

        with self._lock:
            connection = self._by_uid.get(uid)
            if connection is None:
                raise _not_connected(uid)
            rid = str(next(self._counter))
            pending = self._pending[rid] = _Pending(connection)
        try:
            # An event, sent to this one connection and no other. Never
            # `broadcast`: `credential_set` carries a password.
            connection.send(
                encode_event(
                    "agent.request",
                    {"rid": rid, "method": method, "params": params or {}},
                )
            )
            if not pending.done.wait(timeout):
                raise AgentUnreachable(
                    f"{username_for_uid(uid)}'s agent did not answer within "
                    f"{timeout:g}s",
                    detail=f"it was asked to {method}; its log may say why: "
                    "~/Library/Logs/SMBPal/agent.log",
                )
        finally:
            with self._lock:
                self._pending.pop(rid, None)
        if pending.message is None:
            raise AgentUnreachable(
                f"{username_for_uid(uid)}'s agent disconnected before answering",
                detail=f"it was asked to {method}",
            )
        reply = pending.message
        if reply.get("ok"):
            return reply.get("result")
        return Client._unwrap({"ok": False, "error": reply.get("error") or {}})

    def for_uid(self, uid: int) -> "LinkedAgent":
        return LinkedAgent(uid, links=self)


class LinkedAgent(AgentClient):
    """The same methods as `AgentClient`, carried over the agent's own link."""

    def __init__(self, uid: int, *, links: AgentLinks) -> None:
        self.uid = uid
        self.links = links
        self.path = None  # type: ignore[assignment]

    def _call(
        self, method: str, params: dict[str, Any] | None = None, *, timeout: float
    ) -> Any:
        log.info("asking %s's agent to %s", username_for_uid(self.uid), method)
        return self.links.request(self.uid, method, params, timeout=timeout)


def _not_connected(uid: int) -> AgentUnreachable:
    who = username_for_uid(uid)
    return AgentUnreachable(
        f"{who}'s SMBPal agent is not connected, so nothing can mount for them",
        detail=(
            "Mounting on macOS happens in the user's own session. "
            f"{who} starts the agent with `smbpal-agent --install`, and it "
            "connects at every login. If it is running, its log says why it "
            "could not connect: ~/Library/Logs/SMBPal/agent.log"
        ),
    )
