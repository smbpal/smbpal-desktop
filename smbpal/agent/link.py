"""The agent's connection to the daemon, held open for the daemon to use.

**Why the agent dials.** The daemon runs as `_smbpald` since the helper work,
and this agent's socket is `0600` inside a `0700` directory in the person's
home, so the daemon could not open it and every connect, disconnect and stored
password failed on an installed Mac. Rather than make the agent's door wider,
the agent connects to the daemon's socket, which members of `smbpal` can
already reach, registers, and waits. The daemon sends requests down that
connection as `agent.request` events and this answers each with `agent.reply`
(`agent/client.py`, `AgentLinks`).

**It checks who it dialled before it registers.** A request can carry a
password, so the listener must be the daemon: the kernel's answer for the
socket's peer must be root, the daemon's account, or this same user (a
development daemon). `/var/run/smbpal` is `_smbpald`'s and `0750`, so nobody
else could have put a socket there, and this check is the second lock rather
than the only one.

**It keeps dialling.** A daemon restarted by `brew upgrade` or launchd is
reconnected to with backoff, from five seconds to a minute, and each change of
state is logged once.
"""

from __future__ import annotations

import logging
import os
import pwd
import threading
from pathlib import Path
from typing import Any, Callable

from smbpal.errors import SmbpalError
from smbpal.ipc.client import Client

log = logging.getLogger(__name__)

# The account the helper creates for the daemon (helper spike §9).
DAEMON_ACCOUNT = "_smbpald"
FIRST_RETRY = 5.0
LONGEST_RETRY = 60.0


def trusted_uids() -> set[int]:
    uids = {0, os.getuid()}
    try:
        uids.add(pwd.getpwnam(DAEMON_ACCOUNT).pw_uid)
    except KeyError:
        pass
    return uids


class DaemonLink:
    def __init__(
        self,
        dispatcher: Any,
        socket_path: Path,
        *,
        client_factory: Callable[[Path], Client] | None = None,
        trusted: Callable[[], set[int]] = trusted_uids,
    ) -> None:
        self.dispatcher = dispatcher
        self.socket_path = socket_path
        self._client_factory = client_factory or (
            # No reply timeout: the link waits for requests for as long as the
            # session lasts, and `stop` wakes it.
            lambda path: Client(path, timeout=5.0, reply_timeout=None)
        )
        self._trusted = trusted
        self._client: Client | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._said: str | None = None
        self.registered = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="smbpal-link", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        client = self._client
        if client is not None:
            client.interrupt()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None

    def _loop(self) -> None:
        delay = FIRST_RETRY
        while not self._stop.is_set():
            try:
                self._session()
                delay = FIRST_RETRY
            except SmbpalError as exc:
                self._say(f"not connected to the daemon: {exc.message}", warn=True)
            except OSError as exc:
                self._say(f"not connected to the daemon: {exc}", warn=True)
            finally:
                self.registered.clear()
                client, self._client = self._client, None
                if client is not None:
                    client.close()
            if self._stop.wait(delay):
                return
            delay = min(delay * 2, LONGEST_RETRY)

    def _session(self) -> None:
        client = self._client_factory(self.socket_path)
        client.connect()
        self._client = client
        peer = client.peer()
        if peer.uid not in self._trusted():
            raise SmbpalError(
                f"{self.socket_path} is answered by uid {peer.uid}, which is not "
                "the SMBPal daemon, so nothing will be sent to it"
            )
        # Requests may arrive before the register reply does: the daemon files
        # the connection first and answers second. Kept, and answered after.
        early: list[dict[str, Any]] = []
        client.on_event = early.append
        client.call("agent.register")
        client.on_event = None
        self.registered.set()
        self._say(f"connected to the daemon at {self.socket_path}")
        for event in early:
            self._answer(client, event)
        for event in client.events():
            if self._stop.is_set():
                return
            self._answer(client, event)

    def _answer(self, client: Client, event: dict[str, Any]) -> None:
        if event.get("event") != "agent.request":
            return  # state broadcasts and the like: not addressed to us
        data = event.get("data") or {}
        rid = data.get("rid")
        method = data.get("method")
        params = data.get("params") or {}
        if not isinstance(rid, str) or not isinstance(method, str) or not isinstance(params, dict):
            log.warning("ignoring a malformed request from the daemon")
            return
        try:
            reply: dict[str, Any] = {
                "rid": rid,
                "ok": True,
                "result": self.dispatcher.perform(method, params),
            }
        except SmbpalError as exc:
            # The method and the code, never the params: one can be a password.
            log.info("%s -> %s: %s", method, exc.code, exc.message)
            reply = {"rid": rid, "ok": False, "error": exc.to_wire()}
        except Exception as exc:  # noqa: BLE001 - the daemon must hear something
            log.exception("agent failed to handle %s", method)
            reply = {
                "rid": rid,
                "ok": False,
                "error": SmbpalError("the agent could not do that", detail=str(exc)).to_wire(),
            }
        client.send("agent.reply", reply)

    def _say(self, line: str, *, warn: bool = False) -> None:
        if self._said == line:
            return
        self._said = line
        log.log(logging.WARNING if warn else logging.INFO, "%s", line)
