"""Method dispatch, and the one place authorisation happens.

M1's method set is deliberately tiny — the milestone is "a daemon that starts,
loads, holds the socket, and does nothing else". What is not tiny is the shape:
every request is untrusted, every reply is framed, and every method passes the
authoriser before it runs. Adding a mutating method in M3 should require no new
security thinking, only a new entry in the table.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from smbpal import PROTOCOL_VERSION, __version__
from smbpal.config import ConfigStore
from smbpal.errors import NotPermitted, SmbpalError, UnknownMethod
from smbpal.ipc.peer import PeerCredentials
from smbpal.ipc.protocol import Request, encode_failure, encode_success, parse_request
from smbpal.ipc.transport import Connection

log = logging.getLogger(__name__)

Method = Callable[["Dispatcher", Request, PeerCredentials], Any]


class Authoriser:
    """Decides *may act*, which the socket's group guard does not answer (D4).

    Phase 1 has no mutating methods yet, so this currently only separates read
    from write. **The polkit check goes here** when M3 adds the first method
    that changes something — one place, not scattered through the handlers.
    """

    # Methods that only read. Everything not listed is treated as mutating.
    READ_ONLY = frozenset({"ping", "version", "config.get"})

    def check(self, peer: PeerCredentials, method: str) -> None:
        if method in self.READ_ONLY:
            return
        if peer.uid == 0:
            return
        raise NotPermitted(
            f"{method} requires authorisation",
            detail=f"peer {peer.describe()} is not permitted to perform this action",
        )


class Dispatcher:
    """Turns framed bytes into framed bytes. Owns nothing it does not need to."""

    def __init__(
        self,
        store: ConfigStore,
        *,
        authoriser: Authoriser | None = None,
    ) -> None:
        self.store = store
        self.authoriser = authoriser or Authoriser()

    def handle(self, connection: Connection, frame: bytes) -> bytes | None:
        request: Request | None = None
        try:
            request = parse_request(frame)
            # Existence before permission. Answering "requires authorisation" for
            # a method that does not exist sends someone hunting for a
            # permission problem they do not have — the same failure mode M0 §4
            # found in `No such device` for a rejected password. The socket is
            # group-guarded, so the method names are not a secret from anyone
            # who can ask.
            method = _METHODS.get(request.method)
            if method is None:
                raise UnknownMethod(f"no such method: {request.method}")
            self.authoriser.check(connection.peer, request.method)
            result = method(self, request, connection.peer)
            return encode_success(request.id, result)
        except SmbpalError as exc:
            log.info(
                "%s -> %s: %s",
                request.method if request else "<unparsed>",
                exc.code,
                exc.message,
            )
            return encode_failure(request.id if request else None, exc)
        except Exception:  # noqa: BLE001 - a handler bug must not kill the daemon
            log.exception("unhandled error in %s", request.method if request else "<unparsed>")
            return encode_failure(
                request.id if request else None,
                SmbpalError("the daemon hit an internal error; see its journal"),
            )

    # --- methods -----------------------------------------------------------

    def _ping(self, _request: Request, _peer: PeerCredentials) -> dict[str, Any]:
        return {"pong": True}

    def _version(self, _request: Request, _peer: PeerCredentials) -> dict[str, Any]:
        return {"version": __version__, "protocol": PROTOCOL_VERSION}

    def _config_get(self, _request: Request, _peer: PeerCredentials) -> dict[str, Any]:
        # Read through rather than from a cache: the daemon is the only writer
        # (D12), so the file and memory cannot disagree, and reading proves it.
        return self.store.load()


_METHODS: dict[str, Method] = {
    "ping": Dispatcher._ping,
    "version": Dispatcher._version,
    "config.get": Dispatcher._config_get,
}
