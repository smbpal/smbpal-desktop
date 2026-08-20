"""The transport boundary D4 requires from day one.

    "Keep the transport behind an interface from day one. D4 requires remote
    administration to stay possible without redesign, and the cost of that is
    one indirection now."

The interface is deliberately narrow: bytes-framed messages in, messages out,
and a peer identity the transport obtained from somewhere trustworthy. Anything
Unix-socket-shaped — file modes, SO_PEERCRED, socket paths — belongs in the
implementation, not here, or the indirection buys nothing.
"""

from __future__ import annotations

from typing import Any, Callable, Protocol, runtime_checkable

from smbpal.ipc.peer import PeerCredentials


@runtime_checkable
class Connection(Protocol):
    """One client, for as long as it stays connected."""

    @property
    def peer(self) -> PeerCredentials:
        """Who the kernel says this is. Never taken from the message."""

    def send(self, payload: bytes) -> None:
        """Write one already-framed message. Safe to call from any thread."""

    def close(self) -> None: ...


# A handler answers one request and returns the framed reply, or returns None to
# say nothing. It is called on the connection's own thread.
Handler = Callable[[Connection, bytes], bytes | None]


class Transport(Protocol):
    """Somewhere clients arrive from."""

    def serve_forever(self, handler: Handler) -> None: ...

    def broadcast(self, payload: bytes) -> None:
        """Push one framed message to every live connection (M5's channel)."""

    def shutdown(self) -> None: ...

    @property
    def address(self) -> Any:
        """Whatever identifies this endpoint, for logging."""
