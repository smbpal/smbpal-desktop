"""The client half of the socket. Used by the CLI (M2), the GUI (M6) and tests.

Shipping the client with the daemon is D4's point: one package, no version skew
between the two halves of a protocol.
"""

from __future__ import annotations

import errno
import json
import socket
import threading
from pathlib import Path
from typing import Any, Callable, Iterator

from smbpal import PROTOCOL_VERSION
from smbpal.errors import (
    BadRequest,
    ConfigInvalid,
    ConfigIOError,
    DaemonUnreachable,
    InvalidParams,
    NotPermitted,
    SmbpalError,
    UnknownMethod,
    UnsupportedVersion,
)
from smbpal.ipc.protocol import MAX_FRAME_BYTES
from smbpal.ipc.server import DEFAULT_SOCKET_PATH

_ERROR_CLASSES: dict[str, type[SmbpalError]] = {
    cls.code: cls
    for cls in (
        BadRequest,
        ConfigInvalid,
        ConfigIOError,
        InvalidParams,
        NotPermitted,
        UnknownMethod,
        UnsupportedVersion,
    )
}

DEFAULT_TIMEOUT = 10.0


class Client:
    """A synchronous request/response client with an optional event callback."""

    def __init__(
        self,
        path: Path | str = DEFAULT_SOCKET_PATH,
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._buffer = bytearray()
        self._counter = 0
        self._lock = threading.Lock()

    # --- lifecycle ---------------------------------------------------------

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(str(self.path))
        except OSError as exc:
            sock.close()
            if exc.errno in (errno.ENOENT, errno.ECONNREFUSED):
                # D12: "the CLI cannot work when the daemon is stopped. That is
                # correct ... but it must produce a clear error, not a stack trace."
                raise DaemonUnreachable(
                    f"no SMBPal daemon is listening on {self.path}",
                    detail="Start it with: systemctl start smbpald",
                ) from exc
            if exc.errno == errno.EACCES:
                raise DaemonUnreachable(
                    f"not allowed to connect to {self.path}",
                    detail="The socket is group-guarded; membership of the "
                    "'smbpal' group is required.",
                ) from exc
            raise DaemonUnreachable(
                f"cannot connect to {self.path}", detail=str(exc)
            ) from exc
        self._sock = sock

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def interrupt(self) -> None:
        """Wake a thread parked in `events()`, from another thread.

        `close()` is not enough and not safe: the reader is inside `recv()`,
        and closing the descriptor out from under it frees a number the kernel
        may hand to something else. `shutdown()` is the call that makes the
        recv return — after which the reader sees a closed connection and
        unwinds through its own error path, which is where it knows what to do.
        """
        sock = self._sock
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # already gone; the reader will find that out for itself

    def __enter__(self) -> "Client":
        self.connect()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # --- calls -------------------------------------------------------------

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Send one request and return its result, or raise the daemon's error."""
        with self._lock:
            sock = self._require_socket()
            self._counter += 1
            request_id = str(self._counter)
            frame = (
                json.dumps(
                    {
                        "v": PROTOCOL_VERSION,
                        "id": request_id,
                        "method": method,
                        "params": params or {},
                    },
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            sock.sendall(frame)

            # Skip events that arrive while we are waiting for our reply; they
            # are unsolicited by definition and must not be mistaken for one.
            while True:
                message = self._read_message()
                if "event" in message:
                    self._dispatch_event(message)
                    continue
                if message.get("id") != request_id:
                    continue
                return self._unwrap(message)

    def events(self) -> Iterator[dict[str, Any]]:
        """Yield pushed events. For a client that only listens (M5, the tray)."""
        while True:
            message = self._read_message()
            if "event" in message:
                yield message

    on_event: Callable[[dict[str, Any]], None] | None = None

    def _dispatch_event(self, message: dict[str, Any]) -> None:
        if self.on_event is not None:
            self.on_event(message)

    # --- plumbing ----------------------------------------------------------

    def _require_socket(self) -> socket.socket:
        if self._sock is None:
            raise DaemonUnreachable("client is not connected; call connect() first")
        return self._sock

    def _read_message(self) -> dict[str, Any]:
        sock = self._require_socket()
        while True:
            index = self._buffer.find(b"\n")
            if index >= 0:
                line = bytes(self._buffer[:index])
                del self._buffer[: index + 1]
                if not line.strip():
                    continue
                return json.loads(line.decode("utf-8"))
            if len(self._buffer) > MAX_FRAME_BYTES:
                raise BadRequest("daemon sent an unframed reply past the size limit")
            try:
                chunk = sock.recv(65536)
            except socket.timeout as exc:
                raise DaemonUnreachable(
                    f"no reply from the daemon within {self.timeout:g}s"
                ) from exc
            if not chunk:
                raise DaemonUnreachable("the daemon closed the connection")
            self._buffer.extend(chunk)

    @staticmethod
    def _unwrap(message: dict[str, Any]) -> Any:
        if message.get("ok"):
            return message.get("result")
        error = message.get("error") or {}
        code = error.get("code", "internal")
        cls = _ERROR_CLASSES.get(code, SmbpalError)
        raised = cls(error.get("message", "the daemon reported an error"))
        raised.code = code  # keep an unknown code intact rather than flattening it
        raised.detail = error.get("detail")
        raise raised
