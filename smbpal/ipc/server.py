"""The Unix socket transport — the only one Phase 1 ships.

`/run/smbpal/smbpald.sock`, mode 0660, group `smbpal` (D4). §11.1 ruled out a
listening TCP socket, loopback included: a port that exists is a port that can
be reached.

The socket's group is a guard on *who may talk*, not on *who may act*. Every
request still carries the peer's kernel-reported identity to the handler, and
authorisation is decided there.
"""

from __future__ import annotations

import errno
import grp
import logging
import os
import socket
import threading
from pathlib import Path
from typing import Iterator

from smbpal.ipc.peer import PeerCredentials, peer_credentials
from smbpal.ipc.protocol import MAX_FRAME_BYTES
from smbpal.ipc.transport import Handler

log = logging.getLogger(__name__)

DEFAULT_SOCKET_PATH = Path("/run/smbpal/smbpald.sock")
DEFAULT_SOCKET_GROUP = "smbpal"
_SOCKET_MODE = 0o660
_RUNTIME_DIR_MODE = 0o750
_READ_CHUNK = 65536


class UnixSocketConnection:
    """One connected client. `send` is safe to call from any thread."""

    def __init__(self, sock: socket.socket, peer: PeerCredentials) -> None:
        self._sock = sock
        self._peer = peer
        self._write_lock = threading.Lock()
        self._closed = False

    @property
    def peer(self) -> PeerCredentials:
        return self._peer

    def send(self, payload: bytes) -> None:
        with self._write_lock:
            if self._closed:
                return
            try:
                self._sock.sendall(payload)
            except OSError as exc:
                # A client that has gone away is normal, not an incident.
                log.debug("send to %s failed: %s", self._peer.describe(), exc)
                self._closed = True

    def close(self) -> None:
        with self._write_lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()

    def read_frames(self) -> Iterator[bytes]:
        """Yield complete lines, refusing to buffer past the frame limit."""
        buffer = bytearray()
        while True:
            try:
                chunk = self._sock.recv(_READ_CHUNK)
            except OSError as exc:
                if exc.errno not in (errno.ECONNRESET, errno.EBADF):
                    log.debug("recv from %s failed: %s", self._peer.describe(), exc)
                return
            if not chunk:
                return
            buffer.extend(chunk)
            if len(buffer) > MAX_FRAME_BYTES:
                # No newline in a megabyte is not a slow client, it is a client
                # that will happily consume all the memory we give it.
                log.warning(
                    "closing %s: unframed data past %d bytes",
                    self._peer.describe(),
                    MAX_FRAME_BYTES,
                )
                return
            while True:
                index = buffer.find(b"\n")
                if index < 0:
                    break
                line = bytes(buffer[:index])
                del buffer[: index + 1]
                if line.strip():
                    yield line


class UnixSocketTransport:
    """Binds the socket, accepts clients, and can push to all of them."""

    def __init__(
        self,
        path: Path | str = DEFAULT_SOCKET_PATH,
        *,
        group: str | None = DEFAULT_SOCKET_GROUP,
        mode: int = _SOCKET_MODE,
    ) -> None:
        self.path = Path(path)
        self.group = group
        self.mode = mode
        self._listener: socket.socket | None = None
        self._connections: set[UnixSocketConnection] = set()
        self._connections_lock = threading.Lock()
        self._threads_lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._stopping = threading.Event()
        # shutdown() is called from both the signal handler and the serve
        # loop's finally, so it has to be safe to call twice — and quiet the
        # second time.
        self._shutdown_lock = threading.Lock()
        self._shutdown_done = False

    @property
    def address(self) -> str:
        return str(self.path)

    # --- lifecycle ---------------------------------------------------------

    def bind(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=_RUNTIME_DIR_MODE)
        self._clear_stale_socket()

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Create the socket with no group or world access, widen it only after
        # the ownership is right. Binding at 0660 first would leave a window in
        # which the wrong group could connect.
        previous_umask = os.umask(0o177)
        try:
            listener.bind(str(self.path))
        finally:
            os.umask(previous_umask)

        self._apply_ownership()
        listener.listen(16)
        self._listener = listener
        log.info("listening on %s", self.path)

    def _clear_stale_socket(self) -> None:
        """Remove a leftover socket, but never one a live daemon is using."""
        if not self.path.exists():
            return
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(1.0)
            probe.connect(str(self.path))
        except OSError:
            log.info("removing stale socket at %s", self.path)
            self.path.unlink(missing_ok=True)
            return
        finally:
            probe.close()
        raise OSError(
            errno.EADDRINUSE,
            f"another smbpald is already listening on {self.path}",
        )

    def _apply_ownership(self) -> None:
        if self.group is not None:
            try:
                gid = grp.getgrnam(self.group).gr_gid
            except KeyError:
                raise OSError(
                    f"group {self.group!r} does not exist. The package creates it; "
                    "for a development run pass --socket-group '' to skip."
                ) from None
            try:
                os.chown(self.path, -1, gid)
            except PermissionError:
                raise OSError(
                    f"cannot set group {self.group!r} on {self.path} — "
                    "the daemon is a root service (see the plan's daemon lifecycle)"
                ) from None
        os.chmod(self.path, self.mode)

    def serve_forever(self, handler: Handler) -> None:
        if self._listener is None:
            raise RuntimeError("bind() before serve_forever()")
        while not self._stopping.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                if self._stopping.is_set():
                    break
                raise
            thread = threading.Thread(
                target=self._serve_client,
                args=(client, handler),
                name="smbpald-client",
                daemon=True,
            )
            # Started before it is recorded, and recorded under the lock.
            # The other order has a window in which `shutdown()` on another
            # thread joins a thread that has not started, which is a
            # RuntimeError out of the shutdown path — and the shutdown path is
            # what removes the socket file.
            thread.start()
            with self._threads_lock:
                self._threads.append(thread)

    def _serve_client(self, sock: socket.socket, handler: Handler) -> None:
        try:
            peer = peer_credentials(sock)
        except OSError as exc:
            # Without an identity there is no authorisation, so there is no
            # service. Refusing is the only safe answer.
            log.error("refusing a client with no readable credentials: %s", exc)
            sock.close()
            return

        connection = UnixSocketConnection(sock, peer)
        with self._connections_lock:
            if self._stopping.is_set():
                # Accepted a moment before shutdown swept the connections, so
                # this one would never be closed and the client would sit
                # believing a stopped daemon is still there.
                connection.close()
                return
            self._connections.add(connection)
        log.debug("client connected: %s", peer.describe())
        try:
            for frame in connection.read_frames():
                reply = handler(connection, frame)
                if reply is not None:
                    connection.send(reply)
        finally:
            with self._connections_lock:
                self._connections.discard(connection)
            connection.close()
            log.debug("client disconnected: %s", peer.describe())

    def broadcast(self, payload: bytes) -> None:
        """M5's push channel. Nothing emits events yet; the path exists."""
        with self._connections_lock:
            targets = list(self._connections)
        for connection in targets:
            connection.send(payload)

    def shutdown(self) -> None:
        with self._shutdown_lock:
            if self._shutdown_done:
                return
            self._shutdown_done = True
        self._stopping.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        with self._connections_lock:
            targets = list(self._connections)
        for connection in targets:
            connection.close()
        with self._threads_lock:
            threads = list(self._threads)
            self._threads.clear()
        for thread in threads:
            thread.join(timeout=2.0)
        # Leaving the socket behind would make the next start think a daemon is
        # running until it probes and finds nothing.
        self.path.unlink(missing_ok=True)
        log.info("stopped; %s removed", self.path)
