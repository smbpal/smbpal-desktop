"""The Unix socket transport — the only one Phase 1 ships.

`/run/smbpal/smbpald.sock` on Linux and `/var/run/smbpal/smbpald.sock` on
macOS, mode 0660, group `smbpal` (D4). §11.1 ruled out a listening TCP socket,
loopback included: a port that exists is a port that can be reached.

The socket's group is a guard on *who may talk*, not on *who may act*. Every
request still carries the peer's kernel-reported identity to the handler, and
authorisation is decided there.
"""

from __future__ import annotations

import errno
import grp
import logging
import os
import selectors
import socket
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Iterator

from smbpal.ipc.peer import PeerCredentials, peer_credentials
from smbpal.ipc.protocol import MAX_FRAME_BYTES
from smbpal.ipc.transport import Handler

log = logging.getLogger(__name__)

def default_socket_path() -> Path:
    """Where the daemon listens when nobody says otherwise.

    **`/run` does not exist on macOS and cannot be created** — `/` is the
    Signed System Volume, so `mkdir /run` fails for root as surely as for
    anyone. A constant `/run/smbpal/smbpald.sock` therefore named a path the
    daemon could not create and the CLI could not find, and every macOS
    invocation needed `--socket`. Measured 10 October 2026 by a Homebrew
    install run the way a user would; porting surface §6.20. Nine sessions of
    macOS work missed it because every runbook passes `--socket` explicitly for
    an unrelated reason.

    `agent/main.py` has had `default_socket_path()` since D13, under
    `~/Library/Application Support`. This is the system half of the same idea,
    which nothing had needed yet because nothing starts the daemon on macOS.

    **Linux keeps its exact string.** `/var/run` is a symlink to `/run` there,
    so one path would resolve on both and looks free — but that string is also
    in the systemd units, the polkit rules and the group-guard documentation,
    and changing what they agree on to a symlink pointing at the same place
    buys nothing and invites a mismatch.
    """
    if sys.platform == "darwin":
        return Path("/var/run/smbpal/smbpald.sock")
    return Path("/run/smbpal/smbpald.sock")


DEFAULT_SOCKET_PATH = default_socket_path()
DEFAULT_SOCKET_GROUP = "smbpal"
_SOCKET_MODE = 0o660
_RUNTIME_DIR_MODE = 0o750

# **macOS only in practice, and it closes a measured race.** `/var/run` does not
# survive a reboot -- `/var/run/smbpal` had a birth time six seconds later than
# `kern.boottime`, measured 11 October 2026 -- and on macOS the daemon is not
# root, so `mkdir` under `/var/run` (root:daemon) is EPERM. The privileged
# helper makes the directory, launchd gives no ordering between the two jobs,
# and a daemon that loses the race would otherwise exit on the failed bind.
#
# Waiting here rather than letting launchd restart the job, because launchd
# cannot tell *why* a job exited: the daemon returns 2 on an invalid config and
# means it, so `KeepAlive` turned a deliberate refusal into a flapping service.
# This waits for the one condition that is genuinely transient and nothing else.
#
# Thirty seconds because the helper creates the directory as its first act at
# `RunAtLoad` -- it won the real race by about two seconds -- so this is two
# orders of magnitude of slack and still bounded. On Linux the daemon is root,
# creates the directory itself, and never reaches the wait at all.
_RUNTIME_DIR_WAIT_SECONDS = 30.0
_RUNTIME_DIR_POLL_SECONDS = 0.25

# Directories the daemon will never take ownership of, however it is invoked.
# Checked both as given and resolved, so /var/run catches as the /run symlink
# it is on Linux. World-writable directories are refused by mode rather than by
# name: /tmp resolves to /private/tmp on macOS and would walk straight past a
# list, and a directory anyone can rename out from under the socket is the
# wrong place for a guarded socket whatever it is called.
#
# The `/private` forms are the macOS resolved spellings, and they are listed
# because the resolve step only helps when what it produces is in the set.
# `/var/run` on macOS resolves to `/private/var/run`, which is `drwxrwxr-x` —
# so it is caught by neither the name check nor the world-writable one unless
# it is named. Found while giving macOS a default under /var/run (§6.20).
_SHARED_DIRS = frozenset(
    Path(p)
    for p in (
        "/",
        "/run",
        "/var/run",
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/private/var/run",
        "/private/tmp",
        "/private/var/tmp",
    )
)
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


def _describe_mode(info: os.stat_result) -> str:
    """For the one error where the numbers are the whole of the diagnosis."""
    return f"group {info.st_gid} with mode {stat.S_IMODE(info.st_mode):04o}"


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
        # **Closing the listener does not stop `accept()` on Linux.** It does
        # on macOS, which is why this was written without a wake-up and why
        # nothing noticed for two weeks: every `test_cli` test paid the full
        # `join(timeout=5)` on Linux and finished instantly on the machine the
        # code was written on. The daemon itself survived only by accident —
        # SIGTERM interrupts the syscall, so the signal handler's `shutdown()`
        # runs and the retried `accept()` then fails on a closed fd. Anything
        # calling `shutdown()` from another thread simply hung.
        #
        # So: a socketpair the serve loop watches alongside the listener.
        # `shutdown()` writes one byte to it, which is a wake-up that does not
        # depend on what a platform does with a closed descriptor.
        self._wake_r: socket.socket | None = None
        self._wake_w: socket.socket | None = None
        # shutdown() is called from both the signal handler and the serve
        # loop's finally, so it has to be safe to call twice — and quiet the
        # second time.
        self._shutdown_lock = threading.Lock()
        self._shutdown_done = False

    @property
    def address(self) -> str:
        return str(self.path)

    def _ensure_runtime_directory(self) -> None:
        """Make the socket's directory, or wait for whoever can to make it.

        **Only `PermissionError` waits.** Every other failure is reported at
        once, because "I am not allowed to create this" is the single reason
        that someone else might be about to, and treating any other error as
        transient would turn a real misconfiguration into a thirty-second pause
        followed by the same message.
        """
        directory = self.path.parent
        deadline = time.monotonic() + _RUNTIME_DIR_WAIT_SECONDS
        announced = False
        while True:
            try:
                directory.mkdir(parents=True, exist_ok=True, mode=_RUNTIME_DIR_MODE)
                return
            except PermissionError:
                # Checked after the attempt rather than before: the helper may
                # have created it in between, and then there is nothing to wait
                # for. `mkdir(exist_ok=True)` does not re-chmod an existing
                # directory, so the helper's ownership of it stands.
                if directory.is_dir():
                    return
                if time.monotonic() >= deadline:
                    raise
                if not announced:
                    # Once, not every quarter second. A log that says this
                    # thirty times is a log that hides the one line that matters.
                    log.info(
                        "%s does not exist yet and this process may not create "
                        "it; waiting up to %.0fs for the privileged helper",
                        directory,
                        _RUNTIME_DIR_WAIT_SECONDS,
                    )
                    announced = True
                time.sleep(_RUNTIME_DIR_POLL_SECONDS)

    # --- lifecycle ---------------------------------------------------------

    def bind(self) -> None:
        self._ensure_runtime_directory()
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

        # A socket file exists the moment bind() returns, so anything that
        # refuses afterwards has to take it back down: the Pi's restart loop
        # on 29 August 2026 left one behind on every one of its 374 attempts,
        # each cleared as stale by the next.
        try:
            self._apply_ownership()
        except BaseException:
            listener.close()
            self.path.unlink(missing_ok=True)
            raise

        listener.listen(16)
        self._listener = listener
        self._wake_r, self._wake_w = socket.socketpair()
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
            self._apply_directory_ownership(gid)
            try:
                os.chown(self.path, -1, gid)
            except PermissionError:
                raise OSError(
                    f"cannot set group {self.group!r} on {self.path} — "
                    "the daemon is a root service (see the plan's daemon lifecycle)"
                ) from None
        os.chmod(self.path, self.mode)

    def _apply_directory_ownership(self, gid: int) -> None:
        """Give the group the directory as well as the socket.

        `connect()` needs *execute* on every directory in the path, so a 0660
        root:smbpal socket inside a 0750 root:root directory is reachable by
        root and by nobody else — the group guard reads as correct and admits
        no one. Found on a Pi on 29 August 2026, where the CLI answered a
        member-to-be with *membership of the smbpal group is required*, which
        would have stayed the answer after they joined it.

        systemd cannot do this: `RuntimeDirectory=` takes its ownership from
        the unit's `User=` and `Group=`, and giving the unit `Group=smbpal`
        would change the daemon's primary gid and put that group on every file
        it writes into /etc/samba. So the daemon owns the problem, which also
        covers the directory it makes for itself when systemd is not involved.

        **Already-correct is not a failure, and on macOS it is the normal
        case.** Changing a directory's group needs root, or ownership of it; the
        daemon has neither on macOS, where it runs as a service account and the
        compiled helper creates the directory for it (the spike's §9). So the
        state is checked before it is changed, and a directory that already has
        the group and mode this wants is left alone.

        **The docstring this replaces said "the daemon is a root service", and
        that was the whole of the bug.** §9 recorded that *nothing in
        `ipc/server.py` asserts the uid is 0* -- true of the assertions and
        false of the behaviour, because an unconditional `chown` requires root
        whether or not anything says so, and the error message asserted it in
        prose instead. Found 11 October 2026 by reading this before the daemon
        was first run as a non-root user, which is the only reason it was not
        found by the daemon refusing to start.
        """
        directory = self.path.parent
        shared = {directory, directory.resolve()} & _SHARED_DIRS
        info = directory.stat()
        if shared or info.st_mode & stat.S_IWOTH:
            raise OSError(
                f"refusing to give group {self.group!r} ownership of {directory} — "
                "a group-guarded socket needs a directory of its own, not a "
                "shared or world-writable one. Pass --socket-group '' for a "
                "socket in a shared directory."
            )
        if info.st_gid == gid and stat.S_IMODE(info.st_mode) == _RUNTIME_DIR_MODE:
            return
        try:
            os.chown(directory, -1, gid)
            os.chmod(directory, _RUNTIME_DIR_MODE)
        except PermissionError:
            raise OSError(
                f"cannot set group {self.group!r} on {directory} — it is "
                f"{_describe_mode(info)} and this needs group {gid} with mode "
                f"{_RUNTIME_DIR_MODE:04o}. Whatever creates the directory has "
                "to set them: the package does on Linux, and `smbpal setup` "
                "does on macOS."
            ) from None

    def serve_forever(self, handler: Handler) -> None:
        listener = self._listener
        if listener is None:
            if self._stopping.is_set():
                return
            raise RuntimeError("bind() before serve_forever()")
        selector = selectors.DefaultSelector()
        try:
            selector.register(listener, selectors.EVENT_READ)
            if self._wake_r is not None:
                selector.register(self._wake_r, selectors.EVENT_READ)
        except (ValueError, OSError):
            # `shutdown()` landed between starting this thread and registering
            # the listener, and closed it: a closed socket's fd is -1 and the
            # selector refuses it. Stopping before serving is still stopping.
            # Seen in CI on the v0.2.2 tag, where the thread's traceback landed
            # in the next test's captured stderr and failed that test instead.
            selector.close()
            if self._stopping.is_set():
                return
            raise
        try:
            self._accept_loop(selector, handler)
        finally:
            selector.close()
            if self._wake_r is not None:
                self._wake_r.close()
                self._wake_r = None

    def _accept_loop(self, selector: selectors.BaseSelector, handler: Handler) -> None:
        while not self._stopping.is_set():
            try:
                ready = selector.select()
            except OSError:
                # A registered descriptor went away underneath us. That is
                # shutdown if shutdown says so, and a real fault otherwise.
                if self._stopping.is_set():
                    break
                raise
            if any(key.fileobj is self._wake_r for key, _ in ready):
                break
            listener = self._listener
            if listener is None:
                break
            try:
                client, _ = listener.accept()
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
        # The wake-up first, and the listener after: the serve loop must have
        # something to notice before the thing it is watching disappears.
        if self._wake_w is not None:
            try:
                self._wake_w.send(b"\0")
            except OSError:
                pass
            self._wake_w.close()
            self._wake_w = None
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
