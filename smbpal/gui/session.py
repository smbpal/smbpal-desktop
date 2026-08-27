"""The daemon connection, kept off the thread that draws.

**This module is where "the GUI stays responsive with the remote host switched
off" is won or lost**, so it is written without importing GTK and tested
against a real socket. The view supplies one function — `to_main_thread` — and
gets back a component that never blocks it.

Two sockets, not one. The reason is not tidiness:

- a *command* connection, used by one worker thread, one call at a time;
- a *listener* connection, parked in `Client.events()` for the lifetime of the
  window.

One connection cannot do both. `Client.call()` reads until it sees its reply,
so a thread parked in `events()` would eat the reply, and two threads reading
one socket race for frames. The alternative — a single socket read only when a
call is made — would mean events arriving only when the user does something,
which is polling wearing M5's clothes. The daemon broadcasts to every connected
client, so a second connection costs one file descriptor and no protocol.

**A failed job is reported, never retried.** The user pressed a button; if it
did not work they need told, not to have it happen later when they have moved
on. The listener is the opposite: nobody asked for it, so it reconnects on its
own — that is how the window survives `systemctl restart smbpald`.
"""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from typing import Any, Callable

from smbpal.errors import DaemonUnreachable, SmbpalError
from smbpal.gui import model
from smbpal.ipc.client import Client

log = logging.getLogger(__name__)

# Long enough not to hammer a socket that is not coming back, short enough that
# a `systemctl restart smbpald` heals the window before anyone reaches for it.
RETRY_SECONDS = 2.0

_STOP = object()


def _direct(callback: Callable[[], None]) -> None:
    """Run it here. The default, so a test needs no main loop."""
    callback()


@dataclass
class _Job:
    method: str
    params: dict[str, Any]
    # Runs on the worker thread, with the raw result. For turning a `status`
    # reply into a Screen without occupying the main loop to do it.
    transform: Callable[[Any], Any] | None
    # Runs on the main thread, with whatever `transform` returned.
    then: Callable[[Any], None] | None
    # Runs on the main thread instead of `on_error` when this call fails.
    # A dialog needs its own: an error belonging to the form somebody is
    # filling in has to appear in that form, not in a banner behind it.
    catch: Callable[[SmbpalError], None] | None = None


class Session:
    """Every socket call the window makes, and every event it receives."""

    def __init__(
        self,
        client_factory: Callable[[], Client],
        *,
        to_main_thread: Callable[[Callable[[], None]], None] = _direct,
        retry_seconds: float = RETRY_SECONDS,
    ) -> None:
        self._factory = client_factory
        self._to_main = to_main_thread
        self._retry_seconds = retry_seconds

        self._jobs: queue.Queue[Any] = queue.Queue()
        self._stopping = threading.Event()
        self._threads: list[threading.Thread] = []
        self._command: Client | None = None
        # Every live socket, so stop() can wake all of them. A set rather than
        # two attributes because the bug it fixes is a race: a listener that
        # connected *between* stop()'s sweep and its join sat out the client's
        # full socket timeout, which turned closing the window into a five
        # second pause and the test suite into a flake.
        self._clients: set[Client] = set()
        self._clients_lock = threading.Lock()
        # "Back" is only meaningful after a loss. Without this the window would
        # announce a recovery every time it opened.
        self._lost = False

        # Assigned by the view. Every one of them is called on the main thread.
        self.on_screen: Callable[[model.Screen], None] | None = None
        self.on_event: Callable[[dict[str, Any]], None] | None = None
        self.on_error: Callable[[SmbpalError], None] | None = None
        self.on_daemon_lost: Callable[[SmbpalError], None] | None = None
        self.on_daemon_back: Callable[[], None] | None = None

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._spawn("smbpal-gui-worker", self._work)
        self._spawn("smbpal-gui-listener", self._listen)

    def _spawn(self, name: str, target: Callable[[], None]) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        self._threads.append(thread)
        thread.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        # Under the lock, and before the sweep: a thread that reaches `_track`
        # after this point is refused a socket rather than parked on one.
        with self._clients_lock:
            self._stopping.set()
            live = list(self._clients)
        self._jobs.put(_STOP)
        # Both threads may be inside recv() — the listener always is, by
        # design. Setting a flag they cannot see until the socket says
        # something would make closing the window take a timeout.
        for client in live:
            client.interrupt()
        for thread in self._threads:
            thread.join(timeout=timeout)
        self._threads.clear()

    # --- calls -------------------------------------------------------------

    def submit(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        then: Callable[[Any], None] | None = None,
        transform: Callable[[Any], Any] | None = None,
        catch: Callable[[SmbpalError], None] | None = None,
    ) -> None:
        """Queue one call. Returns immediately; the reply arrives on the main thread."""
        self._jobs.put(_Job(method, params or {}, transform, then, catch))

    def refresh(self) -> None:
        """Fetch `status` and hand the view a finished Screen."""
        self.submit("status", transform=model.screen, then=self._deliver_screen)

    def act(self, method: str, ref: str) -> None:
        """A row's button: do it, then re-read, because it changed the machine."""
        self.submit(method, {"ref": ref}, then=lambda _result: self.refresh())

    def _deliver_screen(self, screen: model.Screen) -> None:
        if self.on_screen is not None:
            self.on_screen(screen)

    # --- the worker --------------------------------------------------------

    def _work(self) -> None:
        while not self._stopping.is_set():
            job = self._jobs.get()
            if job is _STOP or self._stopping.is_set():
                break
            self._run(job)
        self._drop()

    def _run(self, job: _Job) -> None:
        try:
            result = self._call(job)
        except DaemonUnreachable as exc:
            # Still the global handler: the daemon being gone is not the form's
            # problem to explain, and every open dialog has the same one.
            self._report(exc, lost=True)
            return
        except SmbpalError as exc:
            if job.catch is not None:
                self._marshal(job.catch, exc)
            else:
                self._report(exc)
            return

        if job.transform is not None:
            try:
                result = job.transform(result)
            except Exception:  # pragma: no cover - a presenter bug, not a fault
                log.exception("could not present the reply to %s", job.method)
                return
        if job.then is not None:
            self._marshal(job.then, result)

    def _call(self, job: _Job) -> Any:
        """One call, with one retry when the connection we were holding is dead.

        **The retry is for the socket, not for the request.** A window sits idle
        for hours; `systemctl restart smbpald` in the meantime leaves it holding
        a file descriptor that only fails when it is next used. Making the user
        press the button twice for that would be blaming them for our
        bookkeeping. A failure on a *fresh* connection is a real failure and is
        reported — so a daemon that is genuinely down still says so, once.
        """
        for attempt in (1, 2):
            reusing = self._command is not None
            try:
                return self._command_client().call(job.method, job.params)
            except (DaemonUnreachable, OSError) as exc:
                self._drop()
                if reusing and attempt == 1:
                    continue
                if isinstance(exc, DaemonUnreachable):
                    raise
                raise DaemonUnreachable(str(exc)) from exc
        raise DaemonUnreachable("could not reach the daemon")  # pragma: no cover

    def _command_client(self) -> Client:
        if self._command is None:
            client = self._connect()
            self._command = client
        return self._command

    def _drop(self) -> None:
        client, self._command = self._command, None
        if client is not None:
            self._release(client)

    # --- socket bookkeeping ------------------------------------------------

    def _connect(self) -> Client:
        """A live client, tracked — or nothing at all, if we are stopping."""
        client = self._factory()
        client.connect()
        with self._clients_lock:
            if self._stopping.is_set():
                # stop() has already swept; this socket would never be woken.
                client.close()
                raise DaemonUnreachable("the session is closing")
            self._clients.add(client)
        return client

    def _release(self, client: Client) -> None:
        with self._clients_lock:
            self._clients.discard(client)
        try:
            client.close()
        except OSError:  # pragma: no cover - already gone
            pass

    # --- the listener ------------------------------------------------------

    def _listen(self) -> None:
        while not self._stopping.is_set():
            client: Client | None = None
            try:
                client = self._connect()
                self._marshal_back()
                for message in client.events():
                    if self._stopping.is_set():
                        break
                    if message.get("event") != "state.changed":
                        continue
                    self._marshal_event(message.get("data") or {})
            except SmbpalError as exc:
                if self._stopping.is_set():
                    break
                self._lost_once(exc)
            except OSError as exc:  # pragma: no cover - defensive
                if self._stopping.is_set():
                    break
                self._lost_once(DaemonUnreachable(str(exc)))
            finally:
                if client is not None:
                    self._release(client)
            # Event.wait, not sleep: stop() must not have to outlast a backoff.
            if self._stopping.wait(self._retry_seconds):
                break

    def _lost_once(self, exc: SmbpalError) -> None:
        """Say it once, not every retry.

        The listener reconnects on a timer, so reporting each failure would put
        the same banner on screen every couple of seconds for as long as the
        daemon is down. The worker is the opposite: it reports every failure,
        because every one of those is a button somebody pressed.
        """
        already = self._lost
        self._lost = True
        if not already:
            self._report(exc, lost=True)

    def _marshal_event(self, data: dict[str, Any]) -> None:
        if self.on_event is not None:
            self._marshal(self.on_event, data)

    def _marshal_back(self) -> None:
        if not self._lost:
            return
        self._lost = False
        if self.on_daemon_back is not None:
            self._marshal(lambda _ignored: self.on_daemon_back(), None)

    # --- plumbing ----------------------------------------------------------

    def _report(self, exc: SmbpalError, *, lost: bool = False) -> None:
        if lost:
            self._lost = True
        handler = self.on_daemon_lost if lost and self.on_daemon_lost else self.on_error
        if handler is not None:
            self._marshal(handler, exc)

    def _marshal(self, callback: Callable[[Any], None], value: Any) -> None:
        self._to_main(lambda: callback(value))
