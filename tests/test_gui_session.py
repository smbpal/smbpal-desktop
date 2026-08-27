"""The GUI's half of the socket: threads, failures, and the main loop.

Half of these run against a real daemon on a real Unix socket, because the
things worth proving here — an event arriving unasked, a reply surviving a
daemon restart — are properties of the socket and not of a stub. The other half
use a stub client, because the property being proved is *timing*, and timing
against a real server is a race dressed as a test.
"""

from __future__ import annotations

import queue
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, Callable

from smbpal.config import ConfigStore
from smbpal.daemon.handlers import Dispatcher
from smbpal.errors import DaemonUnreachable, SmbpalError, UnknownMethod
from smbpal.gui import model
from smbpal.gui.session import Session
from smbpal.ipc.client import Client
from smbpal.ipc.protocol import encode_event
from smbpal.ipc.server import UnixSocketTransport


class MainLoop:
    """Stands in for GLib's. Callbacks queue here and run on the test thread."""

    def __init__(self) -> None:
        self.calls: queue.Queue[Callable[[], None]] = queue.Queue()

    def __call__(self, callback: Callable[[], None]) -> None:
        self.calls.put(callback)

    def pump(self, count: int = 1, timeout: float = 5.0) -> None:
        for _ in range(count):
            self.calls.get(timeout=timeout)()

    def idle(self) -> bool:
        return self.calls.empty()


class DaemonTestCase(unittest.TestCase):
    """A real dispatcher on a real socket, on a path short enough for sun_path."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-")
        self.addCleanup(self._dir.cleanup)
        root = Path(self._dir.name)
        self.socket_path = root / "s.sock"
        self.store = ConfigStore(root / "config.json")
        self.transport = UnixSocketTransport(self.socket_path, group=None)
        self.transport.bind()
        self._serve()
        self.main = MainLoop()

    def _serve(self) -> None:
        self.thread = threading.Thread(
            target=self.transport.serve_forever,
            args=(Dispatcher(self.store).handle,),
            daemon=True,
        )
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self) -> None:
        self.transport.shutdown()
        self.thread.join(timeout=5)

    def session(self) -> Session:
        session = Session(
            lambda: Client(self.socket_path, timeout=5.0),
            to_main_thread=self.main,
            retry_seconds=0.05,
        )
        self.addCleanup(session.stop)
        session.start()
        return session


class TestAgainstARealDaemon(DaemonTestCase):
    def test_refresh_delivers_a_finished_screen(self) -> None:
        self.store.save(
            {
                "version": 1,
                "shares": [],
                "connections": [
                    {
                        "type": "os",
                        "id": "media",
                        "host": "rivendell.local",
                        "share": "Media",
                        "mountpoint": "/media/pi/Media",
                        "auto_connect": "always",
                    }
                ],
            }
        )
        seen: list[model.Screen] = []
        session = self.session()
        session.on_screen = seen.append
        session.refresh()
        self.main.pump()

        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].connections[0].title, "//rivendell.local/Media")

    def test_an_error_is_reported_and_the_session_keeps_working(self) -> None:
        errors: list[SmbpalError] = []
        replies: list[Any] = []
        session = self.session()
        session.on_error = errors.append
        session.submit("no.such.method", then=replies.append)
        session.submit("ping", then=replies.append)
        self.main.pump(2)

        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, UnknownMethod.code)
        # The failed job produced no reply, and did not take the next one with it.
        self.assertEqual(replies, [{"pong": True}])

    def test_a_pushed_event_arrives_without_being_asked_for(self) -> None:
        events: list[dict[str, Any]] = []
        session = self.session()
        session.on_event = events.append
        # Prove the listener has connected before broadcasting: a broadcast to
        # nobody would make this pass or fail on timing.
        session.submit("ping", then=lambda _r: None)
        self.main.pump()
        _wait_for(lambda: len(self.transport._connections) >= 2)

        self.transport.broadcast(
            encode_event("state.changed", {"id": "media", "state": "connected"})
        )
        self.main.pump()

        self.assertEqual(events[0]["state"], "connected")

    def test_events_that_are_not_state_changes_are_ignored(self) -> None:
        events: list[dict[str, Any]] = []
        session = self.session()
        session.on_event = events.append
        session.submit("ping", then=lambda _r: None)
        self.main.pump()
        _wait_for(lambda: len(self.transport._connections) >= 2)

        self.transport.broadcast(encode_event("something.else", {"id": "media"}))
        self.transport.broadcast(
            encode_event("state.changed", {"id": "media", "state": "idle"})
        )
        self.main.pump()

        self.assertEqual([e["state"] for e in events], ["idle"])

    def test_the_window_survives_the_daemon_restarting(self) -> None:
        """`systemctl restart smbpald` must not need the window restarted too."""
        lost: list[SmbpalError] = []
        back: list[bool] = []
        session = self.session()
        session.on_daemon_lost = lost.append
        session.on_daemon_back = lambda: back.append(True)
        session.submit("ping", then=lambda _r: None)
        self.main.pump()

        self._stop_serving()
        self.main.pump()  # the loss
        self.assertEqual(len(lost), 1)

        self.transport = UnixSocketTransport(self.socket_path, group=None)
        self.transport.bind()
        self._serve()
        self.main.pump()  # the recovery
        self.assertEqual(back, [True])

        # And the command half works again, on a socket it had to rebuild.
        replies: list[Any] = []
        session.submit("ping", then=replies.append)
        self.main.pump()
        self.assertEqual(replies, [{"pong": True}])

    def _stop_serving(self) -> None:
        self.transport.shutdown()
        self.thread.join(timeout=5)

    def test_a_loss_is_announced_once_however_long_it_lasts(self) -> None:
        lost: list[SmbpalError] = []
        session = self.session()
        session.on_daemon_lost = lost.append
        self._stop_serving()
        self.main.pump()  # the one announcement

        # Several retry intervals with the daemon still down. A banner per
        # attempt would be a banner every 50 ms here, and every 2 s in the app.
        _sleep_through_retries()
        self.assertTrue(self.main.idle())
        self.assertEqual(len(lost), 1)


class SlowClient:
    """A client whose call blocks until the test lets it finish."""

    def __init__(self, gate: threading.Event) -> None:
        self.gate = gate
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def connect(self) -> None:
        pass

    def close(self) -> None:
        pass

    def interrupt(self) -> None:
        self.gate.set()

    def call(self, method: str, params: dict[str, Any]) -> Any:
        self.calls.append((method, params))
        self.gate.wait(timeout=5)
        return {"method": method}

    def events(self) -> Any:
        # Parks. A listener that returned would spin the retry loop.
        self.gate.wait(timeout=5)
        return iter(())


class TestTheMainThreadIsNeverBlocked(unittest.TestCase):
    """The reason this module exists, stated as a test.

    §9's definition of done says the GUI stays responsive with the remote host
    switched off. What makes that true is that nothing the window calls waits
    on a socket, and `submit` is the only entry point it has.
    """

    def setUp(self) -> None:
        self.gate = threading.Event()
        self.main = MainLoop()
        self.client = SlowClient(self.gate)
        self.session = Session(
            lambda: self.client, to_main_thread=self.main, retry_seconds=0.05
        )
        self.addCleanup(self.session.stop)
        # Registered last so it runs first: the listener is parked on this gate,
        # and stop() would otherwise sit out its join timeout waiting for it.
        self.addCleanup(self.gate.set)
        self.session.start()

    def test_submit_returns_while_the_call_is_still_in_flight(self) -> None:
        replies: list[Any] = []
        self.session.submit("status", then=replies.append)
        _wait_for(lambda: bool(self.client.calls))

        # The daemon has not answered and will not until the gate opens.
        self.assertEqual(replies, [])
        self.assertTrue(self.main.idle())

        self.gate.set()
        self.main.pump()
        self.assertEqual(replies, [{"method": "status"}])

    def test_a_queued_job_waits_its_turn_rather_than_racing(self) -> None:
        order: list[str] = []
        self.session.submit("first", then=lambda _r: order.append("first"))
        self.session.submit("second", then=lambda _r: order.append("second"))
        _wait_for(lambda: bool(self.client.calls))
        self.gate.set()
        self.main.pump(2)

        self.assertEqual(order, ["first", "second"])

    def test_every_callback_arrives_through_the_main_thread_hook(self) -> None:
        threads: list[int] = []
        self.session.submit(
            "ping", then=lambda _r: threads.append(threading.get_ident())
        )
        self.gate.set()
        self.main.pump()

        # Pumped by this thread, so it ran here — not on the worker.
        self.assertEqual(threads, [threading.get_ident()])


class TestActions(unittest.TestCase):
    def test_a_row_action_re_reads_the_machine_afterwards(self) -> None:
        """A button changed something, so what is on screen is now a guess."""
        main = MainLoop()
        calls: list[str] = []

        class Recording:
            def connect(self) -> None:
                pass

            def close(self) -> None:
                pass

            def interrupt(self) -> None:
                pass

            def call(self, method: str, params: dict[str, Any]) -> Any:
                calls.append(method)
                return {} if method == "status" else {"id": params.get("ref")}

            def events(self) -> Any:
                raise DaemonUnreachable("no events in this test")

        session = Session(
            lambda: Recording(), to_main_thread=main, retry_seconds=3600
        )
        self.addCleanup(session.stop)
        session.on_screen = lambda _screen: None
        session.start()
        session.act("connection.disconnect", "media")
        main.pump()  # the action's `then`, which submits the refresh
        main.pump()  # the refresh's screen

        self.assertEqual(calls, ["connection.disconnect", "status"])


def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = threading.Event()
    for _ in range(int(timeout / 0.01)):
        if predicate():
            return
        deadline.wait(0.01)
    raise AssertionError("timed out waiting for the session")


def _sleep_through_retries(rounds: int = 4, interval: float = 0.05) -> None:
    threading.Event().wait(rounds * interval)


if __name__ == "__main__":
    unittest.main()
