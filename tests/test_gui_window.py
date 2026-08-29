"""The window, built for real and driven the way a click drives it.

**There was no test file here at all until 29 August 2026**, and that absence
is the reason two of M6's defects reached hardware. `model` decides what a row
says and is tested exhaustively; `session` decides what reaches the socket and
is tested exhaustively; the widget layer in between decided things too, and
nothing looked. Both of the window's known defects — the scroll position lost
on every event, and a Remove button that stayed live during its own removal —
live in the one GUI module with no coverage.

The window turns out to be perfectly testable without a display server, which
is the part that was assumed rather than checked. `Gtk.init_check()` succeeds
headless on the platforms this runs on, `application=None` builds a real
`Gtk.ApplicationWindow`, and every widget the window makes can be inspected
without a main loop ever running. What cannot be tested here is anything that
needs the compositor to answer — a portal, a popup's placement, whether a
modal window gets keyboard focus. Those stay in `pi-gui-smoke.md`, where they
belong; this file is for the logic that was hiding among them.
"""

from __future__ import annotations

import unittest
from typing import Any

try:
    import gi

    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk

    _HAVE_DISPLAY = bool(Gtk.init_check())
except ImportError:  # pragma: no cover - a machine without python3-gi
    Gtk = None
    _HAVE_DISPLAY = False

if _HAVE_DISPLAY:
    from smbpal.errors import SmbpalError
    from smbpal.gui import model
    from smbpal.gui.window import Window

needs_gtk = unittest.skipUnless(
    _HAVE_DISPLAY, "python3-gi with a usable GDK display is not available"
)


class FakeSession:
    """Records what was submitted and hands back the callbacks it was given."""

    on_screen = None
    on_event = None
    on_error = None
    on_daemon_lost = None
    on_daemon_back = None

    def __init__(self) -> None:
        self.submitted: list[tuple[str, dict[str, Any]]] = []
        self.then: list[Any] = []
        self.catch: list[Any] = []
        self.refreshed = 0

    def submit(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        then: Any = None,
        transform: Any = None,
        catch: Any = None,
    ) -> None:
        self.submitted.append((method, params or {}))
        self.then.append(then)
        self.catch.append(catch)

    def refresh(self) -> None:
        self.refreshed += 1

    def reply(self, result: Any = None) -> None:
        """The daemon answering, on the main thread, as `Session` would."""
        self.then[-1](result)

    def fail(self, exc: SmbpalError) -> None:
        self.catch[-1](exc)


STATUS = {
    "shares": [
        {"id": "s1", "name": "Docs", "state": "serving", "path": "/srv/docs"},
        {"id": "s2", "name": "Photos", "state": "serving", "path": "/srv/photos"},
    ],
    "connections": [
        {"id": "c1", "name": "Media", "state": "connected"},
    ],
}


@needs_gtk
class TestWhatTheWindowDraws(unittest.TestCase):
    def setUp(self) -> None:
        self.session = FakeSession()
        self.window = Window(None, self.session)
        self.window._show(model.screen(STATUS))

    def test_every_row_in_the_screen_becomes_a_line(self) -> None:
        self.assertEqual(set(self.window._row_buttons), {"s1", "s2", "c1"})

    def test_a_row_with_no_screen_leaves_nothing_behind(self) -> None:
        """`_rebuild` empties the body, so a stale row cannot survive it."""
        self.window._show(model.Screen())
        self.assertEqual(self.window._row_buttons, {})

    def test_an_error_is_said_in_the_banner(self) -> None:
        self.window._on_error(SmbpalError("it did not work"))
        self.assertIn("it did not work", self.window._banner.get_label())
        self.assertTrue(self.window._banner.get_visible())


@needs_gtk
class TestAskingBeforeSomethingIrreversible(unittest.TestCase):
    def setUp(self) -> None:
        self.session = FakeSession()
        self.window = Window(None, self.session)
        self.window._show(model.screen(STATUS))
        self.share = self.window._screen.shares[0]

    def test_removing_a_share_asks_before_it_sends(self) -> None:
        self.window._invoke(self.share, model.REMOVE)
        self.assertEqual(self.session.submitted, [])

    def test_an_action_with_nothing_to_ask_goes_straight_out(self) -> None:
        connection = self.window._screen.connections[0]
        self.assertIsNone(model.confirmation(connection, model.DISCONNECT))
        self.window._invoke(connection, model.DISCONNECT)
        self.assertEqual(len(self.session.submitted), 1)


@needs_gtk
class TestARowIsHeldWhileItsOwnCallIsInFlight(unittest.TestCase):
    """A removal is a round trip and the row stays on screen for all of it.

    Found on the Pi on 29 August 2026: *"remove button should be disabled
    while being removed."* A second click sent a second call carrying a `ref`
    the daemon had already acted on, so the error arrived after the removal
    had worked and read as the removal having failed.
    """

    def setUp(self) -> None:
        self.session = FakeSession()
        self.window = Window(None, self.session)
        self.window._show(model.screen(STATUS))
        self.share = self.window._screen.shares[0]

    def live(self, ref: str) -> list[bool]:
        return [b.get_sensitive() for b in self.window._row_buttons[ref]]

    def test_the_buttons_go_dead_when_the_call_goes_out(self) -> None:
        self.window._send(self.share, model.REMOVE)
        self.assertNotIn(True, self.live("s1"))

    def test_a_second_click_sends_nothing(self) -> None:
        """The defect itself, at the level a user meets it.

        Driven through Disconnect rather than Remove, because Remove on a
        share opens a confirmation and so never reaches `_send` on a second
        click anyway — a version of this test written against Remove passes
        whether the guard is there or not, which is worse than not having it.
        """
        connection = self.window._screen.connections[0]
        buttons = self.window._row_buttons["c1"]
        self.window._invoke(connection, model.DISCONNECT)
        self.assertEqual(len(self.session.submitted), 1)
        for button in buttons:
            button.emit("clicked")
        self.assertEqual(len(self.session.submitted), 1)

    def test_a_rebuild_mid_call_does_not_hand_back_a_live_button(self) -> None:
        """Why the held set lives on the window and not on the widgets.

        `_rebuild` destroys every widget it has ever made and builds fresh
        ones, and an unrelated `state.changed` arriving mid-call is exactly
        when that happens — a network misbehaving is why somebody is removing
        a row in the first place. Disabling the widget alone is undone by it.
        """
        self.window._send(self.share, model.REMOVE)
        self.window._rebuild()
        self.assertNotIn(True, self.live("s1"))

    def test_only_that_row_is_held(self) -> None:
        self.window._send(self.share, model.REMOVE)
        self.assertNotIn(False, self.live("s2"))
        self.assertNotIn(False, self.live("c1"))

    def test_the_reply_gives_the_buttons_back(self) -> None:
        self.window._send(self.share, model.REMOVE)
        self.session.reply(None)
        self.window._rebuild()
        self.assertNotIn(False, self.live("s1"))
        self.assertEqual(self.session.refreshed, 1)

    def test_a_failure_gives_them_back_too(self) -> None:
        """Otherwise a refused call leaves the row dead for the session.

        Nothing refreshes after an error, so the release has to rebuild for
        itself rather than waiting for a screen that is not coming.
        """
        self.window._send(self.share, model.REMOVE)
        self.session.fail(SmbpalError("the daemon said no"))
        self.assertNotIn(False, self.live("s1"))
        self.assertIn("the daemon said no", self.window._banner.get_label())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
