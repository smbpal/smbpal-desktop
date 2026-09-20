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

import time
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
        """A row the screen no longer has leaves nothing behind, buttons included."""
        self.window._show(model.Screen())
        self.assertEqual(self.window._row_buttons, {})

    def test_an_error_is_said_in_the_banner(self) -> None:
        self.window._on_error(SmbpalError("it did not work"))
        self.assertIn("it did not work", self.window._banner.get_label())
        self.assertTrue(self.window._banner.get_visible())


@needs_gtk
class TestTheWindowUpdatesInPlace(unittest.TestCase):
    """The scroll position used to go back to the top on every event.

    `_rebuild` emptied the body and built every row again, which collapses the
    scrolled window's content, so an update anywhere sent somebody scrolling
    towards a broken row back to the top: exactly while a network is
    misbehaving, which is exactly when they are scrolling
    (`ideas/window-at-scale.md`). The scroll position itself cannot be read
    without a realised, laid-out window, so these pin the mechanism: nothing
    the update did not change is replaced, and the body is never emptied.
    """

    def setUp(self) -> None:
        self.session = FakeSession()
        self.window = Window(None, self.session)
        self.window._show(model.screen(STATUS))

    def widgets(self) -> dict[str, Any]:
        sections = (
            self.window._shares,
            self.window._connections,
            self.window._unaccounted,
        )
        return {i: w for s in sections for i, (_r, w) in s.drawn.items()}

    def order(self, section: Any) -> list[Any]:
        listbox, rows, index = section.listbox, [], 0
        while (row := listbox.get_row_at_index(index)) is not None:
            rows.append(row)
            index += 1
        return rows

    def test_an_event_replaces_only_the_row_it_is_about(self) -> None:
        before = self.widgets()
        self.window._on_event({"id": "c1", "state": "failed", "message": "gone"})
        after = self.widgets()
        self.assertIsNot(after["c1"], before["c1"])
        self.assertIs(after["s1"], before["s1"])
        self.assertIs(after["s2"], before["s2"])

    def test_a_screen_that_did_not_change_changes_no_widget(self) -> None:
        before = self.widgets()
        self.window._show(model.screen(STATUS))
        self.assertEqual(
            {i: id(w) for i, w in self.widgets().items()},
            {i: id(w) for i, w in before.items()},
        )

    def test_the_body_is_never_emptied(self) -> None:
        """What collapsed the scroll. The body's own children are made once."""
        body, children, child = self.window._body, [], None
        child = body.get_first_child()
        while child is not None:
            children.append(child)
            child = child.get_next_sibling()
        self.window._on_event({"id": "c1", "state": "failed"})
        self.window._show(model.Screen())
        self.window._show(model.screen(STATUS))
        after, child = [], body.get_first_child()
        while child is not None:
            after.append(child)
            child = child.get_next_sibling()
        self.assertEqual([id(c) for c in after], [id(c) for c in children])

    def test_a_new_row_lands_where_the_screen_puts_it(self) -> None:
        status = {
            **STATUS,
            "shares": [
                STATUS["shares"][0],
                {"id": "s3", "name": "Music", "state": "serving", "path": "/srv/music"},
                STATUS["shares"][1],
            ],
        }
        self.window._show(model.screen(status))
        drawn = self.window._shares.drawn
        self.assertEqual(
            self.order(self.window._shares),
            [drawn["s1"][1], drawn["s3"][1], drawn["s2"][1]],
        )

    def test_a_row_that_went_leaves_the_list(self) -> None:
        gone = self.widgets()["s2"]
        self.window._show(model.screen({**STATUS, "shares": STATUS["shares"][:1]}))
        self.assertNotIn(gone, self.order(self.window._shares))
        self.assertNotIn("s2", self.window._row_buttons)

    def test_an_empty_section_says_so_and_the_unaccounted_one_hides(self) -> None:
        self.window._show(model.Screen())
        self.assertTrue(self.window._shares.placeholder.get_visible())
        self.assertFalse(self.window._shares.frame.get_visible())
        self.assertFalse(self.window._unaccounted.head.get_visible())
        self.assertFalse(self.window._unaccounted.placeholder.get_visible())


@needs_gtk
class TestTheScrollPositionSurvivesAnUpdate(unittest.TestCase):
    """The defect itself, measured on a window that is really on screen.

    Sixty-five rows, scrolled most of the way down, then one connection
    changes state. Before the fix this read 2650 before the event and 16
    after it: the top of the window.
    """

    def pump(self, until: Any = None, timeout: float = 3.0) -> None:
        from gi.repository import GLib

        end = time.monotonic() + timeout
        context = GLib.MainContext.default()
        while time.monotonic() < end:
            context.iteration(False)
            if until is not None and until():
                return

    def test_an_event_does_not_scroll_the_window_to_the_top(self) -> None:
        status = {
            "shares": [
                {
                    "id": f"s{i}",
                    "name": f"Share {i}",
                    "state": "serving",
                    "path": f"/srv/{i}",
                }
                for i in range(40)
            ],
            "connections": [
                {"id": f"c{i}", "name": f"Server {i}", "state": "connected"}
                for i in range(25)
            ],
        }
        window = Window(None, FakeSession())
        self.addCleanup(window.destroy)
        window._show(model.screen(status))
        window.present()
        adjustment = window._scroller.get_vadjustment()
        self.pump(until=lambda: adjustment.get_upper() > adjustment.get_page_size() * 2)
        if adjustment.get_upper() <= adjustment.get_page_size() * 2:
            self.skipTest("the window was never laid out, so nothing can scroll")

        adjustment.set_value(adjustment.get_upper() * 0.6)
        self.pump(timeout=0.3)
        before = adjustment.get_value()
        self.assertGreater(before, 0)

        window._on_event({"id": "c12", "state": "failed", "message": "gone"})
        self.pump(timeout=0.3)
        self.assertEqual(adjustment.get_value(), before)

        window._show(model.screen(status))
        self.pump(timeout=0.3)
        self.assertEqual(adjustment.get_value(), before)


@needs_gtk
class TestTheHeaderSaysHowToReachThisComputer(unittest.TestCase):
    """Asked for from the Pi: show this machine's .local name and address."""

    def setUp(self) -> None:
        self.window = Window(None, FakeSession())

    def test_the_identity_is_the_subtitle_and_the_daemon_its_tooltip(self) -> None:
        self.window._show(
            model.screen(
                {
                    **STATUS,
                    "daemon": {"version": "0.2.1", "config": "/etc/smbpal/config.json"},
                    "host": {"hostname": "nas", "mdns": "nas.local",
                             "addresses": ["192.0.2.10"]},
                }
            )
        )
        self.assertEqual(self.window._subtitle.get_text(), "nas.local · 192.0.2.10")
        self.assertIn("smbpald 0.2.1", self.window._subtitle.get_tooltip_text())
        self.assertTrue(self.window._subtitle.get_selectable())

    def test_without_an_identity_the_daemon_line_stays(self) -> None:
        self.window._show(model.screen({**STATUS, "daemon": {"version": "0.2.1"}}))
        self.assertIn("smbpald 0.2.1", self.window._subtitle.get_text())

    def test_an_event_does_not_lose_it(self) -> None:
        """`_on_event` rebuilt the screen field by field, which drops new fields."""
        self.window._show(
            model.screen(
                {**STATUS, "host": {"mdns": "nas.local", "addresses": []}}
            )
        )
        self.window._on_event({"id": "c1", "state": "failed"})
        self.assertEqual(self.window._screen.here, "nas.local")


@needs_gtk
class TestSettingTheSmbPassword(unittest.TestCase):
    """Found on Ubuntu: a share nobody could open, and no way to fix it here."""

    def setUp(self) -> None:
        from smbpal.gui.window import SmbPasswordDialog

        self.saved: list[str] = []
        self.dialog = SmbPasswordDialog(None, "luke", self.saved.append)

    def type(self, first: str, second: str) -> None:
        self.dialog._password.set_text(first)
        self.dialog._again.set_text(second)

    def test_it_will_not_save_until_both_match(self) -> None:
        self.type("one", "two")
        self.assertFalse(self.dialog._go.get_sensitive())
        self.assertTrue(self.dialog._mismatch.get_visible())
        self.type("same", "same")
        self.assertTrue(self.dialog._go.get_sensitive())
        self.dialog._accept(None)
        self.assertEqual(self.saved, ["same"])

    def test_a_share_row_sends_the_account_and_the_password(self) -> None:
        session = FakeSession()
        window = Window(None, session)
        row = model.share_row(
            {"id": "m", "name": "Media", "path": "/srv/m", "state": "serving",
             "credential_ref": "luke", "can_sign_in": False}
        )
        opened: list[Any] = []
        import smbpal.gui.window as window_module

        original = window_module.SmbPasswordDialog

        class Capture:
            def __init__(self, _parent: Any, username: str, save: Any) -> None:
                opened.append(username)
                save("secret-1")

            def present(self) -> None:
                pass

        window_module.SmbPasswordDialog = Capture
        self.addCleanup(setattr, window_module, "SmbPasswordDialog", original)
        window._invoke(row, model.SET_SMB_PASSWORD)
        self.assertEqual(opened, ["luke"])
        method, params = session.submitted[-1]
        self.assertEqual(method, "credential.set")
        self.assertEqual((params["username"], params["password"]), ("luke", "secret-1"))


@needs_gtk
class TestRefusedCredentialsDoNotMakeASecondConnection(unittest.TestCase):
    """Reported from a Pi on 20 September 2026: "now i have 2".

    The form makes two calls. The connection is added, its credentials are
    refused, and the error read as though nothing had happened — so the form
    was filled in again, the second press added a *second* connection, and
    `default_mountpoint` politely gave it a mountpoint of its own rather than
    colliding with the first.
    """

    def setUp(self) -> None:
        from smbpal.gui.dialogs import AddConnectionDialog

        self.session = FakeSession()
        self.form = AddConnectionDialog(None, self.session)
        self.form._host.set_text("nas.local")
        self.form._share.set_text("Media")
        self.form._user.set_text("luke")
        self.form._password.set_text("wrong")

    def refuse(self) -> None:
        self.form._submit()
        self.assertEqual(self.session.submitted[-1][0], "connection.add")
        self.session.reply({"id": "nas-media", "mountpoint": "/media/luke/Media"})
        self.assertEqual(self.session.submitted[-1][0], "connection.set_credentials")
        self.session.fail(SmbpalError("the username or password was refused"))

    def test_a_retry_corrects_the_connection_it_already_made(self) -> None:
        self.refuse()
        self.form._password.set_text("right")
        self.form._submit()
        method, params = self.session.submitted[-1]
        self.assertEqual(method, "connection.set_credentials")
        self.assertEqual(params["ref"], "nas-media")
        self.assertEqual(params["password"], "right")
        # The whole point: no second connection was ever asked for.
        self.assertEqual(
            [m for m, _ in self.session.submitted].count("connection.add"), 1
        )

    def test_the_error_says_the_connection_exists(self) -> None:
        self.refuse()
        text = self.form._error.get_text()
        self.assertIn("refused", text)
        # Without this sentence the obvious next move is to add it again.
        self.assertIn("connection was created", text)


@needs_gtk
class TestSharingAFolderSetsUpSigningIn(unittest.TestCase):
    def setUp(self) -> None:
        from smbpal.gui.dialogs import AddShareDialog

        self.session = FakeSession()
        self.form = AddShareDialog(None, self.session)
        self.form._path.set_text("/srv/media")
        self.form._user.set_text("luke")
        # The form asks who already has an SMB password as it opens.
        self.assertEqual(self.session.submitted[0][0], "credential.list")

    def answer_accounts(self, accounts: list[str]) -> None:
        self.session.then[0](accounts)

    def test_an_account_with_no_password_must_be_given_one(self) -> None:
        self.answer_accounts([])
        self.assertTrue(self.form._password.get_visible())
        self.assertFalse(self.form._go.get_sensitive())
        self.form._password.set_text("pw-1")
        self.form._again.set_text("pw-1")
        self.assertTrue(self.form._go.get_sensitive())

    def test_the_password_is_set_before_the_share_is_added(self) -> None:
        self.answer_accounts([])
        self.form._password.set_text("pw-1")
        self.form._again.set_text("pw-1")
        self.form._submit()
        self.assertEqual(self.session.submitted[-1][0], "credential.set")
        self.assertEqual(self.session.submitted[-1][1]["username"], "luke")
        self.session.reply({"username": "luke"})
        method, params = self.session.submitted[-1]
        self.assertEqual(method, "share.add")
        self.assertEqual(params["credential_ref"], "luke")

    def test_a_failed_password_adds_no_share(self) -> None:
        self.answer_accounts([])
        self.form._password.set_text("pw-1")
        self.form._again.set_text("pw-1")
        self.form._submit()
        self.session.fail(SmbpalError("smbpasswd said no"))
        self.assertNotIn("share.add", [m for m, _p in self.session.submitted])
        self.assertTrue(self.form._error.get_visible())

    def test_an_account_that_has_one_is_not_asked_again(self) -> None:
        self.answer_accounts(["luke"])
        self.assertFalse(self.form._password.get_visible())
        self.assertIn(
            "already has an SMB password", self.form._password_note.get_text()
        )
        self.assertTrue(self.form._go.get_sensitive())
        self.form._submit()
        self.assertEqual(self.session.submitted[-1][0], "share.add")

    def test_unknown_accounts_make_the_password_optional(self) -> None:
        self.session.catch[0](SmbpalError("pdbedit failed"))
        self.assertTrue(self.form._password.get_visible())
        self.assertTrue(self.form._go.get_sensitive())

    def test_the_account_is_required(self) -> None:
        self.answer_accounts(["luke"])
        self.form._user.set_text("")
        self.assertFalse(self.form._go.get_sensitive())

    def test_it_starts_filled_in_with_whoever_is_here(self) -> None:
        from gi.repository import GLib
        from smbpal.gui.dialogs import AddShareDialog

        fresh = AddShareDialog(None, FakeSession())
        self.assertEqual(fresh._user.get_text(), GLib.get_user_name())


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

        `_rebuild` replaces the widgets of any row whose content changed, and
        an unrelated `state.changed` arriving mid-call is exactly when that
        happens — a network misbehaving is why somebody is removing a row in
        the first place. Disabling the widget alone is undone by it.
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


@needs_gtk
class TestTheFormFlags(unittest.TestCase):
    """The tray runs `smbpal-gui --new-share`; nothing checks the spelling but this."""

    def test_the_tray_flags_are_the_app_actions(self) -> None:
        from smbpal.gui import app, tray

        self.assertEqual(
            sorted(flag for _label, flag in tray.FORM_ITEMS.values()),
            sorted(f"--{name}" for name in app.FORMS),
        )

    def test_every_form_action_names_a_window_action(self) -> None:
        from smbpal.gui import app

        window = Window(None, FakeSession())
        for form in app.FORMS.values():
            with self.subTest(action=form):
                self.assertIsNotNone(window.lookup_action(form))
