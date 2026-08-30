"""What the window shows — decided here so it can be tested without GTK.

`gi` is a Debian package (D11) and the suite has no non-stdlib dependency, so
a rule that lived in a widget callback would live somewhere no test on a
development machine could reach. These are the M6 decisions, under test.
"""

from __future__ import annotations

import unittest

from smbpal.daemon import handlers
from smbpal.gui import model
from smbpal.mounts import apply as mounts_apply
from smbpal.mounts import probe
from smbpal.state import machine


class TestConnectionRows(unittest.TestCase):
    def row(self, **kw) -> model.Row:
        base = {
            "id": "nas",
            "host": "nas.local",
            "share": "Media",
            "mountpoint": "/media/pi/Media",
            "state": "idle",
        }
        return model.connection_row({**base, **kw})

    def test_an_idle_connection_is_calm_and_present(self) -> None:
        # 3h: an armed automount is invisible to the file manager until
        # something touches it, so this window is the only place it exists.
        # Painting it as a fault would train people to ignore the colour that
        # matters — M0 §4 found the mount happening 80 s after boot, on first
        # access, which is the design working.
        row = self.row()
        self.assertEqual(row.tone, model.IDLE)
        self.assertFalse(row.needs_attention)
        self.assertIn("it will connect when you open it", row.message)

    def test_a_connected_row_offers_disconnect(self) -> None:
        # The only place it can work. A file manager's eject runs `umount` as
        # the user and the kernel refuses a systemd mount — confirmed on the
        # Pi, 27 August 2026.
        row = self.row(state="connected")
        self.assertIn(model.DISCONNECT, row.actions)
        self.assertNotIn(model.CONNECT, row.actions)

    def test_a_disconnected_row_offers_connect(self) -> None:
        self.assertIn(model.CONNECT, self.row(state="idle").actions)

    def test_auth_failure_offers_the_password_first(self) -> None:
        # Retrying will not help — the kernel already stopped. Offering
        # Connect would reproduce the failure and latch the unit.
        row = self.row(state="auth_failed")
        self.assertEqual(row.actions[0], model.SET_CREDENTIALS)
        self.assertTrue(row.needs_attention)

    def test_the_fallback_is_offered_only_when_unresolved(self) -> None:
        # §3e: recorded, offered, never taken on its own — the address may
        # since belong to a different machine.
        unresolved = self.row(state="unresolved", fallback_host="192.0.2.52")
        self.assertIn(model.USE_FALLBACK, unresolved.actions)
        connected = self.row(state="connected", fallback_host="192.0.2.52")
        self.assertNotIn(model.USE_FALLBACK, connected.actions)

    def test_no_fallback_recorded_means_no_offer(self) -> None:
        self.assertNotIn(model.USE_FALLBACK, self.row(state="unresolved").actions)

    def test_a_disabled_connection_is_muted_not_broken(self) -> None:
        row = self.row(state="disabled")
        self.assertEqual(row.tone, model.MUTED)
        self.assertFalse(row.needs_attention)

    def test_the_daemons_message_wins_over_the_default(self) -> None:
        row = self.row(state="failed", message="/dev/sda1 (exfat) is mounted at …")
        self.assertIn("/dev/sda1", row.message)


class TestShareRows(unittest.TestCase):
    def test_a_read_only_share_says_why_and_offers_the_action(self) -> None:
        # §3c, the whole decision: read-only with a reason, and one explicit
        # action that changes it. Never a silent chown.
        row = model.share_row(
            {"id": "m", "name": "Media", "path": "/srv/m", "state": "read-only",
             "read_only": True, "credential_ref": "pi"}
        )
        self.assertIn(model.MAKE_WRITABLE, row.actions)
        self.assertTrue(row.message)
        self.assertEqual(row.tone, model.ATTENTION)

    def test_read_only_is_not_a_failure(self) -> None:
        row = model.share_row(
            {"id": "m", "name": "M", "path": "/srv/m", "state": "read-only",
             "read_only": True, "credential_ref": "pi"}
        )
        self.assertNotEqual(row.tone, model.PROBLEM)

    def test_no_user_assigned_means_no_make_writable(self) -> None:
        # There would be no defensible owner to give the directory to.
        row = model.share_row(
            {"id": "m", "name": "M", "path": "/srv/m", "state": "read-only",
             "read_only": True}
        )
        self.assertNotIn(model.MAKE_WRITABLE, row.actions)

    def test_a_hand_written_share_is_shown_and_offers_nothing(self) -> None:
        # §8 parks adopting these. Visible and marked, with no action, because
        # there is nothing SMBPal may correctly do to it.
        row = model.share_row(
            {"id": "-", "name": "Legacy", "path": "/srv/legacy", "state": "unmanaged"}
        )
        self.assertEqual(row.actions, ())
        self.assertIn("not modified", row.message)


class TestUnaccounted(unittest.TestCase):
    def test_an_orphan_asks_for_attention(self) -> None:
        row = model.unaccounted_row(
            {"kind": "orphaned", "mountpoint": "/mnt/x", "source": "//h/s",
             "connection_id": "old", "message": "…"}
        )
        self.assertTrue(row.needs_attention)

    def test_someone_elses_mount_is_information_not_a_task(self) -> None:
        row = model.unaccounted_row(
            {"kind": "unmanaged", "mountpoint": "/mnt/y", "source": "//o/s",
             "message": "…"}
        )
        self.assertFalse(row.needs_attention)


class TestScreen(unittest.TestCase):
    STATUS = {
        "daemon": {"version": "0.1.0", "config": "/etc/smbpal/config.json"},
        "shares": [
            {"id": "m", "name": "Media", "path": "/srv/m", "state": "serving"},
            {"id": "r", "name": "Ro", "path": "/srv/r", "state": "read-only",
             "read_only": True, "credential_ref": "pi"},
        ],
        "connections": [
            {"id": "a", "host": "h", "share": "s", "mountpoint": "/m",
             "state": "connected"},
            {"id": "b", "host": "h", "share": "t", "mountpoint": "/n",
             "state": "auth_failed", "message": "the password was refused"},
        ],
        "unaccounted": [
            {"kind": "orphaned", "mountpoint": "/mnt/x", "connection_id": "old",
             "source": "//h/s", "message": "…"}
        ],
    }

    def test_every_section_is_built(self) -> None:
        built = model.screen(self.STATUS)
        self.assertEqual(len(built.shares), 2)
        self.assertEqual(len(built.connections), 2)
        self.assertEqual(len(built.unaccounted), 1)

    def test_problems_gathers_across_sections(self) -> None:
        # 3g's icon has one state and SMBPal has two axes. This is the list it
        # reduces, so the reduction is testable rather than living in a tray.
        problems = model.screen(self.STATUS).problems
        self.assertEqual({r.id for r in problems}, {"r", "b", "old"})

    def test_a_healthy_machine_has_no_problems(self) -> None:
        quiet = {"daemon": {}, "shares": [], "connections": [
            {"id": "a", "host": "h", "share": "s", "mountpoint": "/m",
             "state": "idle"}]}
        self.assertEqual(model.screen(quiet).problems, [])


class TestPushedEvents(unittest.TestCase):
    """M5 pushes; the window folds it in rather than re-fetching."""

    def rows(self) -> list[model.Row]:
        return [
            model.connection_row(
                {"id": "a", "host": "h", "share": "s", "mountpoint": "/m",
                 "state": "idle"}
            )
        ]

    def test_an_event_updates_the_row_it_names(self) -> None:
        updated = model.apply_event(
            self.rows(), {"id": "a", "state": "connected", "message": "mounted"}
        )
        self.assertEqual(updated[0].state, "connected")
        self.assertEqual(updated[0].tone, model.OK)
        self.assertIn(model.DISCONNECT, updated[0].actions)

    def test_an_event_for_something_else_changes_nothing(self) -> None:
        before = self.rows()
        self.assertEqual(model.apply_event(before, {"id": "z", "state": "failed"}), before)

    def test_the_title_survives_an_event_that_does_not_carry_it(self) -> None:
        # The event has no host or share. Rebuilding the row from it alone
        # would blank the line identifying which connection this is.
        updated = model.apply_event(self.rows(), {"id": "a", "state": "failed"})
        self.assertEqual(updated[0].title, "//h/s")

    def test_a_hint_arrives_with_the_event(self) -> None:
        updated = model.apply_event(
            self.rows(),
            {"id": "a", "state": "unresolved", "message": "…", "hint": "try the fallback"},
        )
        self.assertEqual(updated[0].hint, "try the fallback")


class TestActionWiring(unittest.TestCase):
    """`Remove` is two different methods, and the widgets must not decide which."""

    def test_remove_on_a_share_and_on_a_connection_are_different_methods(self) -> None:
        share = model.share_row({"id": "docs", "name": "Docs", "state": "serving"})
        connection = model.connection_row({"id": "media", "state": "idle"})
        self.assertEqual(model.method_for(share, model.REMOVE), "share.remove")
        self.assertEqual(
            model.method_for(connection, model.REMOVE), "connection.remove"
        )

    def test_every_offered_action_has_a_method_and_a_label(self) -> None:
        """A button with no method behind it is a button that does nothing."""
        rows = [
            model.connection_row({"id": "a", "state": state, "fallback_host": "192.0.2.5"})
            for state in _CONNECTION_STATES
        ] + [
            model.share_row({"id": "s", "name": "S", "read_only": True,
                             "credential_ref": "c"}),
            model.share_row({"id": "s", "name": "S", "state": "serving"}),
        ]
        for row in rows:
            for action in row.actions:
                with self.subTest(section=row.section, action=action):
                    self.assertTrue(model.method_for(row, action))
                    self.assertIn(action, model.ACTION_LABELS)

    def test_an_action_the_section_does_not_have_is_a_mistake_not_a_no_op(self) -> None:
        share = model.share_row({"id": "docs", "name": "Docs", "state": "serving"})
        with self.assertRaises(ValueError):
            model.method_for(share, model.DISCONNECT)


class TestConfirmations(unittest.TestCase):
    def test_removing_a_share_promises_the_folder_is_left_alone(self) -> None:
        row = model.share_row({"id": "docs", "name": "Docs", "path": "/srv/docs"})
        text = model.confirmation(row, model.REMOVE)
        self.assertIn("stays exactly where it is", text)

    def test_removing_a_connection_names_where_it_will_stop_appearing(self) -> None:
        row = model.connection_row(
            {"id": "media", "host": "h", "share": "s", "mountpoint": "/media/pi/Media",
             "state": "connected"}
        )
        self.assertIn("/media/pi/Media", model.confirmation(row, model.REMOVE))

    def test_making_a_share_writable_says_it_changes_ownership(self) -> None:
        row = model.share_row(
            {"id": "docs", "name": "Docs", "path": "/srv/docs", "read_only": True,
             "credential_ref": "c"}
        )
        text = model.confirmation(row, model.MAKE_WRITABLE)
        self.assertIn("changes who owns", text)
        self.assertIn("cannot be undone", text)

    def test_a_reversible_action_asks_nothing(self) -> None:
        row = model.connection_row({"id": "media", "state": "idle"})
        self.assertIsNone(model.confirmation(row, model.CONNECT))

    def test_everything_marked_as_needing_confirming_has_something_to_say(self) -> None:
        rows = [
            model.connection_row({"id": "a", "state": "connected"}),
            model.share_row({"id": "s", "name": "S", "read_only": True,
                             "credential_ref": "c"}),
        ]
        for row in rows:
            for action in row.actions:
                if action in model.NEEDS_CONFIRMING:
                    with self.subTest(section=row.section, action=action):
                        self.assertTrue(model.confirmation(row, action))


_CONNECTION_STATES = (
    "connected", "connecting", "reconnecting", "idle", "disabled", "unknown",
    "failed", "auth_failed", "unreachable", "unresolved",
)


class TestEveryStateIsAccountedFor(unittest.TestCase):
    """The bug this pins, found by opening the window rather than by a test.

    `share_row` and `connection_row` used to end in an `else` that painted an
    unrecognised state red and used the state token as its own explanation. So
    a share whose state was `unknown` — meaning *SMBPal could not ask Samba* —
    appeared as a broken share, explained by the word "unknown". These walk the
    vocabularies the daemon actually emits, so a state added there fails here
    instead of reaching somebody as a red row saying nothing.
    """

    def test_every_connection_state_the_daemon_can_send_has_a_presentation(self) -> None:
        # Three sources, because three things produce a connection's state: the
        # monitor, the planner (before the monitor's first look), and the
        # daemon itself when it was started with --no-apply.
        states = (
            set(machine.STATES)
            | set(probe.STATES)
            | {mounts_apply.OCCUPIED, mounts_apply.NO_CREDENTIALS}
            | {handlers.NOT_APPLIED}
        )
        for state in sorted(states):
            with self.subTest(state=state):
                row = model.connection_row({"id": "a", "state": state})
                self.assertNotEqual(
                    (row.tone, row.message),
                    model.UNRECOGNISED,
                    f"{state!r} reaches the window with nothing decided about it",
                )
                self.assertTrue(row.message)

    def test_every_share_state_the_daemon_can_send_has_a_presentation(self) -> None:
        for state in handlers.SHARE_STATES:
            with self.subTest(state=state):
                row = model.share_row({"id": "s", "name": "S", "state": state})
                self.assertNotEqual(
                    (row.tone, row.message),
                    model.UNRECOGNISED,
                    f"{state!r} reaches the window with nothing decided about it",
                )
                self.assertTrue(row.message)

    def test_a_state_nobody_planned_for_is_calm_and_says_so(self) -> None:
        """It is our gap, not the share's fault, so it must not read as one."""
        row = model.share_row({"id": "s", "name": "S", "state": "something new"})
        self.assertEqual(row.tone, model.MUTED)
        self.assertIn("does not recognise", row.message)

    def test_a_share_samba_could_not_be_asked_about_is_not_shown_as_broken(self) -> None:
        row = model.share_row({"id": "s", "name": "S", "state": "unknown"})
        self.assertEqual(row.tone, model.MUTED)
        self.assertIn("could not ask Samba", row.message)

    def test_a_connection_with_no_stored_password_offers_to_take_one(self) -> None:
        row = model.connection_row({"id": "a", "state": mounts_apply.NO_CREDENTIALS})
        self.assertEqual(row.actions[0], model.SET_CREDENTIALS)
        self.assertNotIn(model.CONNECT, row.actions)

    def test_an_occupied_mountpoint_does_not_offer_a_button_that_would_fail(self) -> None:
        row = model.connection_row({"id": "a", "state": mounts_apply.OCCUPIED})
        self.assertNotIn(model.CONNECT, row.actions)
        self.assertEqual(row.tone, model.PROBLEM)

    def test_a_mount_the_monitor_has_not_seen_yet_is_still_shown_as_mounted(self) -> None:
        """The planner says `mounted`; the monitor says `connected`. Both are OK."""
        row = model.connection_row({"id": "a", "state": probe.MOUNTED})
        self.assertEqual(row.tone, model.OK)
        self.assertIn(model.DISCONNECT, row.actions)

    def test_an_unmounted_automount_is_calm_whichever_word_arrived(self) -> None:
        for state in (machine.IDLE, probe.NOT_MOUNTED):
            with self.subTest(state=state):
                row = model.connection_row({"id": "a", "state": state})
                self.assertEqual(row.tone, model.IDLE)
                self.assertIn(model.CONNECT, row.actions)


class TestTheTrayIndicator(unittest.TestCase):
    """3g's open question: one icon, two axes, and 3h's third state."""

    def screen(self, shares=(), connections=()) -> model.Screen:
        return model.screen({"shares": list(shares), "connections": list(connections)})

    def test_nothing_configured_still_shows_an_icon(self) -> None:
        """SNI's `Passive` would hide it exactly when somebody needs a way in."""
        found = model.indicator(self.screen())
        self.assertEqual(found.status, model.MUTED)
        self.assertEqual(found.title, "nothing set up yet")
        self.assertFalse(found.needs_attention)

    def test_configured_and_nothing_live_is_calm(self) -> None:
        """3h one layer up: armed and unmounted is healthy, not a fault."""
        found = model.indicator(
            self.screen(connections=[{"id": "n", "state": "idle"}])
        )
        self.assertEqual(found.status, model.IDLE)
        self.assertFalse(found.needs_attention)

    def test_both_axes_are_counted_when_all_is_well(self) -> None:
        found = model.indicator(
            self.screen(
                shares=[{"id": "d", "name": "Docs", "state": "serving"}],
                connections=[
                    {"id": "n", "state": "connected"},
                    {"id": "m", "state": "connected"},
                ],
            )
        )
        self.assertEqual(found.status, model.OK)
        self.assertIn("1 folder shared", found.title)
        self.assertIn("2 shares connected", found.title)

    def test_one_problem_puts_its_own_words_on_the_icon(self) -> None:
        found = model.indicator(
            self.screen(
                connections=[
                    {"id": "n", "state": "auth_failed", "message": "the password was refused"}
                ]
            )
        )
        self.assertEqual(found.status, model.PROBLEM)
        self.assertEqual(found.title, "the password was refused")

    def test_several_problems_are_counted_rather_than_picked_between(self) -> None:
        found = model.indicator(
            self.screen(
                shares=[{"id": "d", "name": "Docs", "state": "not served"}],
                connections=[{"id": "n", "state": "unreachable", "message": "no answer"}],
            )
        )
        self.assertEqual(found.title, "2 things need attention")

    def test_a_broken_mount_beside_a_healthy_share_says_which(self) -> None:
        """The plan's worry, and why the detail carries both axes separately."""
        found = model.indicator(
            self.screen(
                shares=[{"id": "d", "name": "Docs", "state": "serving"}],
                connections=[
                    {"id": "n", "host": "h", "share": "s", "state": "unreachable",
                     "message": "the server did not answer"}
                ],
            )
        )
        self.assertEqual(found.status, model.PROBLEM)
        self.assertIn("1 folder shared", found.detail)
        self.assertIn("//h/s: the server did not answer", found.detail)

    def test_the_detail_states_an_empty_axis_rather_than_omitting_it(self) -> None:
        """A line that disappears cannot tell anybody anything."""
        found = model.indicator(
            self.screen(connections=[{"id": "n", "state": "connected"}])
        )
        self.assertIn("Nothing shared from this computer", found.detail)

    def test_a_read_only_share_counts_as_shared(self) -> None:
        found = model.indicator(
            self.screen(shares=[{"id": "d", "name": "D", "state": "read-only"}])
        )
        # Read-only asks for attention on its row, so the icon does too — but
        # the share is being served and the count must say so.
        self.assertIn("1 folder shared", found.detail)

    def test_a_daemon_that_is_not_answering_is_a_problem_not_a_blank(self) -> None:
        """An icon that stayed calm about this would be calm about being blind."""
        found = model.offline_indicator("no SMBPal daemon is listening on /run/x")
        self.assertEqual(found.status, model.PROBLEM)
        self.assertTrue(found.needs_attention)
        self.assertIn("no SMBPal daemon is listening", found.detail)
        # And it does not claim the shares have gone: systemd is holding them.
        self.assertIn("already up are unaffected", found.detail)


if __name__ == "__main__":
    unittest.main()
