"""What the window shows — decided here so it can be tested without GTK.

`gi` is a Debian package (D11) and the suite has no non-stdlib dependency, so
a rule that lived in a widget callback would live somewhere no test on a
development machine could reach. These are the M6 decisions, under test.
"""

from __future__ import annotations

import unittest

from smbpal.gui import model


class TestConnectionRows(unittest.TestCase):
    def row(self, **kw) -> model.Row:
        base = {
            "id": "nas",
            "host": "rivendell.local",
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
        unresolved = self.row(state="unresolved", fallback_host="192.168.0.52")
        self.assertIn(model.USE_FALLBACK, unresolved.actions)
        connected = self.row(state="connected", fallback_host="192.168.0.52")
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


if __name__ == "__main__":
    unittest.main()
