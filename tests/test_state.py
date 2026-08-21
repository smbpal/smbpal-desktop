"""The state machine, the errno translation, and the push channel."""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from smbpal.config import ConfigStore, empty_config
from smbpal.config import operations as ops
from smbpal.mounts.apply import Mounter
from smbpal.mounts.credentials import CredentialsStore
from smbpal.mounts.probe import MountProbe
from smbpal.state import machine, translate
from smbpal.state.monitor import StateMonitor, fallback_hint
from tests.fakes import FakeSamba

# Verbatim from M0 §4's journal-wrong-password.txt — the whole reason this
# translation exists.
M0_AUTH_FAILURE = """\
mount[2824]: mount error(13): Permission denied
mount[2824]: Refer to the mount.cifs(8) manual page (e.g. man mount.cifs)
mnt-m0.mount: Mount process exited, code=exited, status=32/n/a
mnt-m0.mount: Failed with result 'exit-code'.
"""


# Verbatim from a Pi run on 21 August 2026, and the reason `reset-failed`
# exists. Note the last two lines: after five attempts systemd stops running
# mount.cifs at all, so the errno above is a reason that is no longer being
# reached.
PI_START_LIMIT = """\
mount error(13): Permission denied
Refer to the mount.cifs(8) manual page (e.g. man mount.cifs) and kernel log messages (dmesg)
mnt-smbpal\\x2dtest.mount: Mount process exited, code=exited, status=32/n/a
mnt-smbpal\\x2dtest.mount: Failed with result 'exit-code'.
Failed to mount mnt-smbpal\\x2dtest.mount - SMBPal mount of //rivendell.local/Media.
mnt-smbpal\\x2dtest.mount: Start request repeated too quickly.
mnt-smbpal\\x2dtest.mount: Failed with result 'exit-code'.
"""


class TestTranslate(unittest.TestCase):
    def test_m0s_rejected_password_becomes_a_reason_a_person_can_act_on(self) -> None:
        # The user saw `No such device`, which sends them hunting for a missing
        # disk. This is the sentence that should have reached them instead.
        cause = translate.translate_journal(M0_AUTH_FAILURE)
        self.assertEqual(cause.state, "auth_failed")
        self.assertEqual(cause.errno, 13)
        self.assertIn("password", cause.message)

    def test_a_rejected_credential_is_not_retryable(self) -> None:
        # M0 §4: a wrong password produced exactly one attempt while an
        # unreachable host produced seven. Retrying a bad credential is how
        # accounts get locked out.
        self.assertFalse(translate.translate_journal(M0_AUTH_FAILURE).retryable)

    def test_a_host_that_is_down_is_retryable(self) -> None:
        cause = translate.translate_journal("mount error(112): Host is down")
        self.assertEqual(cause.state, "unreachable")
        self.assertTrue(cause.retryable)

    def test_a_missing_share_is_not_retryable(self) -> None:
        cause = translate.translate_journal("mount error(2): No such file or directory")
        self.assertIn("no share by that name", cause.message)
        self.assertFalse(cause.retryable)

    def test_a_resolution_failure_has_no_errno_and_is_recognised_anyway(self) -> None:
        cause = translate.translate_journal(
            "mount error: could not resolve address for rivendell.local: Unknown error"
        )
        self.assertEqual(cause.state, "unresolved")
        self.assertIsNone(cause.errno)

    def test_the_most_recent_failure_wins(self) -> None:
        # A unit that failed, was fixed and failed again must report the reason
        # it failed this time.
        cause = translate.translate_journal(
            "mount error(13): Permission denied\nmount error(112): Host is down\n"
        )
        self.assertEqual(cause.errno, 112)

    def test_an_unrecognised_errno_still_says_something(self) -> None:
        cause = translate.translate_journal("mount error(999): what")
        self.assertEqual(cause.state, "failed")
        self.assertIn("999", cause.message)

    def test_a_journal_with_no_failure_returns_nothing(self) -> None:
        self.assertIsNone(translate.translate_journal("Mounted /mnt/nas.\n"))
        self.assertIsNone(translate.translate_journal(""))


class TestMachine(unittest.TestCase):
    CONNECTION = {"id": "nas", "mountpoint": "/mnt/nas", "auto_connect": "on_this_network"}

    def test_an_armed_automount_is_idle_and_not_a_problem(self) -> None:
        # M0 §4 found the mount happening on first access, 80 s after boot. An
        # automount nobody has touched is working exactly as designed, and
        # painting it red would train people to ignore the colour that matters.
        state = machine.derive(
            self.CONNECTION,
            mounted=False,
            unit={"ActiveState": "inactive", "Result": "success"},
        )
        self.assertEqual(state.state, machine.IDLE)
        self.assertFalse(state.is_problem)

    def test_an_unarmed_automount_is_not_reported_as_ready(self) -> None:
        # The same error class as counting autofs as mounted: claiming a state
        # we cannot back up. If nothing is armed, nothing mounts on access.
        state = machine.derive(
            self.CONNECTION,
            mounted=False,
            unit={"ActiveState": "inactive", "Result": "success"},
            armed=False,
        )
        self.assertEqual(state.state, machine.FAILED)
        self.assertIn("smbpal apply", state.message)

    def test_an_armed_automount_is_idle(self) -> None:
        state = machine.derive(
            self.CONNECTION,
            mounted=False,
            unit={"ActiveState": "inactive", "Result": "success"},
            armed=True,
        )
        self.assertEqual(state.state, machine.IDLE)

    def test_mounted_is_connected(self) -> None:
        state = machine.derive(self.CONNECTION, mounted=True, unit=None)
        self.assertEqual(state.state, machine.CONNECTED)

    def test_a_read_only_mount_says_so(self) -> None:
        state = machine.derive(
            self.CONNECTION, mounted=True, unit=None, read_only=True
        )
        self.assertEqual(state.state, machine.CONNECTED)
        self.assertTrue(state.read_only)
        self.assertIn("read-only", state.message)

    def test_a_writable_mount_is_never_called_writable(self) -> None:
        # Whether a write succeeds is the server's decision and we have not
        # asked it. "mounted" is all we can prove; granting write on the NAS
        # would not change anything we can see from here.
        state = machine.derive(
            self.CONNECTION, mounted=True, unit=None, read_only=False
        )
        self.assertEqual(state.message, "mounted")
        self.assertFalse(state.read_only)
        self.assertNotIn("writable", state.message)

    def test_a_failed_unit_with_a_cause_reports_the_cause(self) -> None:
        state = machine.derive(
            self.CONNECTION,
            mounted=False,
            unit={"ActiveState": "failed", "Result": "exit-code"},
            cause=translate.translate_journal(M0_AUTH_FAILURE),
        )
        self.assertEqual(state.state, machine.AUTH_FAILED)
        self.assertTrue(state.is_problem)
        self.assertEqual(state.errno, 13)

    def test_a_failed_unit_with_no_readable_cause_admits_it(self) -> None:
        state = machine.derive(
            self.CONNECTION,
            mounted=False,
            unit={"ActiveState": "failed", "Result": "exit-code", "ExecMainStatus": "32"},
        )
        self.assertEqual(state.state, machine.FAILED)
        self.assertIn("32", state.message)

    def test_a_start_limited_unit_says_nothing_is_retrying(self) -> None:
        # A Pi run hit this: five rejected mounts in ten seconds and systemd
        # stopped trying. Reporting only "the password was refused" would be
        # true and still leave someone stuck, because fixing the password
        # changes nothing until the latch is cleared.
        state = machine.derive(
            self.CONNECTION,
            mounted=False,
            unit={"ActiveState": "failed", "Result": "start-limit-hit"},
            cause=translate.translate_journal(PI_START_LIMIT),
        )
        self.assertEqual(state.state, machine.AUTH_FAILED)
        self.assertEqual(state.errno, 13)
        self.assertIn("password", state.message)
        self.assertIn("stopped retrying", state.message)
        self.assertIn("connection connect", state.message)

    def test_a_start_limited_unit_is_never_reported_as_retryable(self) -> None:
        # `retryable` means "waiting will fix this". Nothing is waiting.
        state = machine.derive(
            self.CONNECTION,
            mounted=False,
            unit={"ActiveState": "failed", "Result": "start-limit-hit"},
            cause=translate.Cause(
                state=machine.UNREACHABLE, message="the server did not answer in time",
                errno=110, retryable=True,
            ),
        )
        self.assertFalse(state.retryable)
        self.assertEqual(state.state, machine.FAILED)

    def test_a_start_limited_unit_with_no_cause_still_says_it_is_stuck(self) -> None:
        state = machine.derive(
            self.CONNECTION,
            mounted=False,
            unit={
                "ActiveState": "failed",
                "Result": "start-limit-hit",
                "ExecMainStatus": "32",
            },
        )
        self.assertEqual(state.state, machine.FAILED)
        self.assertFalse(state.retryable)
        self.assertIn("stopped retrying", state.message)

    def test_auto_connect_never_is_disabled_not_broken(self) -> None:
        state = machine.derive(
            {**self.CONNECTION, "auto_connect": "never"}, mounted=False, unit=None
        )
        self.assertEqual(state.state, machine.DISABLED)
        self.assertFalse(state.is_problem)

    def test_no_unit_information_is_unknown_rather_than_a_guess(self) -> None:
        state = machine.derive(self.CONNECTION, mounted=False, unit=None)
        self.assertEqual(state.state, machine.UNKNOWN)


class MonitorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        (self.root / "units").mkdir()
        # An applied connection has an armed automount sitting on the
        # mountpoint. An empty table would mean nothing was armed, which is a
        # different — and now correctly reported — situation.
        self.mountinfo = self.root / "mountinfo"
        self.armed = (
            "36 25 0:31 / /mnt/nas rw,relatime shared:22 - autofs systemd-1 "
            "rw,fd=39,pgrp=1,timeout=0,direct\n"
        )
        self.mountinfo.write_text(self.armed, encoding="utf-8")
        self.samba = FakeSamba(self.root / "smb.conf")
        self.mounter = Mounter(
            unit_dir=self.root / "units",
            credentials=CredentialsStore(self.root / "creds"),
            probe=MountProbe(mountinfo=self.mountinfo),
            runner=self.samba,
        )
        self.store = ConfigStore(self.root / "config.json")
        doc, self.connection = ops.add_connection(
            empty_config(),
            host="rivendell.local",
            share="Media",
            mountpoint="/mnt/nas",
            fallback_host="192.168.0.52",
        )
        self.store.save(doc)
        self.events: list[tuple[str, dict]] = []
        self.monitor = StateMonitor(
            self.store,
            self.mounter,
            broadcast=lambda event, data: self.events.append((event, data)),
            runner=self.samba,
        )
        self.unit = "mnt-nas.mount"


class TestMonitor(MonitorTestCase):
    def test_the_first_poll_emits_the_starting_state(self) -> None:
        self.monitor.poll()
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0][0], "state.changed")
        self.assertEqual(self.events[0][1]["state"], machine.IDLE)
        self.assertIsNone(self.events[0][1]["previous"])

    def test_an_unchanged_state_emits_nothing(self) -> None:
        self.monitor.poll()
        self.events.clear()
        self.monitor.poll()
        self.assertEqual(self.events, [])

    def test_a_change_emits_once_and_carries_the_previous_state(self) -> None:
        self.monitor.poll()
        self.events.clear()
        self.samba.unit_state[self.unit] = {
            "ActiveState": "failed",
            "Result": "exit-code",
        }
        self.samba.journals[self.unit] = M0_AUTH_FAILURE
        self.monitor.poll()
        self.assertEqual(len(self.events), 1)
        data = self.events[0][1]
        self.assertEqual(data["state"], machine.AUTH_FAILED)
        self.assertEqual(data["previous"], machine.IDLE)
        self.assertTrue(data["is_problem"])

    def test_the_journal_is_read_only_when_the_unit_has_failed(self) -> None:
        # It is the expensive read, and its answer does not change while the
        # state does not.
        self.monitor.poll()
        self.assertNotIn("journalctl", {call[0] for call in self.samba.calls})
        self.samba.unit_state[self.unit] = {"ActiveState": "failed", "Result": "exit-code"}
        self.samba.journals[self.unit] = M0_AUTH_FAILURE
        self.monitor.poll()
        self.assertIn("journalctl", {call[0] for call in self.samba.calls})

    def test_polling_never_stats_a_mountpoint(self) -> None:
        from smbpal.mounts import probe as probe_module

        original = probe_module.os.stat
        probe_module.os.stat = lambda *a, **k: self.fail("stat was called")
        self.addCleanup(setattr, probe_module.os, "stat", original)
        self.monitor.poll()

    def test_a_removed_connection_is_announced(self) -> None:
        self.monitor.poll()
        self.events.clear()
        emptied, _ = ops.remove_connection(self.store.load(), self.connection["id"])
        self.store.save(emptied)
        self.monitor.poll()
        self.assertEqual(self.events[0][0], "connection.removed")

    def test_a_poll_that_throws_does_not_kill_the_loop(self) -> None:
        broken = StateMonitor(self.store, self.mounter, interval=0.01, runner=self.samba)
        broken.poll = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
        broken.start()
        self.addCleanup(broken.stop)
        threading.Event().wait(0.1)
        self.assertIsNotNone(broken._thread)


class TestFallbackHint(MonitorTestCase):
    def test_the_recorded_address_is_offered_only_when_the_name_fails(self) -> None:
        unresolved = machine.ConnectionState("x", machine.UNRESOLVED, "no")
        hint = fallback_hint(self.connection, unresolved)
        self.assertIn("192.168.0.52", hint)
        self.assertIn("use-fallback", hint)

    def test_it_is_never_offered_for_an_unrelated_failure(self) -> None:
        auth = machine.ConnectionState("x", machine.AUTH_FAILED, "no")
        self.assertIsNone(fallback_hint(self.connection, auth))

    def test_the_hint_says_why_it_is_not_automatic(self) -> None:
        # §3e proposed automatic failover. Building it exposed that a DHCP lease
        # can be reassigned, so failing over silently would send the stored
        # credentials to whatever now answers on that address.
        hint = fallback_hint(
            self.connection, machine.ConnectionState("x", machine.UNRESOLVED, "no")
        )
        self.assertIn("reassigned", hint)

    def test_a_connection_with_no_fallback_gets_no_hint(self) -> None:
        self.assertIsNone(
            fallback_hint(
                {**self.connection, "fallback_host": None},
                machine.ConnectionState("x", machine.UNRESOLVED, "no"),
            )
        )


class TestPushReachesAClient(MonitorTestCase):
    """The claim in the plan is "pushed to clients rather than polled".

    D4 has carried events since the first commit with nothing emitting one.
    This is the test that the whole path works end to end, over a real socket.
    """

    def setUp(self) -> None:
        super().setUp()
        from smbpal.daemon.handlers import Dispatcher
        from smbpal.ipc.protocol import encode_event
        from smbpal.ipc.server import UnixSocketTransport

        self.socket_path = Path(tempfile.mkdtemp(dir="/tmp", prefix="smbpal-")) / "s.sock"
        self.addCleanup(lambda: self.socket_path.parent.rmdir() if not self.socket_path.exists() else None)
        self.transport = UnixSocketTransport(self.socket_path, group=None)
        self.transport.bind()
        self.monitor.broadcast = lambda event, data: self.transport.broadcast(
            encode_event(event, data)
        )
        dispatcher = Dispatcher(self.store, mounter=self.mounter, monitor=self.monitor)
        self.thread = threading.Thread(
            target=self.transport.serve_forever, args=(dispatcher.handle,), daemon=True
        )
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self) -> None:
        self.transport.shutdown()
        self.thread.join(timeout=5)

    def test_a_state_change_arrives_at_a_connected_client(self) -> None:
        from smbpal.ipc.client import Client

        with Client(self.socket_path, timeout=5) as client:
            client.call("ping")  # ensure the connection is registered
            self.monitor.poll()  # first poll: idle

            self.samba.unit_state[self.unit] = {
                "ActiveState": "failed",
                "Result": "exit-code",
            }
            self.samba.journals[self.unit] = M0_AUTH_FAILURE
            self.monitor.poll()

            seen = []
            for event in client.events():
                seen.append(event["data"])
                if event["data"]["state"] == machine.AUTH_FAILED:
                    break
            self.assertEqual(seen[-1]["state"], machine.AUTH_FAILED)
            # The point of the whole exercise: the user is told the reason, not
            # the errno the automount returns.
            self.assertIn("password", seen[-1]["message"])

    def test_status_reports_the_monitors_view_not_a_second_opinion(self) -> None:
        from smbpal.ipc.client import Client

        self.samba.unit_state[self.unit] = {
            "ActiveState": "failed",
            "Result": "exit-code",
        }
        self.samba.journals[self.unit] = M0_AUTH_FAILURE
        self.monitor.poll()
        with Client(self.socket_path, timeout=5) as client:
            connection = client.call("status")["connections"][0]
        self.assertEqual(connection["state"], machine.AUTH_FAILED)
        self.assertTrue(connection["is_problem"])


if __name__ == "__main__":
    unittest.main()


class TestClearingALatchedUnit(MonitorTestCase):
    """`connect` and `set_credentials` after systemd has given up.

    Both are what a person reaches for once a mount has failed repeatedly, and
    both are worthless against a unit systemd refuses to start.
    """

    def setUp(self) -> None:
        super().setUp()
        # `set_credentials` commits, and a commit applies, which creates the
        # mountpoint. /mnt/nas is not ours to create on the machine running the
        # tests, so this connection lives under the temporary root.
        from smbpal.mounts import units

        mountpoint = str(self.root / "mnt" / "nas")
        doc, self.connection = ops.add_connection(
            empty_config(), host="rivendell.local", share="Media",
            mountpoint=mountpoint,
        )
        self.store.save(doc)
        self.unit, _ = units.unit_names(mountpoint)

    def dispatcher(self):
        from smbpal.daemon.handlers import Dispatcher

        return Dispatcher(self.store, mounter=self.mounter, monitor=self.monitor)

    def request(self, method: str, **params):
        from smbpal.ipc.peer import PeerCredentials
        from smbpal.ipc.protocol import Request

        return (
            Request(id="1", method=method, params=params),
            PeerCredentials(uid=0, gid=0),
        )

    def test_connect_clears_the_latch_before_starting(self) -> None:
        self.samba.latched.add(self.unit)
        dispatcher = self.dispatcher()

        result = dispatcher._connection_connect(
            *self.request("connection.connect", ref=self.connection["id"])
        )

        self.assertEqual(result["unit"], self.unit)
        self.assertIn(self.unit, self.samba.started_units)

    def test_new_credentials_clear_the_latch(self) -> None:
        # The commonest sequence there is: a rejected password, five retries,
        # then the right password. Without this the new password is never
        # tried and the same stale error keeps being reported.
        self.samba.latched.add(self.unit)
        dispatcher = self.dispatcher()

        dispatcher._connection_set_credentials(
            *self.request(
                "connection.set_credentials",
                ref=self.connection["id"],
                username="luke",
                password="throwaway-for-testing",
            )
        )

        self.assertNotIn(self.unit, self.samba.latched)
