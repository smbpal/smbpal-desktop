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
from smbpal.mounts import probe as probe_module
from smbpal.mounts.probe import MountProbe
from smbpal.state import machine, translate
from smbpal.state.machine import derive
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
Failed to mount mnt-smbpal\\x2dtest.mount - SMBPal mount of //nas.local/Media.
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
            "mount error: could not resolve address for nas.local: Unknown error"
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

    def test_a_refused_connection_names_both_causes_and_how_to_tell(self) -> None:
        """D14: a message may not name a symptom when several causes share it.

        `ECONNREFUSED` is the case that proves the rule, because it cannot be
        narrowed from the client: a refusal carries no reason, so a stopped
        Samba and a blocked port are the same packet. The daemon therefore
        cannot distinguish them, and the rule's second clause applies -- say
        what would. Anything less sends half of all readers to the opposite
        of the fix.
        """
        cause = translate.translate_journal("mount error(111): Connection refused")
        self.assertEqual(cause.state, "unreachable")
        self.assertIn("stopped", cause.message)      # one cause
        self.assertIn("firewall", cause.message)     # the other
        self.assertIn("smbpal status", cause.message)  # what tells them apart
        self.assertTrue(cause.retryable)

    def test_the_table_is_linuxs_numbering_and_not_the_running_platforms(self) -> None:
        """The guard on a fix that looks right and is not.

        `translate_journal` parses a number `mount.cifs` printed into a Linux
        journal. Keying the table on `errno.ECONNREFUSED` instead would read as
        a portability improvement and would quietly break: above the POSIX-fixed
        range of 1 to 34 the numbers differ per platform, and the log can be
        read somewhere other than where it was written.

        So this asserts the literal Linux values, on whatever platform the
        suite runs. On macOS `errno.ECONNREFUSED` is 61, and a symbolic rewrite
        would fail here rather than in front of somebody whose mount broke.
        """
        for number, fragment in (
            (111, "refused the connection"),   # Linux ECONNREFUSED; macOS 61
            (113, "no route"),                 # Linux EHOSTUNREACH; macOS 65
            (110, "did not answer in time"),   # Linux ETIMEDOUT;    macOS 60
            (112, "switched off"),             # Linux EHOSTDOWN;    macOS 64
        ):
            with self.subTest(errno=number):
                cause = translate.translate_journal(f"mount error({number}): x")
                self.assertIn(fragment, cause.message)
                self.assertEqual(cause.state, "unreachable")

    def test_the_posix_fixed_range_is_the_part_that_is_portable(self) -> None:
        # 1 to 34 are fixed by POSIX and identical on Linux and macOS, which is
        # why these entries would survive a symbolic rewrite and the ones above
        # would not. Recorded so the distinction is visible rather than lucky.
        import errno as _errno

        self.assertEqual(_errno.EACCES, 13)
        self.assertEqual(_errno.ENOENT, 2)
        cause = translate.translate_journal("mount error(13): Permission denied")
        self.assertEqual(cause.state, "auth_failed")

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

    def test_someone_elses_filesystem_is_not_reported_as_connected(self) -> None:
        # `mounted` is True here and it is True about a USB stick. Attributing
        # it to this share is the same error as counting an armed automount as
        # connected: a claim the mount table does not support.
        state = machine.derive(
            self.CONNECTION,
            mounted=True,
            unit=None,
            occupied_by="/dev/sda1 (vfat)",
        )
        self.assertEqual(state.state, machine.FAILED)
        self.assertTrue(state.is_problem)
        self.assertIn("/dev/sda1", state.message)
        self.assertIn("/mnt/nas", state.message)

    def test_an_occupied_mountpoint_beats_a_read_only_reading(self) -> None:
        # read_only is derived from the same mount table entry, so it would be
        # describing the intruder too.
        state = machine.derive(
            self.CONNECTION,
            mounted=True,
            unit=None,
            read_only=True,
            occupied_by="/dev/sda1 (vfat)",
        )
        self.assertEqual(state.state, machine.FAILED)
        self.assertFalse(state.read_only)

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
            probe=MountProbe(
                mountinfo=self.mountinfo, cifs_debug_data=self.root / "DebugData"
            ),
            runner=self.samba,
        )
        self.debug_data = self.root / "DebugData"
        self.store = ConfigStore(self.root / "config.json")
        doc, self.connection = ops.add_connection(
            empty_config(),
            host="nas.local",
            share="Media",
            mountpoint="/mnt/nas",
            fallback_host="192.0.2.52",
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


class TestPriming(MonitorTestCase):
    """An armed automount nobody has touched is invisible in the file manager.

    Found on the Pi, 19 September 2026: a connection set up and healthy did
    not appear in the sidebar until its path was opened by hand, because GIO
    hides `autofs` (plan §3h). The monitor now mounts each connection once.
    """

    def setUp(self) -> None:
        super().setUp()
        self.up = True
        self.asked: list[str] = []

        def reachable(host: str) -> bool:
            self.asked.append(host)
            return self.up

        self.monitor = StateMonitor(
            self.store,
            self.mounter,
            runner=self.samba,
            prime=True,
            reachable=reachable,
        )

    def starts(self) -> list[tuple[str, ...]]:
        return [c for c in self.samba.calls if c[:2] == ("systemctl", "start")]

    def mount_it(self) -> None:
        self.mountinfo.write_text(
            self.armed
            + "37 25 0:32 / /mnt/nas rw,relatime shared:23 - cifs "
            "//nas.local/Media rw,vers=3.1.1\n",
            encoding="utf-8",
        )

    def eject_it(self) -> None:
        self.mountinfo.write_text(self.armed, encoding="utf-8")

    def set_connection(self, **changes: str) -> None:
        doc = self.store.load()
        doc["connections"][0].update(changes)
        self.store.save(doc)

    def test_an_armed_idle_connection_is_mounted_without_blocking(self) -> None:
        self.monitor.poll()
        self.assertEqual(
            self.starts(), [("systemctl", "start", "--no-block", self.unit)]
        )

    def test_it_is_primed_once_not_on_every_poll(self) -> None:
        self.monitor.poll()
        # The start is queued; the mount lands a moment later, as `--no-block`
        # means it does on a real machine.
        self.mount_it()
        self.monitor.poll()
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 1)

    def test_a_start_that_never_mounts_is_tried_again_and_then_given_up_on(
        self,
    ) -> None:
        """Nothing in the journal, and the mount never appears.

        Queueing a start every five seconds for ever is not a diagnosis, so the
        monitor stops after three and says exactly that.
        """
        with self.assertLogs("smbpal.state.monitor", level="INFO") as logs:
            for _ in range(6):
                self.monitor.poll()
        self.assertEqual(len(self.starts()), 3)
        self.assertTrue(
            any("never mounted" in line for line in logs.output), logs.output
        )

    def test_a_refused_mount_is_not_tried_again(self) -> None:
        """Fedora, 27 September 2026: `mount error(13): Permission denied`.

        The start is accepted because `--no-block` accepts everything; the mount
        is then refused. Retrying a rejected credential is how accounts get
        locked out (§4), so the monitor stops — but it says why, where it used
        to record the queued start as a prime and blame a disconnect.
        """
        self.samba.journals[self.unit] = M0_AUTH_FAILURE
        with self.assertLogs("smbpal.state.monitor", level="INFO") as logs:
            self.monitor.poll()
            self.monitor.poll()
            self.monitor.poll()
        self.assertEqual(len(self.starts()), 1)
        refused = [line for line in logs.output if "refused" in line]
        self.assertEqual(len(refused), 1, logs.output)
        self.assertIn("the username or password was refused", refused[0])
        self.assertNotIn(
            "somebody disconnected", "".join(logs.output)
        )

    def test_on_this_network_waits_for_the_server_and_then_primes(self) -> None:
        """A Pi that boots before its network, or a laptop that comes home."""
        self.up = False
        self.monitor.poll()
        self.monitor.poll()
        self.assertEqual(self.starts(), [])
        self.assertEqual(self.asked, ["nas.local", "nas.local"])
        self.up = True
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 1)

    def test_a_connection_removed_and_added_again_is_primed_again(self) -> None:
        """Fedora, 27 September 2026.

        Ids come from host and share and the default mountpoint from those, so a
        remove and a re-add produce the same id and the same target. Inside one
        poll interval the monitor never sees the connection leave, so the latch
        still matched and the share sat idle in the file manager for the life of
        the daemon. The daemon says `forget` when it adds or removes one.
        """
        self.monitor.poll()
        self.mount_it()
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 1)
        self.eject_it()
        self.monitor.forget(self.connection["id"])
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 2)

    def test_forgetting_one_connection_does_not_forget_another(self) -> None:
        self.monitor.poll()
        self.mount_it()
        self.monitor.forget("some-other-connection")
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 1)

    def test_a_declined_prime_says_why_once(self) -> None:
        self.up = False
        with self.assertLogs("smbpal.state.monitor", level="INFO") as logs:
            self.monitor.poll()
            self.monitor.poll()
            self.monitor.poll()
        said = [line for line in logs.output if "not priming" in line]
        self.assertEqual(len(said), 1, said)
        self.assertIn("nothing answers on port 445 at nas.local", said[0])

    def test_the_reason_is_said_again_when_it_changes(self) -> None:
        self.up = False
        with self.assertLogs("smbpal.state.monitor", level="INFO") as logs:
            self.monitor.poll()
            self.set_connection(auto_connect="never")
            self.monitor.poll()
        said = [line for line in logs.output if "not priming" in line]
        self.assertEqual(len(said), 2, said)
        # `disabled` rather than "auto_connect is never": `derive` turns
        # `never` into that state, so the earlier gate answers first and the
        # `auto == never` branch of `_maybe_prime` is defensive only.
        self.assertIn("its state is disabled", said[1])

    def test_a_connection_that_was_already_mounted_says_so(self) -> None:
        """The branch that used to be silent, and cost two runs an evening."""
        self.mount_it()
        with self.assertLogs("smbpal.state.monitor", level="INFO") as logs:
            self.monitor.poll()
        self.assertEqual(self.starts(), [])
        self.assertTrue(
            any("already mounted" in line for line in logs.output), logs.output
        )

    def test_always_does_not_wait_for_the_server(self) -> None:
        self.set_connection(auto_connect="always")
        self.up = False
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 1)
        self.assertEqual(self.asked, [])

    def test_never_is_never_primed(self) -> None:
        self.set_connection(auto_connect="never")
        self.monitor.poll()
        self.assertEqual(self.starts(), [])

    def test_an_eject_is_respected(self) -> None:
        """Mounted, then unmounted by somebody: that was a choice."""
        self.monitor.poll()
        self.mount_it()
        self.monitor.poll()
        self.eject_it()
        self.monitor.poll()
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 1)

    def test_a_connection_already_mounted_is_never_primed_after_an_eject(self) -> None:
        self.mount_it()
        self.monitor.poll()
        self.eject_it()
        self.monitor.poll()
        self.assertEqual(self.starts(), [])

    def test_pointing_it_somewhere_else_primes_it_again(self) -> None:
        self.monitor.poll()
        self.set_connection(share="Photos")
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 2)

    def test_a_failed_connection_is_left_to_its_own_retry(self) -> None:
        self.samba.unit_state[self.unit] = {
            "ActiveState": "failed",
            "Result": "exit-code",
        }
        self.samba.journals[self.unit] = M0_AUTH_FAILURE
        self.monitor.poll()
        self.assertEqual(self.starts(), [])

    def test_a_refused_start_is_tried_again_next_poll(self) -> None:
        self.samba.latched.add(self.unit)
        self.monitor.poll()
        self.samba.latched.discard(self.unit)
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 2)

    def test_a_monitor_not_asked_to_prime_never_starts_anything(self) -> None:
        quiet = StateMonitor(self.store, self.mounter, runner=self.samba)
        quiet.poll()
        self.assertEqual(self.starts(), [])


class TestIsTheServerThere(unittest.TestCase):
    """The real TCP check, against a listener this test owns."""

    def test_a_listening_port_is_reachable_and_a_closed_one_is_not(self) -> None:
        import socket

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        self.assertTrue(probe_module.server_reachable("127.0.0.1", port=port))
        listener.close()
        self.assertFalse(probe_module.server_reachable("127.0.0.1", port=port))

    def test_a_name_that_does_not_resolve_is_not_reachable(self) -> None:
        self.assertFalse(probe_module.server_reachable("no-such-host.invalid"))


class TestAnOccupiedMountpoint(MonitorTestCase):
    """The whole path, from the mount table to what a person is told."""

    def test_status_names_what_is_there_instead_of_saying_connected(self) -> None:
        # udisks2 mounting a stick labelled Media on the same path. Without the
        # source check this polls as `connected`, because something is indeed
        # mounted at /mnt/nas.
        self.mountinfo.write_text(
            self.armed
            + "91 25 8:17 / /mnt/nas rw,relatime shared:60 - vfat /dev/sda1 "
            "rw,uid=1000\n",
            encoding="utf-8",
        )
        self.monitor.poll()
        payload = self.events[-1][1]
        self.assertEqual(payload["state"], machine.FAILED)
        self.assertTrue(payload["is_problem"])
        self.assertIn("/dev/sda1", payload["message"])

    def test_our_own_share_still_polls_as_connected(self) -> None:
        self.mountinfo.write_text(
            self.armed
            + "83 36 0:44 / /mnt/nas rw,relatime shared:45 - cifs "
            "//nas.local/Media rw,vers=3.1.1\n",
            encoding="utf-8",
        )
        self.monitor.poll()
        self.assertEqual(self.events[-1][1]["state"], machine.CONNECTED)


class TestFallbackHint(MonitorTestCase):
    def test_the_recorded_address_is_offered_only_when_the_name_fails(self) -> None:
        unresolved = machine.ConnectionState("x", machine.UNRESOLVED, "no")
        hint = fallback_hint(self.connection, unresolved)
        self.assertIn("192.0.2.52", hint)
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
            empty_config(), host="nas.local", share="Media",
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

    def test_disconnect_says_that_the_automount_will_undo_it(self) -> None:
        """D14: a control whose effect cannot be observed looks broken.

        The unmount is real and the `.automount` stays armed, so anything
        touching the path puts it back. On COSMIC, whose file manager watches
        the mountpoint, that is immediate -- press Disconnect, see nothing
        change. The CLI has always said so; the window said nothing, because
        nothing told it to. `share.make_writable` already carries a `note`
        for exactly this, so disconnect carries one too.
        """
        dispatcher = self.dispatcher()

        result = dispatcher._connection_disconnect(
            *self.request("connection.disconnect", ref=self.connection["id"])
        )

        self.assertEqual(result["unit"], self.unit)
        self.assertIn("note", result)
        self.assertIn("mount again", result["note"])

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


class TestReadingWhetherTheServerIsAnswering(unittest.TestCase):
    """Parsing `/proc/fs/cifs/DebugData`.

    It is a kernel debug file, not an API, so the parser walks for the two
    lines it needs and ignores everything else. A layout change must cost an
    empty answer and never a wrong one.
    """

    def parse(self, text: str) -> dict[str, bool] | None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "DebugData"
        path.write_text(text, encoding="utf-8")
        return probe_module.cifs_server_states(path)

    def test_a_good_server_and_a_gone_one(self) -> None:
        states = self.parse(
            "Servers:\n"
            "1) ConnectionId: 0x1 Hostname: nas.local\n"
            "Number of credits: 8190 Dialect 0x311 TCP status: 1 Instance: 1\n"
            "\n"
            "2) ConnectionId: 0x2 Hostname: moria.local\n"
            "TCP status: 3 Instance: 2\n"
        )
        self.assertEqual(states, {"nas.local": True, "moria.local": False})

    def test_the_status_may_share_a_line_with_anything_else(self) -> None:
        """Which it does on current kernels, and did not on older ones."""
        states = self.parse(
            "1) ConnectionId: 0x1 Hostname: nas.local\n"
            "Number of credits: 8190 Dialect 0x311 signed TCP status: 1 Instance: 1\n"
        )
        self.assertEqual(states, {"nas.local": True})

    def test_a_file_that_is_not_there_is_no_opinion(self) -> None:
        """Root-only, and absent until the cifs module has ever loaded."""
        self.assertIsNone(probe_module.cifs_server_states("/nonexistent/DebugData"))

    def test_a_layout_we_do_not_recognise_is_no_opinion(self) -> None:
        self.assertIsNone(self.parse("something else entirely\n"))

    def test_an_unknown_status_number_counts_as_good(self) -> None:
        """A kernel that adds a state must not make working shares look broken."""
        states = self.parse("Hostname: nas.local\nTCP status: 1 Instance: 1\n")
        self.assertEqual(states, {"nas.local": True})

    def test_a_host_the_kernel_does_not_list_is_not_a_verdict(self) -> None:
        states = {"nas.local": True}
        self.assertIsNone(probe_module.server_is_answering("other.local", states))

    def test_matching_ignores_case(self) -> None:
        states = self.parse("Hostname: NAS.local\nTCP status: 3\n")
        self.assertIs(probe_module.server_is_answering("nas.LOCAL", states), False)

    def test_no_states_at_all_is_no_opinion(self) -> None:
        self.assertIsNone(probe_module.server_is_answering("nas.local", None))


class TestAMountedShareWhoseServerHasGone(unittest.TestCase):
    """The Pi, 27 August 2026: mounted, unreachable, reported as connected."""

    def state(self, **kw):
        return derive(
            {"id": "nas", "host": "nas.local", "mountpoint": "/mnt/nas"},
            mounted=True,
            unit={"ActiveState": "active", "Result": "success"},
            **kw,
        )

    def test_a_server_that_stopped_answering_is_unreachable_not_connected(self) -> None:
        state = self.state(server_answering=False)
        self.assertEqual(state.state, machine.UNREACHABLE)
        self.assertTrue(state.is_problem)
        self.assertIn("still mounted", state.message)
        self.assertIn("until it comes back", state.message)

    def test_not_knowing_is_not_a_fault(self) -> None:
        """None means the kernel could not be asked, which is not evidence."""
        self.assertEqual(self.state(server_answering=None).state, machine.CONNECTED)

    def test_a_server_that_is_answering_is_just_connected(self) -> None:
        self.assertEqual(self.state(server_answering=True).state, machine.CONNECTED)

    def test_a_read_only_mount_that_goes_away_still_says_so(self) -> None:
        state = self.state(server_answering=False, read_only=True)
        self.assertEqual(state.state, machine.UNREACHABLE)
        self.assertTrue(state.read_only)


class TestTheMonitorAsksTheKernel(MonitorTestCase):
    """**A wiring test, and it is here because wiring is what keeps breaking.**

    `occupied_by`, `previous` and `in_use` each passed their own unit tests
    while the daemon never passed them. This is the fourth parameter of its
    kind, so it gets pinned at the point where it is actually used rather than
    only where it is implemented.
    """

    def mount_it(self) -> None:
        self.mountinfo.write_text(
            self.armed
            + "37 25 0:32 / /mnt/nas rw,relatime shared:23 - cifs "
            "//nas.local/Media rw,vers=3.1.1\n",
            encoding="utf-8",
        )

    def test_a_mounted_share_with_its_server_gone_is_reported_unreachable(self) -> None:
        self.mount_it()
        self.debug_data.write_text(
            "Hostname: nas.local\nTCP status: 3 Instance: 1\n", encoding="utf-8"
        )
        state = self.monitor.poll()[0]
        self.assertEqual(state.state, machine.UNREACHABLE)

    def test_the_same_share_with_its_server_answering_is_connected(self) -> None:
        self.mount_it()
        self.debug_data.write_text(
            "Hostname: nas.local\nTCP status: 1 Instance: 1\n", encoding="utf-8"
        )
        self.assertEqual(self.monitor.poll()[0].state, machine.CONNECTED)

    def test_without_the_kernels_file_nothing_changes(self) -> None:
        """A machine where the file cannot be read must behave as before."""
        self.mount_it()
        self.assertFalse(self.debug_data.exists())
        self.assertEqual(self.monitor.poll()[0].state, machine.CONNECTED)

    def test_an_unmounted_connection_does_not_ask_at_all(self) -> None:
        """Nothing is mounted, so a server's state cannot say anything useful."""
        self.debug_data.write_text(
            "Hostname: nas.local\nTCP status: 3\n", encoding="utf-8"
        )
        self.assertEqual(self.monitor.poll()[0].state, machine.IDLE)

    def test_the_change_is_pushed_like_any_other(self) -> None:
        """The tray's whole justification: nobody asked, and it still arrives."""
        self.mount_it()
        self.debug_data.write_text(
            "Hostname: nas.local\nTCP status: 1\n", encoding="utf-8"
        )
        self.monitor.poll()
        self.events.clear()

        self.debug_data.write_text(
            "Hostname: nas.local\nTCP status: 3\n", encoding="utf-8"
        )
        self.monitor.poll()
        pushed = [data for event, data in self.events if event == "state.changed"]
        self.assertEqual(pushed[0]["state"], machine.UNREACHABLE)
        self.assertTrue(pushed[0]["is_problem"])


class TestAddingAConnectionClearsWhatPrimingRemembers(MonitorTestCase):
    """The handler side of the Fedora finding of 27 September 2026.

    Removing a connection and adding it back gives the same id and the same
    target, so the latch in `_maybe_prime` matched and the share was never
    primed again. The monitor cannot notice it left, either: inside one poll
    interval it never disappears from the config. So the handlers say so.
    """

    def setUp(self) -> None:
        super().setUp()
        from smbpal.mounts import units

        # Under the temporary root: a commit applies, and applying creates the
        # mountpoint, which /mnt/nas is not ours to do on a test machine.
        self.mountpoint = str(self.root / "mnt" / "nas")
        doc, self.connection = ops.add_connection(
            empty_config(),
            host="nas.local",
            share="Media",
            mountpoint=self.mountpoint,
        )
        self.store.save(doc)
        self.unit, _ = units.unit_names(self.mountpoint)
        self.mountinfo.write_text(
            "36 25 0:31 / %s rw,relatime shared:22 - autofs systemd-1 "
            "rw,fd=39,pgrp=1,timeout=0,direct\n" % self.mountpoint,
            encoding="utf-8",
        )
        self.monitor = StateMonitor(
            self.store,
            self.mounter,
            runner=self.samba,
            prime=True,
            reachable=lambda host: True,
        )

    def starts(self) -> list[tuple[str, ...]]:
        return [
            c
            for c in self.samba.calls
            if c[:2] == ("systemctl", "start") and self.unit in c
        ]

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

    def armed_line(self) -> str:
        return (
            "36 25 0:31 / %s rw,relatime shared:22 - autofs systemd-1 "
            "rw,fd=39,pgrp=1,timeout=0,direct\n" % self.mountpoint
        )

    def mount_it(self) -> None:
        self.mountinfo.write_text(
            self.armed_line()
            + "37 25 0:32 / %s rw,relatime shared:23 - cifs //nas.local/Media "
            "rw,vers=3.1.1\n" % self.mountpoint,
            encoding="utf-8",
        )

    def eject_it(self) -> None:
        self.mountinfo.write_text(self.armed_line(), encoding="utf-8")

    def test_storing_credentials_makes_it_try_the_mount_again(self) -> None:
        """The race `connection add --user` creates, Fedora 27 September 2026.

        The connection exists before the password does: the CLI prompts after
        the add, and the monitor polls every five seconds. So it primes a
        connection with no credentials, the server refuses the mount, and
        priming stops — correctly, because a refused credential must not be
        retried. Storing credentials is what makes that refusal out of date.
        """
        self.samba.journals[self.unit] = M0_AUTH_FAILURE
        self.monitor.poll()
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 1)

        self.dispatcher()._connection_set_credentials(
            *self.request(
                "connection.set_credentials",
                ref=self.connection["id"],
                username="pi",
                password="not the one that was refused",
            )
        )
        self.samba.journals[self.unit] = ""
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 2)

    def test_it_primes_again_after_a_remove_and_an_add(self) -> None:
        self.monitor.poll()
        # Mounted, so the latch is set for real — without this the connection
        # is only mid-attempt and would be retried anyway, which would make
        # this test pass with or without `forget`.
        self.mount_it()
        self.monitor.poll()
        self.eject_it()
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 1)

        dispatcher = self.dispatcher()
        dispatcher._connection_remove(
            *self.request("connection.remove", ref=self.connection["id"])
        )
        dispatcher._connection_add(
            *self.request(
                "connection.add",
                host="nas.local",
                share="Media",
                mountpoint=self.mountpoint,
            )
        )
        # No poll in between: the config never showed the connection missing,
        # which is exactly the case `gone` cannot catch.
        self.monitor.poll()
        self.assertEqual(len(self.starts()), 2)
