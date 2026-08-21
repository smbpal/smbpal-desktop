"""Units, credentials, and the probe that must never block."""

from __future__ import annotations

import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path

from smbpal.config import empty_config
from smbpal.config import operations as ops
from smbpal.errors import InvalidParams
from smbpal.mounts import probe as probe_module
from smbpal.mounts import units
from smbpal.mounts.apply import MARKER, Mounter
from smbpal.mounts.credentials import CredentialsStore
from tests.fakes import FakeSamba


class TestEscaping(unittest.TestCase):
    """Captured from `systemd-escape -p --suffix=mount` on Pi OS, 20 August 2026.

    A fixture rather than four assertions derived from one reading of the spec.
    Getting one wrong means a unit name systemd never matches, and therefore a
    mount that silently never happens.
    """

    CONFIRMED = {
        "/mnt/m0": "mnt-m0.mount",
        "/mnt/my-share": "mnt-my" + chr(92) + "x2dshare.mount",
        "/.dotdir": chr(92) + "x2edotdir.mount",
        "/srv/a b": "srv-a" + chr(92) + "x20b.mount",
    }

    def test_against_real_systemd_output(self) -> None:
        for path, expected in self.CONFIRMED.items():
            with self.subTest(path=path):
                self.assertEqual(units.unit_names(path)[0], expected)

    def test_the_automount_name_matches_the_mount_name(self) -> None:
        self.assertEqual(
            units.unit_names("/mnt/m0"), ("mnt-m0.mount", "mnt-m0.automount")
        )

    def test_the_root_path(self) -> None:
        self.assertEqual(units.escape_path("/"), "-")

    def test_redundant_slashes_collapse(self) -> None:
        self.assertEqual(units.escape_path("//mnt///m0/"), "mnt-m0")

    def test_a_dot_elsewhere_is_left_alone(self) -> None:
        self.assertEqual(units.escape_path("/mnt/a.b"), "mnt-a.b")

    def test_non_ascii_escapes_per_byte(self) -> None:
        # Confirmed on the Pi alongside the four above.
        self.assertEqual(units.escape_path("/srv/\u00e9"), "srv-" + chr(92) + "xc3" + chr(92) + "xa9")


class TestUnitContent(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = {
            "id": "nas",
            "host": "rivendell.local",
            "share": "Media",
            "mountpoint": "/mnt/nas",
            "auto_connect": "on_this_network",
        }

    def test_the_mount_names_the_remote_and_the_mountpoint(self) -> None:
        text = units.mount_unit(self.connection, "/etc/smbpal/credentials/nas")
        self.assertIn("What=//rivendell.local/Media", text)
        self.assertIn("Where=/mnt/nas", text)
        self.assertIn("Type=cifs", text)

    def test_soft_is_explicit_rather_than_inherited(self) -> None:
        # M0 found it the default, and it is the option that decides what
        # happens when the remote disappears — not something to leave to a
        # distribution.
        self.assertIn("soft", units.mount_options(self.connection, None))

    def test_the_credential_is_a_path_never_a_value(self) -> None:
        options = units.mount_options(self.connection, "/etc/smbpal/credentials/nas")
        self.assertIn("credentials=/etc/smbpal/credentials/nas", options)
        self.assertNotIn("password", options)

    def test_no_credentials_means_guest(self) -> None:
        self.assertIn("guest", units.mount_options(self.connection, None))

    def test_an_owner_becomes_forced_uid_and_gid(self) -> None:
        options = units.mount_options(
            {**self.connection, "uid": 1000, "gid": 1000}, None
        )
        self.assertIn("uid=1000", options)
        self.assertIn("forceuid", options)
        self.assertIn("gid=1000", options)
        self.assertIn("forcegid", options)

    def test_timeout_idle_sec_is_deliberately_absent(self) -> None:
        # M0 §4 watched a background desktop process re-trigger the automount
        # 80 s after boot, so idle unmounting cannot be relied on at all.
        directives = [
            line
            for line in units.automount_unit(self.connection).splitlines()
            if line.strip().startswith("TimeoutIdleSec")
        ]
        self.assertEqual(directives, [], "the comment explains its absence; the "
                         "directive itself must not be there")

    def test_both_units_carry_the_marker_that_makes_them_ours(self) -> None:
        self.assertIn(MARKER, units.mount_unit(self.connection, None))
        self.assertIn(MARKER, units.automount_unit(self.connection))


class TestCredentialsFile(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.store = CredentialsStore(Path(self._dir.name) / "credentials")

    def test_it_is_owner_read_write_only(self) -> None:
        path = self.store.write("nas", username="pi", password="hunter2")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_the_directory_is_not_readable_by_anyone_else(self) -> None:
        self.store.write("nas", username="pi", password="hunter2")
        mode = stat.S_IMODE(self.store.directory.stat().st_mode)
        self.assertEqual(mode & 0o077, 0, f"{mode:04o}")

    def test_the_format_is_what_cifs_expects(self) -> None:
        path = self.store.write("nas", username="pi", password="hunter2", domain="WG")
        self.assertEqual(
            path.read_text(encoding="utf-8"), "username=pi\npassword=hunter2\ndomain=WG\n"
        )

    def test_a_newline_in_a_password_is_refused(self) -> None:
        # It would inject a second directive into a one-per-line file.
        with self.assertRaises(InvalidParams):
            self.store.write("nas", username="pi", password="a\npassword=b")

    def test_a_reference_cannot_escape_the_directory(self) -> None:
        for bad in ("../../etc/passwd", "a/b", ".", ""):
            with self.subTest(ref=bad):
                with self.assertRaises(InvalidParams):
                    self.store.path_for(bad)

    def test_only_the_username_can_be_read_back(self) -> None:
        self.store.write("nas", username="pi", password="hunter2")
        self.assertEqual(self.store.username_for("nas"), "pi")


class TestProbeNeverBlocks(unittest.TestCase):
    """The M0 §4 requirement, under test rather than commented."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.mountinfo = self.root / "mountinfo"
        # Verbatim shape from a Pi: an armed automount and the cifs mount that
        # appears under it, stacked on the same mountpoint.
        self.armed = (
            "36 25 0:31 / /mnt/nas rw,relatime shared:22 - autofs systemd-1 "
            "rw,fd=39,pgrp=1,timeout=0,minproto=5,maxproto=5,direct\n"
        )
        self.real = (
            "83 36 0:44 / /mnt/nas rw,relatime shared:45 - cifs "
            "//rivendell.local/Media rw,vers=3.1.1,uid=1000,forceuid\n"
        )
        self.mountinfo.write_text(self.armed + self.real, encoding="utf-8")

    def test_is_mounted_never_touches_the_filesystem(self) -> None:
        # The whole point: "is it mounted" is answered from the kernel's table,
        # so a NAS that is switched off cannot make it slow.
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        original = probe_module.os.stat
        probe_module.os.stat = lambda *a, **k: self.fail("stat was called")
        self.addCleanup(setattr, probe_module.os, "stat", original)
        self.assertTrue(probe.is_mounted("/mnt/nas"))
        self.assertEqual(probe.state("/mnt/nas"), probe_module.MOUNTED)

    def test_a_hanging_stat_does_not_hang_the_caller(self) -> None:
        probe = probe_module.MountProbe(mountinfo=self.mountinfo, timeout=0.2)
        release = threading.Event()
        original = probe_module.os.stat

        def slow(*_a, **_k):
            release.wait(10)
            return original(self.root)

        probe_module.os.stat = slow
        self.addCleanup(setattr, probe_module.os, "stat", original)
        self.addCleanup(release.set)

        started = time.monotonic()
        state = probe.state("/mnt/nas", deep=True)
        elapsed = time.monotonic() - started

        self.assertEqual(state, probe_module.CHECKING)
        self.assertLess(elapsed, 2.0, "the caller was blocked past its own timeout")

    def test_a_second_call_while_one_is_stuck_does_not_start_another_probe(self) -> None:
        probe = probe_module.MountProbe(mountinfo=self.mountinfo, timeout=0.1)
        release = threading.Event()
        calls = []
        original = probe_module.os.stat

        def slow(*_a, **_k):
            calls.append(1)
            release.wait(10)
            return original(self.root)

        probe_module.os.stat = slow
        self.addCleanup(setattr, probe_module.os, "stat", original)
        self.addCleanup(release.set)

        for _ in range(4):
            probe.reachable("/mnt/nas")
        # One blocked thread per mountpoint, not one per question asked.
        self.assertEqual(sum(calls), 1)

    def test_an_unreachable_mount_reports_unreachable_not_mounted(self) -> None:
        probe = probe_module.MountProbe(mountinfo=self.mountinfo, timeout=1.0)
        self.assertEqual(probe.state("/mnt/nas", deep=True), probe_module.UNREACHABLE)

    def test_no_procfs_is_unknown_rather_than_a_guess(self) -> None:
        probe = probe_module.MountProbe(mountinfo=self.root / "absent")
        self.assertEqual(probe.state("/mnt/nas"), probe_module.UNKNOWN)

    def test_a_mountpoint_with_a_space_is_matched(self) -> None:
        self.mountinfo.write_text(
            "26 1 0:24 / /mnt/with\\040space rw shared:1 - cifs //r/M rw\n",
            encoding="utf-8",
        )
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        self.assertTrue(probe.is_mounted("/mnt/with space"))

    def test_an_armed_automount_alone_is_not_mounted(self) -> None:
        # The bug this replaced: autofs occupies the mountpoint from the moment
        # the unit is enabled, so matching on the path alone reported every
        # armed automount as connected. Found on the Pi, where `status` said
        # connected while `ls` returned `No such device`.
        self.mountinfo.write_text(self.armed, encoding="utf-8")
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        self.assertFalse(probe.is_mounted("/mnt/nas"))
        self.assertTrue(probe.is_armed("/mnt/nas"))
        self.assertEqual(probe.state("/mnt/nas"), probe_module.NOT_MOUNTED)

    def test_the_cifs_mount_under_an_armed_automount_counts(self) -> None:
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        self.assertTrue(probe.is_mounted("/mnt/nas"))
        self.assertEqual(probe.state("/mnt/nas"), probe_module.MOUNTED)

    def test_the_filesystem_type_and_source_are_read_from_past_the_separator(
        self,
    ) -> None:
        entries = probe_module.mount_entries(self.mountinfo)
        self.assertEqual(
            [(e.fstype, e.source) for e in entries],
            [("autofs", "systemd-1"), ("cifs", "//rivendell.local/Media")],
        )

    def test_a_line_with_no_separator_is_skipped_rather_than_misread(self) -> None:
        self.mountinfo.write_text("garbage line with no dash field\n", encoding="utf-8")
        self.assertEqual(probe_module.mount_entries(self.mountinfo), [])


class TestMounter(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.unit_dir = self.root / "units"
        self.unit_dir.mkdir()
        self.mountinfo = self.root / "mountinfo"
        self.mountinfo.write_text("", encoding="utf-8")
        self.samba = FakeSamba(self.root / "smb.conf")
        self.mounter = Mounter(
            unit_dir=self.unit_dir,
            credentials=CredentialsStore(self.root / "credentials"),
            probe=probe_module.MountProbe(mountinfo=self.mountinfo),
            runner=self.samba,
        )

    def config(self, **kw) -> dict:
        mountpoint = kw.pop("mountpoint", str(self.root / "mnt" / "nas"))
        doc, _ = ops.add_connection(
            empty_config(),
            host=kw.pop("host", "rivendell.local"),
            share=kw.pop("share", "Media"),
            mountpoint=mountpoint,
            **kw,
        )
        return doc

    def test_apply_writes_both_units_and_reloads(self) -> None:
        config = self.config()
        self.mounter.apply(config)
        names = {p.name for p in self.unit_dir.iterdir()}
        self.assertEqual(len(names), 2)
        self.assertTrue(any(n.endswith(".automount") for n in names))
        self.assertEqual(self.samba.daemon_reloads, 1)

    def test_the_automount_is_enabled_not_the_mount(self) -> None:
        # Enabling the mount would make boot wait for the NAS; the automount is
        # what keeps the mount on first access (M0 §4).
        self.mounter.apply(self.config())
        self.assertTrue(all(u.endswith(".automount") for u in self.samba.enabled_units))

    def test_apply_clears_a_latched_failure_before_arming(self) -> None:
        # A Pi run left the mount unit in `start-limit-hit`, where systemd
        # refuses it before mount.cifs runs. `apply` is what someone runs after
        # fixing the cause, so arming a unit that cannot fire would make the
        # command a no-op that looks like a success.
        config = self.config()
        mountpoint = config["connections"][0]["mountpoint"]
        mount_name, automount_name = units.unit_names(mountpoint)
        self.samba.latched.add(mount_name)

        self.mounter.apply(config)

        self.assertNotIn(mount_name, self.samba.latched)
        reset = ("systemctl", "reset-failed", mount_name)
        enable = [c for c in self.samba.calls if c[:2] == ("systemctl", "enable")]
        self.assertIn(reset, self.samba.calls)
        self.assertLess(
            self.samba.calls.index(reset),
            self.samba.calls.index(enable[-1]),
            "the latch must be cleared before the automount is armed",
        )

    def test_auto_connect_never_disables_the_automount(self) -> None:
        self.mounter.apply(self.config(auto_connect="never"))
        self.assertEqual(self.samba.enabled_units, set())

    def test_the_mountpoint_is_created(self) -> None:
        config = self.config()
        self.mounter.apply(config)
        self.assertTrue(Path(config["connections"][0]["mountpoint"]).is_dir())

    def test_removing_a_connection_removes_its_units(self) -> None:
        config = self.config()
        self.mounter.apply(config)
        emptied, _ = ops.remove_connection(config, config["connections"][0]["id"])
        self.mounter.apply(emptied)
        self.assertEqual(list(self.unit_dir.iterdir()), [])

    def test_a_unit_we_did_not_write_is_never_removed(self) -> None:
        # Identified by the marker in the file, not by the name — a hand-written
        # mnt-media.mount that happens to collide is not ours to delete.
        theirs = self.unit_dir / "mnt-theirs.mount"
        theirs.write_text("[Mount]\nWhat=//other/thing\n", encoding="utf-8")
        self.mounter.apply(empty_config())
        self.assertTrue(theirs.exists())

    def test_teardown_removes_only_ours(self) -> None:
        theirs = self.unit_dir / "mnt-theirs.mount"
        theirs.write_text("[Mount]\n", encoding="utf-8")
        self.mounter.apply(self.config())
        self.mounter.teardown()
        self.assertEqual([p.name for p in self.unit_dir.iterdir()], ["mnt-theirs.mount"])

    def test_plan_never_stats_a_mountpoint(self) -> None:
        # `status` calls this. A switched-off NAS must not make it slow.
        config = self.config()
        self.mounter.apply(config)
        original = probe_module.os.stat
        probe_module.os.stat = lambda *a, **k: self.fail("stat was called")
        self.addCleanup(setattr, probe_module.os, "stat", original)
        planned = self.mounter.plan(config)
        self.assertEqual(planned[0].state, probe_module.NOT_MOUNTED)

    def test_credentials_reach_the_unit_as_a_path(self) -> None:
        config = self.config(credential_ref="nas")
        self.mounter.credentials.write("nas", username="pi", password="hunter2")
        self.mounter.apply(config)
        text = next(
            p for p in self.unit_dir.iterdir() if p.suffix == ".mount"
        ).read_text(encoding="utf-8")
        self.assertIn("credentials=", text)
        self.assertNotIn("hunter2", text)


if __name__ == "__main__":
    unittest.main()
