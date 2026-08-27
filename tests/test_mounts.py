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
from smbpal.mounts import inventory
from smbpal.mounts import probe as probe_module
from smbpal.mounts import units
from smbpal.mounts.apply import MARKER, OCCUPIED, Mounter, foreign_mount
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

    def test_the_mount_unit_cannot_be_enabled(self) -> None:
        # An `[Install]` section here is an invitation to `systemctl enable` the
        # mount, which would mount the share during boot — the single thing the
        # automount exists to prevent. Only the automount is installable.
        text = units.mount_unit(self.connection, None)
        self.assertNotIn("[Install]", text)
        self.assertNotIn("WantedBy", text)

    def test_the_automount_is_the_installable_one(self) -> None:
        text = units.automount_unit(self.connection)
        self.assertIn("[Install]", text)
        self.assertIn("WantedBy=multi-user.target", text)

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

    def test_occupant_is_the_filesystem_not_the_trigger(self) -> None:
        # Both lines sit on /mnt/nas. The autofs one is the trigger and says
        # nothing about what is actually there.
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        entry = probe.occupant("/mnt/nas")
        assert entry is not None
        self.assertEqual(entry.fstype, "cifs")
        self.assertEqual(entry.source, "//rivendell.local/Media")

    def test_an_armed_automount_alone_has_no_occupant(self) -> None:
        # Nothing is mounted yet, so there is nothing to be hidden by mounting.
        self.mountinfo.write_text(self.armed, encoding="utf-8")
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        self.assertIsNone(probe.occupant("/mnt/nas"))

    def test_a_foreign_filesystem_is_reported_as_the_occupant(self) -> None:
        # What udisks2 leaves behind when a stick labelled Media is plugged in.
        self.mountinfo.write_text(
            "91 25 8:17 / /mnt/nas rw,relatime shared:60 - vfat "
            "/dev/sda1 rw,uid=1000,gid=1000\n",
            encoding="utf-8",
        )
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        entry = probe.occupant("/mnt/nas")
        assert entry is not None
        self.assertEqual((entry.fstype, entry.source), ("vfat", "/dev/sda1"))

    def test_a_writable_mount_is_not_read_only(self) -> None:
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        self.assertIs(probe.is_read_only("/mnt/nas"), False)

    def test_a_read_only_mount_is_reported_as_one(self) -> None:
        # The `ro` that matters is field 5, the per-mount options — the same
        # position `rw` sits in above. The superblock options after the source
        # carry their own copy and are not what the kernel enforces on.
        self.mountinfo.write_text(
            self.armed
            + "83 36 0:44 / /mnt/nas ro,relatime shared:45 - cifs "
            "//rivendell.local/Media ro,vers=3.1.1,uid=1000,forceuid\n",
            encoding="utf-8",
        )
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        self.assertIs(probe.is_read_only("/mnt/nas"), True)

    def test_the_autofs_trigger_is_not_what_gets_asked(self) -> None:
        # The trigger is always `rw` whatever the mount under it says, so
        # reading the first line matching the path would answer the wrong
        # question — the same confusion that made an armed automount look
        # connected.
        self.mountinfo.write_text(
            self.armed
            + "83 36 0:44 / /mnt/nas ro,relatime shared:45 - cifs //r/M ro\n",
            encoding="utf-8",
        )
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        self.assertIs(probe.is_read_only("/mnt/nas"), True)

    def test_an_armed_but_unmounted_path_has_no_answer(self) -> None:
        # Not False. Nothing is mounted, so "is it read-only" has no answer,
        # and False would read as "writable".
        self.mountinfo.write_text(self.armed, encoding="utf-8")
        probe = probe_module.MountProbe(mountinfo=self.mountinfo)
        self.assertIsNone(probe.is_read_only("/mnt/nas"))

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

    def occupy(self, mountpoint: str, line: str | None = None) -> None:
        """Put something else on the mountpoint, the way udisks2 would."""
        self.mountinfo.write_text(
            line
            or f"91 25 8:17 / {mountpoint} rw,relatime shared:60 - vfat "
            f"/dev/sda1 rw,uid=1000,gid=1000\n",
            encoding="utf-8",
        )

    def test_no_units_are_written_over_someone_elses_mount(self) -> None:
        config = self.config()
        self.occupy(config["connections"][0]["mountpoint"])
        self.mounter.apply(config)
        self.assertEqual(list(self.unit_dir.iterdir()), [])

    def test_nothing_is_armed_over_someone_elses_mount(self) -> None:
        # The automount is the dangerous half: arming it mounts on top at the
        # next access, whenever that is, with nobody watching.
        config = self.config()
        self.occupy(config["connections"][0]["mountpoint"])
        self.mounter.apply(config)
        self.assertEqual(self.samba.enabled_units, set())

    def test_an_occupied_mountpoint_does_not_reap_the_units(self) -> None:
        # A stick plugged in this morning must not delete the connection. The
        # mountpoint is unavailable; the connection is still configured.
        config = self.config()
        self.mounter.apply(config)
        before = {p.name for p in self.unit_dir.iterdir()}
        self.occupy(config["connections"][0]["mountpoint"])
        self.mounter.apply(config)
        self.assertEqual({p.name for p in self.unit_dir.iterdir()}, before)

    def test_an_occupied_mountpoint_is_reported_not_called_mounted(self) -> None:
        # `is_mounted` is True here — about the stick. Saying `mounted` would
        # attribute somebody else's filesystem to this share.
        config = self.config()
        self.occupy(config["connections"][0]["mountpoint"])
        self.assertEqual(self.mounter.plan(config)[0].state, OCCUPIED)

    def test_our_own_mount_is_not_mistaken_for_an_intruder(self) -> None:
        config = self.config()
        mountpoint = config["connections"][0]["mountpoint"]
        self.occupy(
            mountpoint,
            f"83 36 0:44 / {mountpoint} rw,relatime shared:45 - cifs "
            "//rivendell.local/Media rw,vers=3.1.1\n",
        )
        self.mounter.apply(config)
        self.assertEqual(len(list(self.unit_dir.iterdir())), 2)
        self.assertEqual(self.mounter.plan(config)[0].state, probe_module.MOUNTED)

    def test_a_unit_is_kept_while_its_mount_is_still_up(self) -> None:
        # The marker in the unit file is the only evidence a mount was ours —
        # a cifs line in mountinfo says nothing about who made it. Unlinking
        # while the unmount has not taken would demote an orphan we may clean
        # up into an unmanaged mount we may not touch.
        config = self.config()
        mountpoint = config["connections"][0]["mountpoint"]
        self.mounter.apply(config)
        self.occupy(
            mountpoint,
            f"83 36 0:44 / {mountpoint} rw,relatime shared:45 - cifs "
            "//rivendell.local/Media rw,vers=3.1.1\n",
        )
        self.mounter.apply(empty_config())
        kept = [p.name for p in self.unit_dir.iterdir()]
        self.assertIn("mount", "".join(kept))
        self.assertTrue(any(n.endswith(".mount") for n in kept))

    def test_a_unit_whose_mount_went_away_is_removed(self) -> None:
        config = self.config()
        self.mounter.apply(config)
        self.mounter.apply(empty_config())
        self.assertEqual(list(self.unit_dir.iterdir()), [])

    def test_a_commit_removes_what_that_change_dropped(self) -> None:
        config = self.config()
        self.mounter.apply(config)
        self.mounter.apply(empty_config(), previous=config)
        self.assertEqual(list(self.unit_dir.iterdir()), [])

    def test_a_commit_leaves_alone_what_its_config_never_mentioned(self) -> None:
        # The 27 August Pi case. The daemon opened --config
        # /tmp/smbpal-test.json, which does not exist, while the real
        # connection sat in /etc/smbpal/config.json. One `connection add`
        # against that empty document must not reap a working setup.
        config = self.config()
        self.mounter.apply(config)
        before = {p.name for p in self.unit_dir.iterdir()}
        self.mounter.apply(empty_config(), previous=empty_config())
        self.assertEqual({p.name for p in self.unit_dir.iterdir()}, before)

    def test_an_explicit_apply_still_sweeps(self) -> None:
        # No `previous` means a person typed `smbpal apply`, which is the
        # command for exactly this. Deliberate, so it is allowed.
        self.mounter.apply(self.config())
        self.mounter.apply(empty_config())
        self.assertEqual(list(self.unit_dir.iterdir()), [])

    def test_an_empty_mountpoint_we_chose_is_cleared_up(self) -> None:
        # Observed on a Pi: with the connection removed and nothing mounted, a
        # stick labelled Media still went to Media1, because udisks2 picks its
        # mountpoint by testing whether the directory exists.
        self.mounter.managed_roots = frozenset({str(self.root)})
        config = self.config()
        mountpoint = Path(config["connections"][0]["mountpoint"])
        self.mounter.apply(config)
        self.assertTrue(mountpoint.is_dir())
        self.mounter.apply(empty_config())
        self.assertFalse(mountpoint.exists())

    def test_a_mountpoint_outside_our_roots_is_left_alone(self) -> None:
        # An empty directory at /srv/backups harms nobody and was probably
        # there before SMBPal was. Whose namespace it is, not who made it.
        config = self.config()
        mountpoint = Path(config["connections"][0]["mountpoint"])
        self.mounter.apply(config)
        self.mounter.apply(empty_config())
        self.assertTrue(mountpoint.is_dir())

    def test_a_mountpoint_with_anything_in_it_survives(self) -> None:
        # rmdir is the whole check: it refuses, and we take the refusal.
        self.mounter.managed_roots = frozenset({str(self.root)})
        config = self.config()
        mountpoint = Path(config["connections"][0]["mountpoint"])
        self.mounter.apply(config)
        (mountpoint / "someones-file").write_text("x", encoding="utf-8")
        self.mounter.apply(empty_config())
        self.assertTrue((mountpoint / "someones-file").exists())

    def test_credentials_reach_the_unit_as_a_path(self) -> None:
        config = self.config(credential_ref="nas")
        self.mounter.credentials.write("nas", username="pi", password="hunter2")
        self.mounter.apply(config)
        text = next(
            p for p in self.unit_dir.iterdir() if p.suffix == ".mount"
        ).read_text(encoding="utf-8")
        self.assertIn("credentials=", text)
        self.assertNotIn("hunter2", text)


class TestForeignMountDetection(unittest.TestCase):
    """Whose filesystem is on the mountpoint — the question `is_mounted` cannot ask."""

    connection = {
        "id": "nas",
        "host": "rivendell.local",
        "share": "Media",
        "mountpoint": "/media/pi/Media",
    }

    def entry(self, fstype: str, source: str) -> probe_module.MountEntry:
        return probe_module.MountEntry(
            mountpoint="/media/pi/Media", fstype=fstype, source=source, options="rw"
        )

    def test_our_own_share_is_not_foreign(self) -> None:
        entry = self.entry("cifs", "//rivendell.local/Media")
        self.assertIsNone(foreign_mount(entry, self.connection))

    def test_the_case_of_the_host_does_not_matter(self) -> None:
        # SMB hostnames are case-insensitive and the kernel echoes back what it
        # was given, so a unit written from a differently-cased name still
        # describes the same mount.
        entry = self.entry("cifs", "//Rivendell.local/media")
        self.assertIsNone(foreign_mount(entry, self.connection))

    def test_the_fallback_address_is_still_this_share(self) -> None:
        # `connection use-fallback` swaps host and fallback_host, so straight
        # after a swap the mount that is up was made under the other name.
        connection = {**self.connection, "fallback_host": "192.168.0.52"}
        entry = self.entry("cifs", "//192.168.0.52/Media")
        self.assertIsNone(foreign_mount(entry, connection))

    def test_a_usb_stick_is_foreign(self) -> None:
        entry = self.entry("vfat", "/dev/sda1")
        self.assertIs(foreign_mount(entry, self.connection), entry)

    def test_another_share_on_the_same_path_is_foreign(self) -> None:
        entry = self.entry("cifs", "//rivendell.local/Backups")
        self.assertIs(foreign_mount(entry, self.connection), entry)

    def test_nothing_mounted_is_not_foreign(self) -> None:
        self.assertIsNone(foreign_mount(None, self.connection))


class TestInventory(unittest.TestCase):
    """Three classes, because the action a person can take differs."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.unit_dir = self.root / "units"
        self.unit_dir.mkdir()
        self.mountinfo = self.root / "mountinfo"
        self.mountinfo.write_text("", encoding="utf-8")

    def write_unit(self, name: str, mountpoint: str, identifier: str) -> None:
        (self.unit_dir / name).write_text(
            f"{MARKER}{identifier}. Do not edit.\n[Mount]\nWhere={mountpoint}\n",
            encoding="utf-8",
        )

    def mount(self, mountpoint: str, source: str, fstype: str = "cifs") -> None:
        self.mountinfo.write_text(
            self.mountinfo.read_text(encoding="utf-8")
            + f"83 36 0:44 / {mountpoint} rw,relatime shared:45 - {fstype} "
            f"{source} rw,vers=3.1.1\n",
            encoding="utf-8",
        )

    def survey(self, config: dict) -> list[inventory.Finding]:
        return inventory.survey(
            config, unit_dir=self.unit_dir, mountinfo=self.mountinfo
        )

    def config(self, *mountpoints: str) -> dict:
        return {
            "connections": [
                {"id": f"c{i}", "mountpoint": m} for i, m in enumerate(mountpoints)
            ]
        }

    def test_a_configured_connection_is_not_reported(self) -> None:
        self.write_unit("mnt-nas.mount", "/mnt/nas", "nas")
        self.mount("/mnt/nas", "//rivendell.local/Media")
        self.assertEqual(self.survey(self.config("/mnt/nas")), [])

    def test_our_unit_with_no_config_entry_is_an_orphan(self) -> None:
        # The Pi case: connection gone from the config, automount still
        # enabled, share still mounting on access.
        self.write_unit("mnt-nas.mount", "/mnt/nas", "nas")
        self.mount("/mnt/nas", "//rivendell.local/Media")
        finding = self.survey(self.config())[0]
        self.assertEqual(finding.kind, inventory.ORPHANED)
        self.assertEqual(finding.connection_id, "nas")
        self.assertTrue(finding.mounted)
        self.assertIn("no longer in the config", finding.message)

    def test_an_orphan_that_has_never_mounted_is_still_found(self) -> None:
        # Nothing in mountinfo but autofs, which identifies nothing. The unit
        # is the only place this is visible, and it will mount on the next ls.
        self.write_unit("mnt-nas.automount", "/mnt/nas", "nas")
        finding = self.survey(self.config())[0]
        self.assertEqual(finding.kind, inventory.ORPHANED)
        self.assertFalse(finding.mounted)
        self.assertIn("will mount on access", finding.message)

    def test_a_cifs_mount_that_is_not_ours_is_unmanaged(self) -> None:
        self.mount("/mnt/theirs", "//elsewhere/Stuff")
        finding = self.survey(self.config())[0]
        self.assertEqual(finding.kind, inventory.UNMANAGED)
        self.assertIsNone(finding.connection_id)
        self.assertIn("left alone", finding.message)

    def test_an_orphan_is_not_also_counted_as_unmanaged(self) -> None:
        self.write_unit("mnt-nas.mount", "/mnt/nas", "nas")
        self.mount("/mnt/nas", "//rivendell.local/Media")
        findings = self.survey(self.config())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, inventory.ORPHANED)

    def test_both_units_for_one_orphan_report_once(self) -> None:
        self.write_unit("mnt-nas.mount", "/mnt/nas", "nas")
        self.write_unit("mnt-nas.automount", "/mnt/nas", "nas")
        self.assertEqual(len(self.survey(self.config())), 1)

    def test_a_non_smb_mount_is_not_our_business(self) -> None:
        # Reporting every stray ext4 mount would be noise dressed as diligence.
        self.mount("/mnt/disk", "/dev/sda1", fstype="ext4")
        self.assertEqual(self.survey(self.config()), [])

    def test_an_unmarked_unit_is_not_claimed_as_ours(self) -> None:
        (self.unit_dir / "mnt-theirs.mount").write_text(
            "[Mount]\nWhere=/mnt/theirs\n", encoding="utf-8"
        )
        self.assertEqual(self.survey(self.config()), [])

    def test_the_marker_is_the_one_in_apply(self) -> None:
        # Two copies of this string would mean units written by one and never
        # recognised by the other.
        self.assertEqual(inventory.MARKER, MARKER)


if __name__ == "__main__":
    unittest.main()
