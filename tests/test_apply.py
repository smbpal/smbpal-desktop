"""The apply pipeline: config in, a serving Samba out — and back again."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from smbpal.cli.main import _connection_summary
from smbpal.config import ConfigStore, empty_config
from smbpal.config import operations as ops
from smbpal.daemon.handlers import Dispatcher
from smbpal.discovery.advertise import Advertiser
from smbpal.errors import AlreadyExists, SmbpalError
from smbpal.ipc.peer import PeerCredentials
from smbpal.ipc.protocol import Request
from smbpal.mounts import units
from smbpal.mounts.apply import Mounter
from smbpal.mounts.credentials import CredentialsStore
from smbpal.mounts.probe import MountProbe
from smbpal.samba import control, include
from smbpal.samba.apply import Applier
from smbpal.shares import ownership
from tests.fakes import FakeSamba
from smbpal.daemon.handlers import Dispatcher
from smbpal.errors import AlreadyExists
from smbpal.ipc.peer import PeerCredentials
from smbpal.ipc.protocol import Request
from tests.test_samba import STOCK

_PEER = PeerCredentials(uid=0, gid=0, pid=1)


class ApplyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.smb_conf = self.root / "smb.conf"
        self.smb_conf.write_text(STOCK, encoding="utf-8")
        self.smbpal_conf = self.root / "smbpal.conf"
        self.service_file = self.root / "avahi" / "smbpal.service"
        self.samba = FakeSamba(self.smb_conf)
        self.applier = Applier(
            smb_conf=self.smb_conf,
            smbpal_conf=self.smbpal_conf,
            advertiser=Advertiser(self.service_file),
            runner=self.samba,
        )
        self.me = ownership.serving_identity(_username())

    def config_with_share(self, **kw) -> dict:
        directory = kw.pop("path", None) or str(self.root / "srv")
        Path(directory).mkdir(parents=True, exist_ok=True)
        doc, _ = ops.add_share(
            empty_config(),
            name=kw.pop("name", "Media"),
            path=directory,
            credential_ref=kw.pop("credential_ref", _username()),
            **kw,
        )
        return doc


class TestApply(ApplyTestCase):
    def test_it_writes_our_file_and_adds_the_include(self) -> None:
        self.applier.apply(self.config_with_share())
        self.assertIn("[Media]", self.smbpal_conf.read_text(encoding="utf-8"))
        self.assertTrue(include.has_include(self.smb_conf.read_text(encoding="utf-8")))

    def test_the_share_actually_appears_in_the_effective_config(self) -> None:
        # The fake parses smb.conf and follows the include, so this fails for
        # the real reason if the block or the generated file is wrong.
        self.applier.apply(self.config_with_share())
        self.assertIn("Media", control.effective_share_names(runner=self.samba))

    def test_it_reloads_and_never_restarts(self) -> None:
        self.applier.apply(self.config_with_share())
        commands = {call[0] for call in self.samba.calls}
        self.assertIn("smbcontrol", commands)
        self.assertNotIn("systemctl", commands)

    def test_applying_twice_changes_nothing(self) -> None:
        config = self.config_with_share()
        self.applier.apply(config)
        after_first = self.smb_conf.read_text(encoding="utf-8")
        self.applier.apply(config)
        self.assertEqual(self.smb_conf.read_text(encoding="utf-8"), after_first)
        self.assertEqual(after_first.count(self.applier.include_line), 1)

    def test_a_share_that_does_not_appear_is_reported_as_a_failure(self) -> None:
        # Simulate the M0 failure: our file is written but the include never
        # took, so Samba is serving nothing of ours and says OK about it.
        config = self.config_with_share()
        original_ensure = self.applier._ensure_include
        self.applier._ensure_include = lambda: None  # type: ignore[method-assign]
        self.addCleanup(setattr, self.applier, "_ensure_include", original_ensure)
        with self.assertRaises(control.ShareNotServed):
            self.applier.apply(config)

    def test_a_missing_directory_is_created_and_owned(self) -> None:
        target = self.root / "made-by-smbpal"
        doc, _ = ops.add_share(
            empty_config(), name="New", path=str(target), credential_ref=_username()
        )
        self.applier.apply(doc)
        self.assertTrue(target.is_dir())

    def test_a_share_with_no_user_does_not_get_a_directory_invented_for_it(
        self,
    ) -> None:
        target = self.root / "no-user"
        doc, _ = ops.add_share(
            empty_config(), name="NoUser", path=str(target), credential_ref=None
        )
        self.applier.apply(doc)
        # Better a share Samba complains about than a root-owned directory
        # nothing can write.
        self.assertFalse(target.exists())


class TestTeardown(ApplyTestCase):
    def test_smb_conf_comes_back_byte_identical(self) -> None:
        self.applier.apply(self.config_with_share())
        self.applier.teardown()
        self.assertEqual(self.smb_conf.read_text(encoding="utf-8"), STOCK)

    def test_our_file_and_the_mdns_record_are_removed(self) -> None:
        self.applier.apply(self.config_with_share())
        self.assertTrue(self.smbpal_conf.exists())
        self.assertTrue(self.service_file.exists())
        self.applier.teardown()
        self.assertFalse(self.smbpal_conf.exists())
        self.assertFalse(self.service_file.exists())

    def test_teardown_on_a_machine_we_never_touched_is_harmless(self) -> None:
        self.applier.teardown()
        self.assertEqual(self.smb_conf.read_text(encoding="utf-8"), STOCK)


class TestAdvertising(ApplyTestCase):
    def test_the_record_appears_with_a_share_and_goes_with_the_last_one(self) -> None:
        config = self.config_with_share()
        report = self.applier.apply(config)
        self.assertTrue(report.advertising)
        self.assertIn("_smbpal._tcp", self.service_file.read_text(encoding="utf-8"))

        emptied, _ = ops.remove_share(config, "Media")
        report = self.applier.apply(emptied)
        self.assertFalse(report.advertising)
        self.assertFalse(self.service_file.exists())

    def test_a_disabled_share_does_not_count_as_sharing(self) -> None:
        # §3f gates on *active* shares: a machine serving nothing should be
        # silent on an untrusted network.
        config = self.config_with_share(enabled=False)
        self.assertFalse(self.applier.apply(config).advertising)

    def test_the_record_carries_no_application_version(self) -> None:
        self.applier.apply(self.config_with_share())
        text = self.service_file.read_text(encoding="utf-8")
        self.assertIn("<txt-record>v=1</txt-record>", text)
        self.assertNotIn("ver=", text)
        self.assertNotIn("caps=", text)


class TestOwnership(ApplyTestCase):
    def test_an_unwritable_directory_makes_the_share_read_only_with_a_reason(
        self,
    ) -> None:
        # §3c: read-only with a message, and nothing on disk touched.
        if self.me.uid == 0:
            self.skipTest("root can write anywhere, which is the point of the check")
        target = self.root / "theirs"
        target.mkdir()
        target.chmod(0o500)
        self.addCleanup(target.chmod, 0o700)
        doc = self.config_with_share(path=str(target))
        planned = self.applier.plan(doc)[0]
        self.assertTrue(planned.read_only)
        self.assertIn("read only = yes", self._rendered(doc))

    def test_the_reason_names_the_mode_when_the_owner_is_already_right(self) -> None:
        # The first version of this said "it belongs to luke" to luke, blaming
        # ownership for what was a missing write bit — and sending the user to
        # change the wrong thing.
        if self.me.uid == 0:
            self.skipTest("root can write anywhere")
        target = self.root / "mine-but-locked"
        target.mkdir(mode=0o500)
        self.addCleanup(target.chmod, 0o700)
        planned = self.applier.plan(self.config_with_share(path=str(target)))[0]
        self.assertIn("does not include write permission for the owner", planned.reason)
        self.assertIn("0500", planned.reason)

    def test_make_writable_fixes_a_mode_problem_not_just_an_owner_problem(self) -> None:
        # chown alone is a no-op when the serving user already owns it, and the
        # share would stay read-only while claiming to have been fixed.
        if self.me.uid == 0:
            self.skipTest("root can write anywhere")
        target = self.root / "mine-but-locked"
        target.mkdir(mode=0o500)
        self.addCleanup(target.chmod, 0o700)
        status = ownership.make_writable(target, self.me)
        self.assertTrue(status.writable)

    def test_make_writable_does_not_widen_group_or_other(self) -> None:
        if self.me.uid == 0:
            self.skipTest("root can write anywhere")
        target = self.root / "narrow"
        target.mkdir(mode=0o500)
        self.addCleanup(target.chmod, 0o700)
        ownership.make_writable(target, self.me)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode) & 0o077, 0)

    def test_the_owner_is_not_changed_as_a_side_effect(self) -> None:
        target = self.root / "theirs"
        target.mkdir()
        target.chmod(0o500)
        self.addCleanup(target.chmod, 0o700)
        before = target.stat()
        self.applier.apply(self.config_with_share(path=str(target)))
        after = target.stat()
        self.assertEqual(
            (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
            (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
        )

    def test_a_writable_directory_keeps_the_configured_intent(self) -> None:
        planned = self.applier.plan(self.config_with_share())[0]
        self.assertFalse(planned.read_only)
        self.assertIsNone(planned.reason)

    def test_choosing_read_only_gives_no_reason_because_there_is_no_fix(self) -> None:
        planned = self.applier.plan(self.config_with_share(read_only=True))[0]
        self.assertTrue(planned.read_only)
        self.assertIsNone(planned.reason)

    def _rendered(self, doc) -> str:
        self.applier.apply(doc)
        return self.smbpal_conf.read_text(encoding="utf-8")


class TestMakeWritableWarnsAboutLiveClients(ApplyTestCase):
    def test_the_result_says_connected_clients_keep_the_old_permissions(self) -> None:
        # Samba applies share parameters at tree connect, so a client that was
        # already attached when the share was read-only keeps what it
        # negotiated. Confirmed on the Pi: a Windows client connecting fresh
        # could write while a Mac holding an older session could not.
        if self.me.uid == 0:
            self.skipTest("root can write anywhere")

        target = self.root / "locked"
        target.mkdir(mode=0o500)
        self.addCleanup(target.chmod, 0o700)
        store = ConfigStore(self.root / "config.json")
        store.save(self.config_with_share(path=str(target)))
        dispatcher = Dispatcher(store, applier=self.applier)

        result = dispatcher._share_make_writable(
            Request(id="1", method="share.make_writable", params={"ref": "Media"}),
            PeerCredentials(uid=os.getuid(), gid=os.getgid()),
        )
        self.assertIn("reconnect", result["note"])


class TestRollback(ApplyTestCase):
    def test_a_failed_apply_leaves_no_record_of_an_unserved_share(self) -> None:
        # D12: "a config edit that the daemon has not applied is a lie."
        store = ConfigStore(self.root / "config.json")
        dispatcher = Dispatcher(store, applier=self.applier)
        self.samba.reload_fails = True

        from smbpal.ipc.peer import PeerCredentials
        from smbpal.ipc.protocol import Request

        with self.assertRaises(SmbpalError):
            dispatcher._share_add(
                Request(
                    id="1",
                    method="share.add",
                    params={
                        "name": "Media",
                        "path": str(self.root / "srv"),
                        "credential_ref": _username(),
                    },
                ),
                PeerCredentials(uid=os.getuid(), gid=os.getgid()),
            )
        self.assertEqual(store.load()["shares"], [])


def _username() -> str:
    import getpass

    return getpass.getuser()


class TestUnmanagedShares(ApplyTestCase):
    """§8 parks adopting a hand-written share. That is not the same as hiding it."""

    def setUp(self) -> None:
        super().setUp()
        self.smb_conf.write_text(
            self.smb_conf.read_text(encoding="utf-8")
            + "\n[Legacy]\n   path = /srv/legacy\n",
            encoding="utf-8",
        )
        self.store = ConfigStore(self.root / "config.json")
        self.dispatcher = Dispatcher(self.store, applier=self.applier)

    def status(self) -> dict:
        return self.dispatcher._status(None, None)

    def test_a_hand_written_share_appears_marked(self) -> None:
        # A list showing two of someone's five shares reads as SMBPal having
        # broken the other three.
        rows = {r["name"]: r for r in self.status()["shares"]}
        self.assertIn("Legacy", rows)
        self.assertEqual(rows["Legacy"]["state"], "unmanaged")
        self.assertIs(rows["Legacy"]["managed"], False)

    def test_sambas_own_sections_are_not_listed_as_shares(self) -> None:
        names = {r["name"] for r in self.status()["shares"]}
        self.assertNotIn("global", names)
        self.assertNotIn("printers", names)

    def test_adding_a_share_that_would_shadow_one_is_refused(self) -> None:
        # SMBPal cannot edit their section — it only writes smbpal.conf — but
        # it can append a second [Legacy] after it, and Samba takes the last
        # one. Their share stops working and nothing says so.
        Path(self.root / "mine").mkdir()
        with self.assertRaises(AlreadyExists) as caught:
            self.dispatcher._share_add(
                Request(id=1, method="share.add",
                        params={"name": "legacy", "path": str(self.root / "mine")}),
                _PEER,
            )
        self.assertIn("SMBPal did not create", caught.exception.message)
        self.assertIn("/srv/legacy", caught.exception.detail)

    def test_an_unrelated_name_is_still_allowed(self) -> None:
        Path(self.root / "mine").mkdir()
        share = self.dispatcher._share_add(
            Request(id=1, method="share.add",
                    params={"name": "Media", "path": str(self.root / "mine")}),
            _PEER,
        )
        self.assertEqual(share["name"], "Media")


class TestApplyDoesBothHalves(ApplyTestCase):
    """`smbpal apply` is the command three messages tell people to run."""

    def setUp(self) -> None:
        super().setUp()
        self.unit_dir = self.root / "units"
        self.unit_dir.mkdir()
        self.mountinfo = self.root / "mountinfo"
        self.mountinfo.write_text("", encoding="utf-8")
        self.mounter = Mounter(
            unit_dir=self.unit_dir,
            credentials=CredentialsStore(self.root / "creds"),
            probe=MountProbe(mountinfo=self.mountinfo),
            runner=self.samba,
        )
        self.store = ConfigStore(self.root / "config.json")
        doc, self.connection = ops.add_connection(
            empty_config(),
            host="rivendell.local",
            share="Media",
            mountpoint=str(self.root / "mnt" / "nas"),
        )
        self.store.save(doc)
        self.dispatcher = Dispatcher(
            self.store, applier=self.applier, mounter=self.mounter
        )

    def apply(self) -> dict:
        return self.dispatcher._apply(
            Request(id=1, method="apply", params={}), _PEER
        )

    def test_it_writes_the_mount_units(self) -> None:
        # Before this, `smbpal apply` called only the Samba applier, so it did
        # nothing whatever to connections.
        self.apply()
        self.assertEqual(len(list(self.unit_dir.iterdir())), 2)

    def test_it_arms_the_automount(self) -> None:
        self.apply()
        self.assertTrue(
            any(u.endswith(".automount") for u in self.samba.enabled_units)
        )

    def test_it_clears_a_latched_unit(self) -> None:
        # Mounter.apply calls reset-failed on the reasoning that apply is the
        # command people reach for after fixing whatever was wrong. That was
        # only true for a commit; a typed `apply` never reached it.
        mount_name, _ = units.unit_names(self.connection["mountpoint"])
        self.samba.latched.add(mount_name)
        self.apply()
        self.assertNotIn(mount_name, self.samba.latched)

    def test_the_report_carries_the_connections(self) -> None:
        # `serving nothing` with two connections mounted is how the missing
        # half was found: true about shares, silent about everything else.
        report = self.apply()
        self.assertEqual(len(report["connections"]), 1)
        self.assertEqual(report["connections"][0]["id"], self.connection["id"])


class TestConnectionSummary(unittest.TestCase):
    def test_states_are_counted(self) -> None:
        summary = _connection_summary(
            [{"state": "mounted"}, {"state": "mounted"}, {"state": "not mounted"}]
        )
        self.assertEqual(summary, "connections: 2 mounted, 1 not mounted")

    def test_nothing_configured_says_nothing(self) -> None:
        self.assertEqual(_connection_summary([]), "")


class TestTeardownIsReachable(ApplyTestCase):
    """§6's reversibility claim, from the wire rather than from a unit test.

    Both teardowns existed and nothing called them: no IPC method, no CLI verb,
    no shutdown path. The claim was implemented, unit-tested and unreachable,
    so it had never run against a real smb.conf. Found on a Pi on 27 August
    2026 by running the runbook's teardown step and getting the include block
    back in the diff.
    """

    def setUp(self) -> None:
        super().setUp()
        self.unit_dir = self.root / "units"
        self.unit_dir.mkdir()
        self.mountinfo = self.root / "mountinfo"
        self.mountinfo.write_text("", encoding="utf-8")
        self.mounter = Mounter(
            unit_dir=self.unit_dir,
            credentials=CredentialsStore(self.root / "creds"),
            probe=MountProbe(mountinfo=self.mountinfo),
            runner=self.samba,
            managed_roots=frozenset({str(self.root)}),
        )
        self.store = ConfigStore(self.root / "config.json")
        self.dispatcher = Dispatcher(
            self.store, applier=self.applier, mounter=self.mounter
        )
        self.pristine = self.smb_conf.read_text(encoding="utf-8")

    def teardown_call(self) -> dict:
        return self.dispatcher._teardown(
            Request(id=1, method="teardown", params={}), _PEER
        )

    def test_smb_conf_comes_back_byte_identical(self) -> None:
        # The claim itself. Removed as a block, because M0's line-based removal
        # left a blank line behind and the diff blamed it.
        self.applier.apply(self.config_with_share())
        self.assertNotEqual(self.smb_conf.read_text(encoding="utf-8"), self.pristine)
        self.teardown_call()
        self.assertEqual(self.smb_conf.read_text(encoding="utf-8"), self.pristine)

    def test_it_takes_the_generated_file_and_the_units(self) -> None:
        doc, _ = ops.add_connection(
            self.config_with_share(),
            host="rivendell.local",
            share="Media",
            mountpoint=str(self.root / "mnt" / "nas"),
        )
        self.applier.apply(doc)
        self.mounter.apply(doc)
        self.assertTrue(self.smbpal_conf.exists())
        self.assertEqual(len(list(self.unit_dir.iterdir())), 2)

        result = self.teardown_call()
        self.assertFalse(self.smbpal_conf.exists())
        self.assertEqual(list(self.unit_dir.iterdir()), [])
        self.assertEqual(len(result["units_removed"]), 2)
        self.assertTrue(result["include_removed"])

    def test_the_config_is_kept(self) -> None:
        # Side effects, not intent. A later apply has to put it all back.
        self.store.save(self.config_with_share())
        self.teardown_call()
        self.assertEqual(len(self.store.load()["shares"]), 1)

    def test_apply_after_teardown_restores_everything(self) -> None:
        config = self.config_with_share()
        self.store.save(config)
        self.applier.apply(config)
        self.teardown_call()
        self.dispatcher._apply(Request(id=2, method="apply", params={}), _PEER)
        self.assertTrue(self.smbpal_conf.exists())
        self.assertIn("smbpal", self.smb_conf.read_text(encoding="utf-8"))

    def test_tearing_down_twice_is_not_an_error(self) -> None:
        self.applier.apply(self.config_with_share())
        self.teardown_call()
        second = self.teardown_call()
        self.assertFalse(second["include_removed"])
        self.assertEqual(self.smb_conf.read_text(encoding="utf-8"), self.pristine)


if __name__ == "__main__":
    unittest.main()
