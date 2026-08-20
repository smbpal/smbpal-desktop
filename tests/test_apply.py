"""The apply pipeline: config in, a serving Samba out — and back again."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from smbpal.config import ConfigStore, empty_config
from smbpal.config import operations as ops
from smbpal.daemon.handlers import Dispatcher
from smbpal.discovery.advertise import Advertiser
from smbpal.errors import SmbpalError
from smbpal.samba import control, include
from smbpal.samba.apply import Applier
from smbpal.shares import ownership
from tests.fake_samba import FakeSamba
from tests.test_samba import STOCK


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


if __name__ == "__main__":
    unittest.main()
