"""The include block, the generated file, and the checks around them."""

from __future__ import annotations

import unittest
from pathlib import Path

from smbpal.samba import conf, control, include, passwd
from smbpal.samba.include import SmbConfError
from smbpal.errors import InvalidParams, NotFound
from tests.fake_samba import FakeSamba

# Debian's stock smb.conf, reduced to the parts that matter here. [print$] is
# last on purpose: that is the section M0's appended include landed inside.
STOCK = """\
#======================= Global Settings =======================

[global]
   workgroup = WORKGROUP
   log file = /var/log/samba/log.%m

#======================= Share Definitions =====================

[homes]
   comment = Home Directories
   browseable = no

[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
"""


class TestIncludeBlock(unittest.TestCase):
    def test_the_block_goes_immediately_after_global(self) -> None:
        lines = include.insert_include(STOCK).splitlines()
        self.assertEqual(lines[lines.index("[global]") + 1], include.BEGIN_MARKER)
        self.assertEqual(lines[lines.index("[global]") + 2], include.INCLUDE_LINE)

    def test_it_is_not_appended_to_the_end(self) -> None:
        # M0 appended and the line became a parameter of [print$].
        result = include.insert_include(STOCK)
        self.assertNotEqual(result.splitlines()[-1], include.INCLUDE_LINE)

    def test_inserting_twice_inserts_once(self) -> None:
        once = include.insert_include(STOCK)
        self.assertEqual(include.insert_include(once), once)
        self.assertEqual(once.count(include.INCLUDE_LINE), 1)

    def test_removal_is_byte_identical(self) -> None:
        # M0's line-based removal left a blank line behind and §6's diff
        # blamed it.
        self.assertEqual(include.remove_include(include.insert_include(STOCK)), STOCK)

    def test_a_global_header_with_odd_spacing_or_case_is_found(self) -> None:
        for header in ("  [global]", "[GLOBAL]", "[Global]\t"):
            with self.subTest(header=header):
                text = STOCK.replace("[global]", header)
                self.assertTrue(include.has_include(include.insert_include(text)))

    def test_a_file_with_no_global_is_refused_rather_than_appended(self) -> None:
        with self.assertRaises(SmbConfError) as caught:
            include.insert_include("[homes]\n   browseable = no\n")
        self.assertIn("will not append", caught.exception.detail or "")

    def test_stray_bare_includes_are_swept_up(self) -> None:
        # M0 produced duplicates before the guard existed.
        messy = STOCK.replace("[global]", f"[global]\n{include.INCLUDE_LINE}")
        self.assertNotIn(include.INCLUDE_LINE, include.remove_include(messy))

    def test_an_unterminated_block_is_refused_not_guessed(self) -> None:
        broken = STOCK.replace("[global]", f"[global]\n{include.BEGIN_MARKER}")
        with self.assertRaises(SmbConfError):
            include.remove_include(broken)

    def test_crlf_line_endings_survive(self) -> None:
        crlf = STOCK.replace("\n", "\r\n")
        inserted = include.insert_include(crlf)
        self.assertIn(f"{include.INCLUDE_LINE}\r\n", inserted)
        self.assertEqual(include.remove_include(inserted), crlf)


class TestGeneratedConf(unittest.TestCase):
    def _share(self, **kw):
        base = {
            "id": "m",
            "name": "Media",
            "path": "/srv/media",
            "read_only": False,
            "enabled": True,
            "credential_ref": "pi",
        }
        base.update(kw)
        return base

    def test_a_share_becomes_a_section(self) -> None:
        text = conf.render([self._share()])
        self.assertIn("[Media]", text)
        self.assertIn("path = /srv/media", text)
        self.assertIn("read only = no", text)
        self.assertIn("valid users = pi", text)

    def test_guests_are_refused_explicitly(self) -> None:
        # Pi OS ships `map to guest = bad user` enabled (M0 §1), so a share is
        # guest-reachable unless it says otherwise.
        self.assertIn("guest ok = no", conf.render([self._share()]))

    def test_a_disabled_share_is_not_rendered(self) -> None:
        self.assertNotIn("[Media]", conf.render([self._share(enabled=False)]))

    def test_a_share_with_no_user_gets_no_valid_users_line(self) -> None:
        self.assertNotIn("valid users", conf.render([self._share(credential_ref=None)]))

    def test_a_line_break_is_refused_even_though_validation_should_have_caught_it(
        self,
    ) -> None:
        with self.assertRaises(conf.GenerationRefused):
            conf.render([self._share(name="Media\n[global]")])


class TestControl(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.smb_conf = self.root / "smb.conf"
        self.smb_conf.write_text(STOCK, encoding="utf-8")
        self.samba = FakeSamba(self.smb_conf)

    def test_effective_names_come_from_the_dump(self) -> None:
        names = control.effective_share_names(runner=self.samba)
        self.assertEqual(names, {"global", "homes", "print$"})

    def test_reload_uses_reload_config_and_never_a_restart(self) -> None:
        control.reload_config(runner=self.samba)
        self.assertEqual(self.samba.calls[-1], ("smbcontrol", "all", "reload-config"))

    def test_a_failed_reload_is_reported(self) -> None:
        self.samba.reload_fails = True
        with self.assertRaises(control.ReloadFailed):
            control.reload_config(runner=self.samba)

    def test_verify_present_fails_when_the_share_is_not_in_the_dump(self) -> None:
        with self.assertRaises(control.ShareNotServed) as caught:
            control.verify_present({"Media"}, runner=self.samba)
        self.assertIn("M0 §1a", caught.exception.detail or "")


class TestCredentials(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.samba = FakeSamba(Path(self._dir.name) / "smb.conf")

    def test_a_nonexistent_posix_account_is_refused_before_anything_is_asked(
        self,
    ) -> None:
        # §3b: smbpasswd prompts twice and only then fails, so the check has to
        # happen first or the user types a password that is thrown away.
        with self.assertRaises(NotFound):
            passwd.require_posix_user("definitely-no-such-user-12345")
        self.assertEqual(self.samba.calls, [])

    def test_an_illegal_username_is_refused(self) -> None:
        for bad in ("../root", "has space", "UPPER", ""):
            with self.subTest(username=bad):
                with self.assertRaises((InvalidParams, NotFound)):
                    passwd.require_posix_user(bad)

    def test_the_password_goes_on_stdin_and_never_into_argv(self) -> None:
        # M0 §9: sudo journals full command lines and ps shows arguments.
        import getpass as _getpass

        me = _getpass.getuser()
        passwd.set_password(me, "hunter2", runner=self.samba)
        argv = self.samba.calls[-1]
        self.assertEqual(argv, ("smbpasswd", "-a", "-s", me))
        self.assertNotIn("hunter2", " ".join(argv))
        self.assertEqual(self.samba.stdin[-1], "hunter2\nhunter2\n")

    def test_removal_uses_pdbedit_x_which_leaves_the_posix_account(self) -> None:
        import getpass as _getpass

        me = _getpass.getuser()
        passwd.set_password(me, "x", runner=self.samba)
        passwd.remove_user(me, runner=self.samba)
        self.assertEqual(self.samba.calls[-1], ("pdbedit", "-x", "-u", me))
        self.assertEqual(passwd.list_users(runner=self.samba), [])

    def test_listing_never_asks_for_hashes(self) -> None:
        # `pdbedit -L -w` prints password hashes, and §11.3 publishes full
        # history — a hash that reaches a capture is a hash that is published.
        passwd.list_users(runner=self.samba)
        self.assertNotIn("-w", self.samba.calls[-1])


if __name__ == "__main__":
    unittest.main()
