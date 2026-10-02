"""The login Keychain, which is half the reason the agent exists.

Two halves, like `test_netfs.py`. The part that needs macOS says so and skips;
the part most likely to rot is the shape of the module itself, and that is
checkable anywhere.

**The macOS half writes to the developer's own login Keychain**, because there
is no other kind. It uses a documentation hostname and an account named after
this process, and removes the item in a cleanup that runs even when the test
fails. CI is Linux, so none of it runs there.
"""

from __future__ import annotations

import os
import sys
import unittest

from smbpal.agent import keychain

darwin_only = unittest.skipUnless(
    sys.platform == "darwin", "the Keychain is macOS only"
)

HOST = "nas.example"


class TestItImportsAnywhere(unittest.TestCase):
    def test_available_is_the_platform_and_nothing_loads_at_import(self) -> None:
        self.assertEqual(keychain.available(), sys.platform == "darwin")

    @unittest.skipIf(sys.platform == "darwin", "this is the not-macOS case")
    def test_on_linux_it_says_what_is_wrong_and_what_is_used_instead(self) -> None:
        with self.assertRaises(keychain.KeychainError) as caught:
            keychain.present(HOST, "anyone")
        self.assertIn("macOS only", caught.exception.message)
        self.assertIn("mount.cifs", caught.exception.detail or "")


class TestWhoIsAllowedToReadAPassword(unittest.TestCase):
    """**This rule was reversed by a measurement, and the test says so.**

    It began as `set`, `present`, `forget` and no read: the store exists so
    that something *else* can read it, the way `mount.cifs` reads the file
    `CredentialsStore` writes. NetAuthAgent turned out not to read it when
    asked not to show UI -- measured against a real server on 2 October 2026 --
    and the NetFS header has no option to turn the lookup on without permitting
    a dialog a launchd agent must not raise.

    **So what is asserted now is the property that actually mattered**, which
    is not "nobody reads it" but "only the session does". The daemon runs as
    root, cannot read this Keychain, and has nowhere to put a password it
    fetched: the mount call on its own client carries none.
    """

    def test_the_session_can_read_it(self) -> None:
        self.assertTrue(callable(keychain.get_password))

    def test_the_daemons_own_store_still_cannot(self) -> None:
        # The Linux half of the same rule, unchanged: that file is written for
        # `mount.cifs` to read, and a daemon reading it back would make root a
        # party to every credential it stores.
        from smbpal.mounts.credentials import CredentialsStore

        self.assertTrue(hasattr(CredentialsStore, "username_for"))
        for forbidden in ("password_for", "get_password", "read_password"):
            self.assertFalse(hasattr(CredentialsStore, forbidden), forbidden)

    def test_and_the_mount_call_between_them_carries_no_password(self) -> None:
        # The agent fetches the credential itself, so the one call that crosses
        # the daemon-to-agent boundary on the mount path still has no secret in
        # it. `credential_set` remains the only one that does.
        from smbpal.agent.client import AgentClient

        self.assertNotIn("password", AgentClient.mount.__code__.co_varnames)


@darwin_only
class TestAgainstTheRealKeychain(unittest.TestCase):
    def setUp(self) -> None:
        # Named after the process so two runs cannot collide, and so an item
        # left behind by a crash is obviously not a real credential.
        self.account = f"smbpal-test-{os.getpid()}"
        self.addCleanup(self._tidy)

    def _tidy(self) -> None:
        keychain.forget(HOST, self.account)

    def test_the_whole_cycle(self) -> None:
        self.assertFalse(keychain.present(HOST, self.account))
        self.assertEqual(
            keychain.set_password(HOST, self.account, "throwaway-for-a-test"), "created"
        )
        self.assertTrue(keychain.present(HOST, self.account))
        self.assertTrue(keychain.forget(HOST, self.account))
        self.assertFalse(keychain.present(HOST, self.account))

    def test_storing_twice_replaces_rather_than_failing_or_duplicating(self) -> None:
        """The measured fact the whole design rests on.

        `SecItemAdd` of a second item with the same server, account and
        protocol returns `errSecDuplicateItem` -- so there is exactly one item
        per share, and SMBPal cannot keep its own beside one Finder wrote. That
        is why `keychain_credential` has to record which of the two happened.
        """
        self.assertEqual(
            keychain.set_password(HOST, self.account, "throwaway-first"), "created"
        )
        self.assertEqual(
            keychain.set_password(HOST, self.account, "throwaway-second"), "replaced"
        )

    def test_the_password_comes_back_exactly(self) -> None:
        secret = "throwaway-with-£-and-a-space"
        keychain.set_password(HOST, self.account, secret)
        self.assertEqual(keychain.get_password(HOST, self.account), secret)

    def test_reading_one_that_is_not_there_is_none_not_an_error(self) -> None:
        self.assertIsNone(keychain.get_password(HOST, f"{self.account}-absent"))

    def test_forgetting_nothing_is_not_a_failure(self) -> None:
        # The shape `netfs.unmount` and `launchd.bootout` already have: a
        # caller asking for something to be gone has got what it asked for.
        self.assertFalse(keychain.forget(HOST, f"{self.account}-never-existed"))

    def test_an_empty_field_is_refused_before_the_framework_sees_it(self) -> None:
        for host, account, password in (
            ("", self.account, "throwaway"),
            (HOST, "", "throwaway"),
            (HOST, self.account, ""),
        ):
            with self.subTest(host=host, account=account):
                with self.assertRaises(keychain.KeychainError):
                    keychain.set_password(host, account, password)

    def test_the_system_describes_its_own_errors(self) -> None:
        # Better than a table of ours that would need maintaining, and it is
        # how the duplicate case was identified in the first place.
        self.assertIn("already exists", keychain._message(keychain.ERR_DUPLICATE_ITEM))


if __name__ == "__main__":
    unittest.main()
