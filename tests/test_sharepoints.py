"""The macOS apply: config to sharepoints, through a helper that is faked here.

The real helper needs root and a socket whose path is fixed on purpose, so the
fake stands in for it at the `Helper` method boundary -- after the wire format,
which `test_helper_client.py` pins. What is asserted is the reconcile: what is
published, what is removed, what is refused, and that nothing SMBPal did not
publish is ever touched (§6's guarantee in its macOS form, helper spike §3).

Paths use a made-up account; nothing here reads the machine's sharepoints.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from smbpal.config.store import ConfigStore
from smbpal.daemon.handlers import Dispatcher
from smbpal.errors import AlreadyExists, NeedsAuthorisation, NotSupported
from smbpal.ipc.peer import PeerCredentials
from smbpal.ipc.protocol import Request
from smbpal.samba.apply import ApplyError
from smbpal.sharepoints import SharepointApplier
from smbpal.system.helper import HelperError, PathFacts
from tests.test_ipc import ServerTestCase

GRANT = bytes(32)
HOME = "/Users/someone"


def ok(path: str, *, owner: str = "someone", uid: int = 501, acl: bool = False) -> PathFacts:
    return PathFacts(
        verdict="ok", resolved=path, uid=uid, gid=20, mode=0o755, owner=owner, has_acl=acl
    )


class FakeHelper:
    """The helper's sharepoint verbs over an in-memory `sharing -l`."""

    def __init__(self) -> None:
        self.facts: dict[str, PathFacts] = {}
        # Somebody else's share, present before SMBPal arrived.
        self.records: dict[str, dict[str, object]] = {
            "Public": {"path": f"{HOME}/Public", "smb_name": "Public", "smb_shared": True}
        }
        self.owned: list[str] = []
        self.calls: list[tuple[str, ...]] = []
        self.publish_takes = True

    def path_inspect(self, path: str) -> PathFacts:
        return self.facts.get(path, ok(path))

    def share_list(self) -> bytes:
        return json.dumps(self.records).encode()

    def share_owned(self) -> list[str]:
        return list(self.owned)

    def share_publish(self, name: str, path: str, *, auth: bytes) -> None:
        self.calls.append(("publish", name, path))
        if name in self.records:
            raise HelperError("refused", token="exists")
        if self.publish_takes:
            self.records[name] = {"path": path, "smb_name": name, "smb_shared": True}
        self.owned.append(name)

    def share_unpublish(self, name: str, *, auth: bytes) -> None:
        self.calls.append(("unpublish", name))
        if name not in self.owned:
            raise HelperError("refused", token="not-ours")
        self.records.pop(name, None)
        self.owned.remove(name)


def share(name: str, path: str, **extra: object) -> dict[str, object]:
    return {"type": "os", "id": name.lower(), "name": name, "path": path, **extra}


class SharepointCase(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = FakeHelper()
        self.applier = SharepointApplier(self.helper)  # type: ignore[arg-type]

    def config(self, *shares: dict[str, object]) -> dict[str, object]:
        return {"version": 1, "shares": list(shares), "connections": []}


class TestReconcile(SharepointCase):
    def test_a_new_share_is_published_and_verified(self) -> None:
        report = self.applier.apply(self.config(share("Docs", f"{HOME}/Documents")), grant=GRANT)
        self.assertEqual(self.helper.calls, [("publish", "Docs", f"{HOME}/Documents")])
        self.assertEqual(report.served, ["Docs"])

    def test_the_resolved_path_is_what_is_published(self) -> None:
        """§13 rule 1: the helper shares what it checked."""
        self.helper.facts["/Volumes/Link"] = ok("/Volumes/Disk/Real")
        self.applier.apply(self.config(share("Disk", "/Volumes/Link")), grant=GRANT)
        self.assertEqual(self.helper.calls, [("publish", "Disk", "/Volumes/Disk/Real")])

    def test_applying_twice_changes_nothing_and_needs_no_grant(self) -> None:
        config = self.config(share("Docs", f"{HOME}/Documents"))
        self.applier.apply(config, grant=GRANT)
        self.helper.calls.clear()
        self.applier.apply(config)  # no grant, and none needed
        self.assertEqual(self.helper.calls, [])

    def test_a_removed_share_is_unpublished(self) -> None:
        self.applier.apply(self.config(share("Docs", f"{HOME}/Documents")), grant=GRANT)
        self.helper.calls.clear()
        self.applier.apply(self.config(), grant=GRANT)
        self.assertEqual(self.helper.calls, [("unpublish", "Docs")])

    def test_a_moved_share_is_republished(self) -> None:
        self.applier.apply(self.config(share("Docs", f"{HOME}/Documents")), grant=GRANT)
        self.helper.calls.clear()
        self.applier.apply(self.config(share("Docs", f"{HOME}/Desktop")), grant=GRANT)
        self.assertEqual(
            self.helper.calls,
            [("unpublish", "Docs"), ("publish", "Docs", f"{HOME}/Desktop")],
        )

    def test_a_disabled_share_is_not_published(self) -> None:
        self.applier.apply(
            self.config(share("Docs", f"{HOME}/Documents", enabled=False)), grant=GRANT
        )
        self.assertEqual(self.helper.calls, [])

    def test_somebody_elses_share_is_never_touched(self) -> None:
        self.applier.apply(self.config(share("Docs", f"{HOME}/Documents")), grant=GRANT)
        self.applier.apply(self.config(), grant=GRANT)
        self.assertIn("Public", self.helper.records)
        self.assertNotIn(("unpublish", "Public"), self.helper.calls)

    def test_a_name_somebody_else_already_shares_is_refused_before_any_change(self) -> None:
        with self.assertRaises(AlreadyExists) as caught:
            self.applier.apply(self.config(share("Public", f"{HOME}/Documents")), grant=GRANT)
        self.assertIn(f"{HOME}/Public", caught.exception.detail or "")
        self.assertEqual(self.helper.calls, [])

    def test_a_change_without_a_grant_asks_for_one(self) -> None:
        """Root is waved through by `Authoriser` and not by the helper, so
        reaching here without a grant must say what to acquire."""
        with self.assertRaises(NeedsAuthorisation) as caught:
            self.applier.apply(self.config(share("Docs", f"{HOME}/Documents")))
        self.assertEqual(caught.exception.right, "app.smbpal.manage-shares")

    def test_a_publish_that_does_not_appear_fails_verification(self) -> None:
        """`sharing` said nothing when handed a missing folder (account spike):
        presence is the only evidence."""
        self.helper.publish_takes = False
        with self.assertRaises(ApplyError):
            self.applier.apply(self.config(share("Docs", f"{HOME}/Documents")), grant=GRANT)

    def test_a_helper_refusal_is_explained(self) -> None:
        self.helper.records["Docs"] = {"path": "/elsewhere"}
        self.helper.owned.append("Docs")  # stale ours: unpublish, then publish
        self.helper.share_unpublish = lambda name, *, auth: (_ for _ in ()).throw(  # type: ignore[method-assign]
            HelperError("refused", token="denied")
        )
        with self.assertRaises(ApplyError) as caught:
            self.applier.apply(self.config(share("Docs", f"{HOME}/Documents")), grant=GRANT)
        self.assertIn("expired", caught.exception.detail or "")


class TestWhatSection13Refuses(SharepointCase):
    def refused(self, path: str, facts: PathFacts) -> str:
        self.helper.facts[path] = facts
        with self.assertRaises(ApplyError) as caught:
            self.applier.apply(self.config(share("S", path)), grant=GRANT)
        self.assertEqual(self.helper.calls, [], "nothing may be published")
        return caught.exception.detail or ""

    def test_a_whole_home_says_to_share_a_folder_inside_it(self) -> None:
        detail = self.refused(HOME, PathFacts("home-root", HOME, 501, 20, 0o750, "someone"))
        self.assertIn("whole home folder", detail)
        self.assertNotIn("rule", detail.lower())

    def test_a_path_that_resolves_outside_says_where_it_went(self) -> None:
        detail = self.refused(
            "/Volumes/Macintosh HD", PathFacts("outside-roots", "/", 0, 0, 0o755, "root")
        )
        self.assertIn("resolves to /", detail)

    def test_a_missing_folder_is_not_created_on_macos(self) -> None:
        detail = self.refused(f"{HOME}/Nope", PathFacts("not-found"))
        self.assertIn("create it first", detail)

    def test_a_system_owned_folder(self) -> None:
        detail = self.refused("/Users/Shared", PathFacts("system-owned", "/Users/Shared", 0, 0, 0o1777, "root"))
        self.assertIn("system account", detail)

    def test_read_only_is_refused_until_it_is_measured(self) -> None:
        with self.assertRaises(ApplyError) as caught:
            self.applier.apply(
                self.config(share("Docs", f"{HOME}/Documents", read_only=True)), grant=GRANT
            )
        self.assertIn("read-only", caught.exception.message)
        self.assertEqual(self.helper.calls, [])

    def test_a_disabled_share_may_point_anywhere(self) -> None:
        """Refusal is about what would be published; a disabled share is not."""
        self.helper.facts[HOME] = PathFacts("home-root", HOME, 501, 20, 0o750, "someone")
        self.applier.apply(self.config(share("H", HOME, enabled=False)), grant=GRANT)


class TestPlanning(SharepointCase):
    def test_the_plan_carries_the_refusal_as_the_reason(self) -> None:
        self.helper.facts[HOME] = PathFacts("home-root", HOME, 501, 20, 0o750, "someone")
        [planned] = self.applier.plan(self.config(share("H", HOME)))
        self.assertIn("whole home folder", planned.reason or "")

    def test_an_acl_makes_writability_unknown_rather_than_false(self) -> None:
        """macOS grants access with `chmod +a`, so mode bits are not the answer."""
        self.helper.facts["/Volumes/D"] = PathFacts(
            "ok", "/Volumes/D", 0o7777, 20, 0o700, "nobody-in-particular", has_acl=True
        )
        [planned] = self.applier.plan(
            self.config(share("D", "/Volumes/D", credential_ref="root"))
        )
        self.assertIsNone(planned.status.writable)
        self.assertTrue(planned.status.is_dir)

    def test_planning_never_publishes(self) -> None:
        self.applier.plan(self.config(share("Docs", f"{HOME}/Documents")))
        self.assertEqual(self.helper.calls, [])


class TestTeardown(SharepointCase):
    def test_only_what_smbpal_published_goes(self) -> None:
        self.applier.apply(self.config(share("Docs", f"{HOME}/Documents")), grant=GRANT)
        result = self.applier.teardown(grant=GRANT)
        self.assertEqual(result, {"sharepoints_removed": ["Docs"]})
        self.assertEqual(list(self.helper.records), ["Public"])

    def test_nothing_to_remove_needs_no_grant(self) -> None:
        self.assertEqual(self.applier.teardown(), {"sharepoints_removed": []})


class DispatcherCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = ConfigStore(Path(tmp.name) / "config.json")
        self.helper = FakeHelper()
        self.dispatcher = Dispatcher(
            self.store, applier=SharepointApplier(self.helper)  # type: ignore[arg-type]
        )
        self.peer = PeerCredentials(uid=0, gid=0)

    def request(self, method: str, params: dict[str, object], auth: bytes | None = GRANT) -> Request:
        return Request(id=1, method=method, params=params, auth=auth)


class TestTheDispatcherOnMacOS(DispatcherCase):
    def test_share_add_publishes_with_the_requests_grant(self) -> None:
        self.dispatcher._share_add(
            self.request("share.add", {"name": "Docs", "path": f"{HOME}/Documents"}), self.peer
        )
        self.assertEqual(self.helper.calls, [("publish", "Docs", f"{HOME}/Documents")])
        self.assertEqual(len(self.store.load()["shares"]), 1)

    def test_a_refused_folder_rolls_the_config_back(self) -> None:
        """D12: a config edit the daemon has not applied is a lie."""
        self.helper.facts[HOME] = PathFacts("home-root", HOME, 501, 20, 0o750, "someone")
        with self.assertRaises(ApplyError):
            self.dispatcher._share_add(
                self.request("share.add", {"name": "Home", "path": HOME}), self.peer
            )
        self.assertEqual(self.store.load().get("shares", []), [])


class TestTheUnsupportedMethodsOverTheSocket(ServerTestCase):
    """What a sharepoint applier cannot do yet is refused by name, before any
    prompt -- the same rule as a daemon that cannot serve at all."""

    def make_dispatcher(self) -> Dispatcher:
        return Dispatcher(self.store, applier=SharepointApplier(FakeHelper()))  # type: ignore[arg-type]

    def test_each_is_refused_by_name_and_says_what_to_do_instead(self) -> None:
        client = self.client()
        for method in sorted(SharepointApplier.UNSUPPORTED_METHODS):
            with self.subTest(method=method):
                with self.assertRaises(NotSupported) as caught:
                    client.call(method, {"ref": "x"})
                self.assertIn(method, caught.exception.message)
                self.assertNotIn("Samba", caught.exception.detail or "")


class TestWhatTheDispatcherLeavesAlone(DispatcherCase):
    def test_a_connection_edit_does_not_reconcile_sharepoints(self) -> None:
        """Drift needs a manage-shares grant to fix; a connection edit has the
        other right, and must not fail asking for this one."""
        self.helper.owned.append("Gone")  # ours, removed by hand in Settings
        self.dispatcher._commit({"version": 1, "shares": []}, {"version": 1, "shares": []})
        self.assertEqual(self.helper.calls, [])

    def test_status_survives_a_helper_that_cannot_be_asked(self) -> None:
        def down(_path: str) -> PathFacts:
            raise HelperError("the privileged helper is not running")

        self.helper.path_inspect = down  # type: ignore[method-assign]
        [planned] = self.dispatcher.applier.plan(  # type: ignore[union-attr]
            {"shares": [share("Docs", f"{HOME}/Documents")]}
        )
        self.assertIn("not running", planned.reason or "")
