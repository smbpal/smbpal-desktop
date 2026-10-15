"""Removing a connection unmounts what SMBPal mounted, and nothing else.

15 October 2026: a removed connection's share stayed mounted on a Mac, and an
unconditional unmount would have taken a Finder mount of the same share with
it. So the agent keeps a ledger of the mounts it made (`agent/ledger.py`).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from smbpal.agent.handlers import AgentDispatcher
from smbpal.agent.ledger import MountLedger
from smbpal.errors import SmbpalError
from smbpal.mounts.volumes import SmbMount

ME = 501
URL = "smb://nas.example/Media"


def media(fsid: int, where: str = "/Volumes/Media", uid: int = ME) -> SmbMount:
    return SmbMount("nas.example", "Media", where, uid, fsid=(fsid, 30))


class Table:
    def __init__(self, *mounts: SmbMount) -> None:
        self.mounts = list(mounts)

    def __call__(self) -> list[SmbMount]:
        return list(self.mounts)


class TheLedger(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "mounts.json"

    def test_a_recorded_mount_is_owned_and_survives_a_restart(self) -> None:
        table = Table(media(1))
        MountLedger(self.path, mounts=table).record(media(1))
        again = MountLedger(self.path, mounts=table)
        self.assertTrue(again.owns(media(1)))

    def test_a_remount_at_the_same_path_is_not_ours(self) -> None:
        table = Table(media(1))
        ledger = MountLedger(self.path, mounts=table)
        ledger.record(media(1))
        self.assertFalse(ledger.owns(media(2)))

    def test_a_gone_mount_is_pruned(self) -> None:
        table = Table(media(1))
        ledger = MountLedger(self.path, mounts=table)
        ledger.record(media(1))
        table.mounts = [media(2)]
        ledger.record(media(2))
        self.assertEqual([e["fsid"] for e in json.loads(self.path.read_text())], [[2, 30]])

    def test_an_unreadable_ledger_owns_nothing(self) -> None:
        self.path.write_text("not json")
        self.assertFalse(MountLedger(self.path, mounts=Table(media(1))).owns(media(1)))

    def test_the_file_is_private(self) -> None:
        MountLedger(self.path, mounts=Table(media(1))).record(media(1))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)


class Mounter:
    def __init__(self, table: Table, *, busy: set[str] | None = None) -> None:
        self.table = table
        self.busy = busy or set()
        self.unmounted: list[str] = []
        self.next_fsid = 1

    def mount(self, url: str, **_kw: Any) -> str:
        self.table.mounts.append(media(self.next_fsid))
        self.next_fsid += 1
        return "/Volumes/Media"

    def unmount(self, mountpoint: str, **_kw: Any) -> bool:
        if mountpoint in self.busy:
            raise SmbpalError("the volume is in use")
        self.unmounted.append(mountpoint)
        self.table.mounts = [m for m in self.table.mounts if m.mountpoint != mountpoint]
        return True


def release(dispatcher: AgentDispatcher) -> dict[str, Any]:
    from smbpal.ipc.protocol import Request

    return dispatcher._release(Request(id="1", method="agent.release", params={"url": URL}))


class Release(unittest.TestCase):
    def test_what_smbpal_mounted_is_unmounted(self) -> None:
        table = Table()
        mounter = Mounter(table)
        dispatcher = AgentDispatcher(uid=ME, mounter=mounter, mounts=table)
        dispatcher.mount_url(URL)
        result = release(dispatcher)
        self.assertEqual(result["unmounted"], ["/Volumes/Media"])
        self.assertEqual(result["left"], [])

    def test_a_finder_mount_of_the_same_share_is_left(self) -> None:
        table = Table(media(9))
        mounter = Mounter(table)
        dispatcher = AgentDispatcher(uid=ME, mounter=mounter, mounts=table)
        result = release(dispatcher)
        self.assertEqual(mounter.unmounted, [])
        self.assertEqual(result["left"], [{"mountpoint": "/Volumes/Media", "reason": "not-ours"}])

    def test_reusing_a_finder_mount_does_not_make_it_ours(self) -> None:
        table = Table(media(9))
        mounter = Mounter(table)
        dispatcher = AgentDispatcher(uid=ME, mounter=mounter, mounts=table)
        self.assertTrue(dispatcher.mount_url(URL)["already"])
        release(dispatcher)
        self.assertEqual(mounter.unmounted, [])

    def test_a_busy_mount_is_left_and_said(self) -> None:
        table = Table()
        mounter = Mounter(table, busy={"/Volumes/Media"})
        dispatcher = AgentDispatcher(uid=ME, mounter=mounter, mounts=table)
        dispatcher.mount_url(URL)
        result = release(dispatcher)
        self.assertEqual(result["left"][0]["reason"], "busy")

    def test_another_users_mount_is_not_considered(self) -> None:
        table = Table(media(9, uid=502))
        dispatcher = AgentDispatcher(uid=ME, mounter=Mounter(table), mounts=table)
        self.assertEqual(release(dispatcher), {"url": URL, "unmounted": [], "left": []})


if __name__ == "__main__":
    unittest.main()
