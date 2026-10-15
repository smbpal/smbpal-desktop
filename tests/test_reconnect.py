"""The macOS reconnect loop: what it puts back, and what it leaves alone.

Everything the loop touches is injected — the daemon's list, the mount table,
the mount itself and both clocks — so the decisions are tested here on Linux,
where CI runs, and the mechanisms (`getfsstat`, kqueue, NetFS) are measured on
a Mac instead.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from smbpal.agent.handlers import AgentDispatcher
from smbpal.agent.reconnect import (
    FAST_BACKOFF,
    MAX_BACKOFF,
    SLEEP_GAP,
    SLOW_ATTEMPT,
    TROUBLE_WINDOW,
    Reconnector,
)
from smbpal.errors import SmbpalError
from smbpal.ipc.peer import PeerCredentials
from smbpal.mounts import volumes
from smbpal.mounts.netfs import NetFSError, smb_url
from smbpal.mounts.volumes import SmbMount, mount_key, parse_from_name

ME = 501


def encode_request(request_id: int, method: str, params: dict[str, Any]) -> bytes:
    return json.dumps(
        {"v": 1, "id": str(request_id), "method": method, "params": params}
    ).encode() + b"\n"


def connection(**overrides: Any) -> dict[str, Any]:
    base = {
        "id": "nas-media",
        "host": "nas.example",
        "share": "Media",
        "owner": "alice",
        "auto_connect": "on_this_network",
        "credential_account": "alice",
    }
    base.update(overrides)
    return base


class Harness:
    """A Reconnector with every input in reach of the test."""

    def __init__(self, connections: list[dict[str, Any]] | None = None) -> None:
        self.connections = [connection()] if connections is None else connections
        self.table: list[SmbMount] = []
        self.mounted: list[str] = []
        self.fail_with: SmbpalError | None = None
        self.list_fails = False
        self.mount_takes = 0.0
        self.wall = 1_000_000.0
        self.mono = 100.0
        self.loop = Reconnector(
            uid=ME,
            username="alice",
            connections=self._list,
            mount=self._mount,
            mounts=lambda: list(self.table),
            interval=5.0,
            wall=lambda: self.wall,
            monotonic=lambda: self.mono,
        )

    def _list(self) -> list[dict[str, Any]]:
        if self.list_fails:
            raise SmbpalError("no SMBPal daemon is listening")
        return list(self.connections)

    def _mount(self, record: dict[str, Any]) -> str:
        self.mounted.append(record["id"])
        # How long the attempt takes, on the loop's own clock.
        self.mono += self.mount_takes
        if self.fail_with is not None:
            raise self.fail_with
        where = f"/Volumes/{record['share']}"
        self.table.append(
            SmbMount(record["host"], record["share"], where, owner_uid=ME)
        )
        return where

    def advance(self, seconds: float, *, slept: float = 0.0) -> None:
        self.mono += seconds
        self.wall += seconds + slept

    def drop(self) -> None:
        self.table.clear()

    def tick(self, flags: int = 0) -> None:
        self.advance(5.0)
        self.loop.tick(flags)


class Priming(unittest.TestCase):
    def test_an_unmounted_connection_is_mounted_on_the_first_pass(self) -> None:
        h = Harness()
        h.tick()
        self.assertEqual(h.mounted, ["nas-media"])

    def test_one_already_mounted_is_left_alone(self) -> None:
        h = Harness()
        h.table.append(SmbMount("NAS.example", "media", "/Volumes/media", ME))
        h.tick()
        self.assertEqual(h.mounted, [])

    def test_another_persons_connection_is_not_ours_to_mount(self) -> None:
        h = Harness([connection(owner="bob")])
        h.tick()
        self.assertEqual(h.mounted, [])

    def test_someone_elses_mount_of_the_same_share_does_not_count(self) -> None:
        h = Harness()
        h.table.append(SmbMount("nas.example", "Media", "/Volumes/Media", 502))
        h.tick()
        self.assertEqual(h.mounted, ["nas-media"])

    def test_never_means_never(self) -> None:
        h = Harness([connection(auto_connect="never")])
        h.tick()
        self.assertEqual(h.mounted, [])

    def test_on_this_network_is_attempted_since_macos_cannot_probe(self) -> None:
        h = Harness([connection(auto_connect="on_this_network")])
        h.tick()
        self.assertEqual(h.mounted, ["nas-media"])


class EjectOrLost(unittest.TestCase):
    def mounted_harness(self) -> Harness:
        h = Harness()
        h.tick()
        h.tick()
        self.assertEqual(h.mounted, ["nas-media"])
        return h

    def test_an_unexplained_disappearance_is_an_eject_and_is_respected(self) -> None:
        h = self.mounted_harness()
        h.drop()
        h.tick()
        h.tick()
        self.assertEqual(h.mounted, ["nas-media"])

    def test_a_disappearance_across_a_sleep_is_put_back(self) -> None:
        h = self.mounted_harness()
        h.drop()
        h.advance(0.0, slept=SLEEP_GAP + 600)
        h.tick()
        self.assertEqual(h.mounted, ["nas-media", "nas-media"])

    def test_a_mount_dropped_minutes_after_waking_is_still_put_back(self) -> None:
        h = self.mounted_harness()
        h.advance(0.0, slept=3600)
        h.tick()  # woke; still mounted
        h.advance(120)
        h.drop()
        h.tick()
        self.assertEqual(h.mounted, ["nas-media", "nas-media"])

    def test_scheduling_jitter_is_not_a_sleep(self) -> None:
        h = self.mounted_harness()
        h.drop()
        h.advance(0.0, slept=SLEEP_GAP - 1)
        h.tick()
        self.assertEqual(h.mounted, ["nas-media"])

    def test_a_not_responding_report_explains_the_loss(self) -> None:
        h = self.mounted_harness()
        h.tick(volumes.VQ_NOTRESP)
        h.advance(60)
        h.drop()
        h.tick()
        self.assertEqual(h.mounted, ["nas-media", "nas-media"])

    def test_a_report_long_past_explains_nothing(self) -> None:
        h = self.mounted_harness()
        h.tick(volumes.VQ_DEAD)
        h.advance(TROUBLE_WINDOW + 1)
        h.drop()
        h.tick()
        self.assertEqual(h.mounted, ["nas-media"])

    def test_a_mount_or_unmount_event_is_not_trouble(self) -> None:
        h = self.mounted_harness()
        h.drop()
        h.tick(volumes.VQ_UNMOUNT | volumes.VQ_MOUNT)
        self.assertEqual(h.mounted, ["nas-media"])

    def test_an_eject_ends_when_somebody_mounts_it_again_by_hand(self) -> None:
        h = self.mounted_harness()
        h.drop()
        h.tick()  # held as an eject
        h.table.append(SmbMount("nas.example", "Media", "/Volumes/Media", ME))
        h.tick()  # Finder mounted it
        h.drop()
        h.advance(0.0, slept=3600)
        h.tick()
        self.assertEqual(h.mounted, ["nas-media", "nas-media"])


class Failures(unittest.TestCase):
    def test_a_refused_credential_is_never_retried(self) -> None:
        h = Harness()
        h.fail_with = NetFSError("refused", status=80, retryable=False)
        h.tick()
        for _ in range(5):
            h.advance(MAX_BACKOFF)
            h.tick()
        self.assertEqual(h.mounted, ["nas-media"])

    def test_a_temporary_failure_backs_off_and_then_retries(self) -> None:
        h = Harness()
        h.fail_with = NetFSError("no route", status=65, retryable=True)
        h.tick()  # attempt 1 fails: next try 10 s later
        h.loop.tick()  # same instant: too soon
        self.assertEqual(h.mounted, ["nas-media"])
        h.fail_with = None
        h.advance(10.0)
        h.loop.tick()
        self.assertEqual(h.mounted, ["nas-media", "nas-media"])

    def test_backoff_is_capped(self) -> None:
        h = Harness()
        h.fail_with = NetFSError("no route", status=65, retryable=True)
        for _ in range(12):
            h.advance(MAX_BACKOFF)
            h.loop.tick()
        self.assertEqual(len(h.mounted), 12)

    def test_an_error_that_is_not_netfs_is_treated_as_temporary(self) -> None:
        h = Harness()
        h.fail_with = SmbpalError("the Keychain is locked")
        h.tick()
        h.fail_with = None
        h.advance(MAX_BACKOFF)
        h.loop.tick()
        self.assertEqual(h.mounted, ["nas-media", "nas-media"])

    def test_a_netfs_error_without_a_status_is_not_retried(self) -> None:
        self.assertFalse(NetFSError("that is not a URL SMBPal can mount").retryable)


class AskedForThroughSmbpal(unittest.TestCase):
    def test_a_disconnect_is_held_even_across_a_sleep(self) -> None:
        h = Harness()
        h.tick()
        h.tick()
        h.loop.released("/Volumes/Media")
        h.drop()
        h.advance(0.0, slept=3600)
        h.tick()
        self.assertEqual(h.mounted, ["nas-media"])

    def test_a_disconnect_of_a_mount_that_had_already_dropped_holds(self) -> None:
        h = Harness()
        h.tick()
        h.tick()
        h.drop()
        h.tick(volumes.VQ_NOTRESP)  # lost; reconnects at once
        h.drop()
        h.loop.released("/Volumes/Media")
        h.advance(0.0, slept=3600)
        h.tick()
        self.assertEqual(h.mounted.count("nas-media"), 2)

    def test_a_connect_clears_a_hold(self) -> None:
        h = Harness()
        h.tick()
        h.tick()
        h.loop.released("/Volumes/Media")
        h.drop()
        h.tick()
        h.loop.connected("smb://nas.example/Media", "/Volumes/Media")
        h.advance(0.0, slept=3600)
        h.tick()  # the connect's mount is not in the table: it dropped again
        self.assertEqual(h.mounted, ["nas-media", "nas-media"])

    def test_the_agents_own_methods_tell_the_loop(self) -> None:
        class Mounter:
            def mount(self, url: str, **_kw: Any) -> str:
                return "/Volumes/Media"

            def unmount(self, mountpoint: str, **_kw: Any) -> bool:
                return False

        class Seen:
            def __init__(self) -> None:
                self.calls: list[tuple[str, ...]] = []

            def connected(self, url: str, where: str) -> None:
                self.calls.append(("connected", url, where))

            def released(self, where: str) -> None:
                self.calls.append(("released", where))

        class Conn:
            peer = PeerCredentials(uid=ME, gid=20)

        dispatcher = AgentDispatcher(uid=ME, mounter=Mounter())
        dispatcher.reconnector = seen = Seen()
        dispatcher.handle(Conn(), encode_request(1, "agent.mount", {"url": "smb://h/S"}))
        dispatcher.handle(
            Conn(), encode_request(2, "agent.unmount", {"mountpoint": "/Volumes/S"})
        )
        self.assertEqual(
            seen.calls,
            [("connected", "smb://h/S", "/Volumes/Media"), ("released", "/Volumes/S")],
        )


class TheList(unittest.TestCase):
    def test_a_daemon_restarting_does_not_empty_the_list(self) -> None:
        h = Harness()
        h.tick()
        h.list_fails = True
        h.drop()
        h.advance(0.0, slept=3600)
        h.tick()
        self.assertEqual(h.mounted, ["nas-media", "nas-media"])

    def test_a_removed_connection_is_forgotten(self) -> None:
        h = Harness()
        h.tick()
        h.connections = []
        h.tick()
        self.assertEqual(h.loop._tracks, {})

    def test_repointing_a_connection_makes_it_new(self) -> None:
        h = Harness()
        h.tick()
        h.tick()
        h.loop.released("/Volumes/Media")
        h.connections = [connection(share="Photos")]
        h.tick()
        self.assertEqual(h.mounted, ["nas-media", "nas-media"])


class MountTable(unittest.TestCase):
    def test_from_name_with_a_user(self) -> None:
        self.assertEqual(parse_from_name("//alice@nas.example/Media"), ("nas.example", "Media"))

    def test_from_name_for_a_guest(self) -> None:
        self.assertEqual(parse_from_name("//nas.example/Media"), ("nas.example", "Media"))

    def test_from_name_with_a_domain_and_an_encoded_space(self) -> None:
        self.assertEqual(
            parse_from_name("//WORK;alice@nas.example/My%20Share"),
            ("nas.example", "My Share"),
        )

    def test_from_name_that_is_not_smb(self) -> None:
        self.assertIsNone(parse_from_name("/dev/disk3s1"))
        self.assertIsNone(parse_from_name("//nas.example/"))

    def test_keys_ignore_case_and_brackets(self) -> None:
        self.assertEqual(mount_key("[2001:DB8::1]", "Media"), mount_key("2001:db8::1", "media"))

    def test_the_url_and_the_key_agree(self) -> None:
        url = smb_url("nas.example", "My Share")
        self.assertEqual(url, "smb://nas.example/My%20Share")
        h = Harness([connection(share="My Share")])
        h.tick()
        h.tick()
        h.loop.released("/Volumes/My Share")
        h.loop.connected(url, "/Volumes/My Share")
        self.assertIsNone(h.loop._tracks["nas-media"].held)

    def test_off_macos_the_table_is_empty_and_events_just_wait(self) -> None:
        if volumes.available():
            self.skipTest("this is a Mac")
        self.assertEqual(volumes.smb_mounts(), [])
        self.assertEqual(volumes.VolumeEvents().wait(0.01), 0)


if __name__ == "__main__":
    unittest.main()


class FoundReinstallingTheAgent(unittest.TestCase):
    """15 October 2026: a disconnect forgotten on restart, and a second copy."""

    def test_a_recorded_disconnect_survives_a_fresh_agent(self) -> None:
        h = Harness([connection(disconnected=True)])
        h.tick()
        h.advance(0.0, slept=3600)
        h.tick()
        self.assertEqual(h.mounted, [])

    def test_a_recorded_disconnect_does_not_unmount_what_finder_mounted(self) -> None:
        h = Harness([connection(disconnected=True)])
        h.table.append(SmbMount("nas.example", "Media", "/Volumes/Media", ME))
        h.tick()
        self.assertEqual(h.loop._tracks["nas-media"].mounted_at, "/Volumes/Media")

    def test_an_existing_mount_is_answered_not_mounted_again(self) -> None:
        class Mounter:
            def __init__(self) -> None:
                self.calls = 0

            def mount(self, url: str, **_kw: Any) -> str:
                self.calls += 1
                return "/Volumes/Code-1"

        mounter = Mounter()
        dispatcher = AgentDispatcher(
            uid=ME,
            mounter=mounter,
            mounts=lambda: [SmbMount("NAS.example", "code", "/Volumes/Code", ME)],
        )
        result = dispatcher.mount_url("smb://nas.example/Code")
        self.assertEqual(result["mountpoint"], "/Volumes/Code")
        self.assertTrue(result["already"])
        self.assertEqual(mounter.calls, 0)

    def test_another_users_mount_is_not_ours_to_reuse(self) -> None:
        class Mounter:
            def mount(self, url: str, **_kw: Any) -> str:
                return "/Volumes/Code-1"

        dispatcher = AgentDispatcher(
            uid=ME,
            mounter=Mounter(),
            mounts=lambda: [SmbMount("nas.example", "Code", "/Volumes/Code", 502)],
        )
        self.assertEqual(
            dispatcher.mount_url("smb://nas.example/Code")["mountpoint"], "/Volumes/Code-1"
        )


class DisconnectFindsTheShare(unittest.TestCase):
    """15 October 2026: the record said `/Volumes/Code-1`, Code was at `/Volumes/Code`."""

    def setUp(self) -> None:
        self.unmounted: list[str] = []
        unmounted = self.unmounted

        class Mounter:
            def unmount(self, mountpoint: str, **_kw: Any) -> bool:
                unmounted.append(mountpoint)
                return True

        self.table = [
            SmbMount("nas.example", "Code", "/Volumes/Code", ME),
            SmbMount("nas.example", "Code", "/Volumes/Code-2", ME),
            SmbMount("nas.example", "Code", "/Volumes/Code-9", 502),
        ]
        self.dispatcher = AgentDispatcher(
            uid=ME, mounter=Mounter(), mounts=lambda: list(self.table)
        )

    def unmount(self, **params: Any) -> dict[str, Any]:
        reply = self.dispatcher.handle(
            type("Conn", (), {"peer": PeerCredentials(uid=ME, gid=20)})(),
            encode_request(1, "agent.unmount", params),
        )
        assert reply is not None
        return json.loads(reply)["result"]

    def test_a_stale_mountpoint_does_not_hide_the_mount(self) -> None:
        result = self.unmount(
            mountpoint="/Volumes/Code-1", url="smb://nas.example/Code"
        )
        self.assertTrue(result["unmounted"])
        self.assertEqual(sorted(self.unmounted), ["/Volumes/Code", "/Volumes/Code-2"])

    def test_without_a_url_the_mountpoint_is_used_as_before(self) -> None:
        self.unmount(mountpoint="/Volumes/Code-1")
        self.assertEqual(self.unmounted, ["/Volumes/Code-1"])

    def test_nothing_of_that_share_mounted_falls_back_to_the_mountpoint(self) -> None:
        self.table.clear()
        self.unmount(mountpoint="/Volumes/Code", url="smb://nas.example/Code")
        self.assertEqual(self.unmounted, ["/Volumes/Code"])


class WhatAPersonIsShown(unittest.TestCase):
    """The states the loop reports, in `state/machine.py`'s words."""

    def harness(self, **overrides: Any) -> tuple[Harness, list[list[dict[str, Any]]]]:
        h = Harness([connection(**overrides)])
        reports: list[list[dict[str, Any]]] = []
        h.loop.on_states = reports.append
        return h, reports

    def last(self, reports: list[list[dict[str, Any]]]) -> dict[str, Any]:
        return reports[-1][0]

    def test_mounted_is_connected_with_where(self) -> None:
        h, reports = self.harness()
        h.tick()
        self.assertEqual(self.last(reports)["state"], "connected")
        self.assertEqual(self.last(reports)["mountpoint"], "/Volumes/Media")

    def test_a_report_is_sent_when_something_changes_and_not_otherwise(self) -> None:
        h, reports = self.harness()
        h.tick()
        h.tick()
        h.tick()
        self.assertEqual(len(reports), 1)

    def test_an_eject_is_calm_and_says_so(self) -> None:
        h, reports = self.harness()
        h.tick()
        h.drop()
        h.tick()
        self.assertEqual(self.last(reports)["state"], "idle")
        self.assertIn("ejected", self.last(reports)["message"])

    def test_a_disconnect_is_calm_and_says_so(self) -> None:
        h, reports = self.harness(disconnected=True)
        h.tick()
        self.assertEqual(self.last(reports)["state"], "idle")
        self.assertIn("disconnected", self.last(reports)["message"])

    def test_never_is_disabled(self) -> None:
        h, reports = self.harness(auto_connect="never")
        h.tick()
        self.assertEqual(self.last(reports)["state"], "disabled")

    def test_a_refused_password_is_auth_failed(self) -> None:
        h, reports = self.harness()
        h.fail_with = NetFSError("refused", status=80, retryable=False, state="auth_failed")
        h.tick()
        self.assertEqual(self.last(reports)["state"], "auth_failed")
        self.assertFalse(self.last(reports)["retryable"])

    def test_an_unreachable_server_keeps_its_word_and_is_retried(self) -> None:
        h, reports = self.harness()
        h.fail_with = NetFSError("no route", status=65, retryable=True, state="unreachable")
        h.tick()
        self.assertEqual(self.last(reports)["state"], "unreachable")
        self.assertTrue(self.last(reports)["retryable"])

    def test_another_temporary_failure_is_reconnecting(self) -> None:
        h, reports = self.harness()
        h.fail_with = NetFSError("odd", status=-5000, retryable=True, state="failed")
        h.tick()
        self.assertEqual(self.last(reports)["state"], "reconnecting")

    def test_every_reported_state_is_one_the_machine_knows(self) -> None:
        from smbpal.state.machine import STATES

        for overrides in ({}, {"disconnected": True}, {"auto_connect": "never"}):
            h, reports = self.harness(**overrides)
            h.tick()
            self.assertIn(self.last(reports)["state"], STATES)


class TheLagWhenAServerComesBack(unittest.TestCase):
    """0.2.15 could wait five minutes to remount a NAS that had come back."""

    def unreachable(self) -> NetFSError:
        return NetFSError("no route", status=65, retryable=True, state="unreachable")

    def wait_for(self, h: Harness) -> float:
        return h.loop._tracks["nas-media"].next_try - h.mono

    def test_fast_failures_never_wait_longer_than_the_short_cap(self) -> None:
        h = Harness()
        h.fail_with = self.unreachable()
        for _ in range(10):
            h.advance(MAX_BACKOFF)
            h.loop.tick()
        self.assertLessEqual(self.wait_for(h), FAST_BACKOFF)

    def test_slow_failures_still_back_off_to_the_long_cap(self) -> None:
        h = Harness()
        h.fail_with = self.unreachable()
        h.mount_takes = SLOW_ATTEMPT + 1
        for _ in range(10):
            h.advance(MAX_BACKOFF)
            h.loop.tick()
        self.assertGreater(self.wait_for(h), FAST_BACKOFF)

    def test_a_network_change_retries_at_once(self) -> None:
        h = Harness()
        h.fail_with = self.unreachable()
        for _ in range(5):
            h.advance(FAST_BACKOFF)
            h.loop.tick()
        attempts = len(h.mounted)
        h.fail_with = None
        h.advance(1.0)
        h.loop.tick(volumes.NETWORK_CHANGED)
        self.assertEqual(len(h.mounted), attempts + 1)
        self.assertEqual(h.loop._tracks["nas-media"].status[0], "connected")

    def test_without_a_change_the_backoff_is_waited_out(self) -> None:
        h = Harness()
        h.fail_with = self.unreachable()
        for _ in range(5):
            h.advance(FAST_BACKOFF)
            h.loop.tick()
        attempts = len(h.mounted)
        h.advance(1.0)
        h.loop.tick()
        self.assertEqual(len(h.mounted), attempts)

    def test_a_wake_retries_at_once_and_for_a_little_while(self) -> None:
        h = Harness()
        h.fail_with = self.unreachable()
        for _ in range(5):
            h.advance(FAST_BACKOFF)
            h.loop.tick()
        attempts = len(h.mounted)
        h.advance(1.0, slept=3600)
        h.loop.tick()
        h.advance(5.0)
        h.loop.tick()
        self.assertEqual(len(h.mounted), attempts + 2)

    def test_a_network_change_does_not_undo_a_disconnect(self) -> None:
        h = Harness([connection(disconnected=True)])
        h.tick()
        h.loop.tick(volumes.NETWORK_CHANGED)
        self.assertEqual(h.mounted, [])


class ALongOutageLeavesATrace(unittest.TestCase):
    def test_retries_are_logged_about_once_a_minute(self) -> None:
        h = Harness()
        h.fail_with = NetFSError("no route", status=65, retryable=True, state="unreachable")
        with self.assertLogs("smbpal.agent.reconnect", level="INFO") as logs:
            for _ in range(20):  # ten minutes of 30 s retries
                h.advance(30.0)
                h.loop.tick()
        still = [line for line in logs.output if "still retrying" in line]
        self.assertGreaterEqual(len(still), 8)
        self.assertLessEqual(len(still), 11)
        self.assertIn("attempt", still[-1])
