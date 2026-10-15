"""Putting this person's connections back when macOS lets them go.

**macOS has no reconnect story for SMB** (porting surface §6.8): a server going
away is terminal for the mount, and sleep or a network change goes the same
way. §6.8 called the health-check loop *the reason for D13's agent to exist at
all*. This is that loop.

**It runs in the agent, not the daemon, and that was not the first plan.** The
daemon runs as `_smbpald` since the helper work (helper spike §9), and the
agent's socket is `0600` inside a `0700` directory in the person's home, and
admits only its owner and root. So a daemon-driven loop could not reach any
agent at all. Run here instead, the loop needs nothing new from anyone: it
reads `connection.list` from the daemon's socket like any member of the
`smbpal` group, mounts in its own session, and reads the credential from its
own Keychain. The password never leaves the session, and no account gains a way
into it.

**What it does, every tick** (5 s, or at once when the kernel says a volume
came or went):

- reads the connections whose `owner` is this person, keeping the last list if
  the daemon is restarting;
- reads the mount table without blocking (`mounts/volumes.py`);
- mounts any of them that is not mounted, unless something below says not to.

The first pass after the agent starts is the macOS form of the Linux monitor's
*priming*: at login, after a reboot, every connection set to connect
automatically is mounted.

**What stops it.**

- **`auto_connect: never`.** Never mounted except on request.
- **A disconnect asked for through SMBPal.** The agent performs it, so it knows.
  Held until a `connect`.
- **An eject — or what looks like one.** A mount that disappears while nothing
  suggests the server went away is taken as a person's choice, and mounting it
  straight back would be arguing with them: the Linux monitor's rule, for the
  same reason. *Something suggests the server went away* means either **the Mac
  slept** across the gap — `time.monotonic` is `mach_absolute_time` here, which
  stops during sleep, so a wall clock that ran ahead of it measures the sleep —
  or **the kernel reported a volume not responding** (`VQ_NOTRESP`/`VQ_DEAD`)
  in the last few minutes. **This is the part not yet measured against a real
  server**: whether a server going away raises those flags before macOS drops
  the mount is the question the hardware run answers. Until then a loss the
  loop cannot explain is held, not retried — the safe direction, since the
  failure is a mount that does not come back, which is today's behaviour.
- **A refused credential.** Never retried, because retrying one is how
  accounts get locked out (§4). Anything temporary is retried with backoff,
  doubling from the interval to five minutes.

**`on_this_network` behaves as `always` here, and has to.** The Linux monitor
asks port 445 first; on macOS that probe is refused by the Local Network
privacy gate before it reaches the network (`probe.can_probe`), so the loop
asks NetFS instead, whose answer for a server that is not on this network is a
retryable failure — and the backoff is what keeps that from being a mount
attempt every five seconds.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from smbpal.errors import SmbpalError
from smbpal.mounts import volumes
from smbpal.mounts.netfs import NetFSError
from smbpal.state.machine import (
    AUTH_FAILED,
    CONNECTED,
    DISABLED,
    FAILED,
    IDLE,
    RECONNECTING,
    UNKNOWN,
    UNREACHABLE,
)

log = logging.getLogger(__name__)

DEFAULT_INTERVAL = 5.0
# **Two caps, chosen by how long a failed attempt took.** A server that is off
# usually fails fast -- no route, a name that does not resolve -- and trying
# that every 30 s costs nothing. The five-minute cap of 0.2.15 is what made a
# NAS that came back wait up to five minutes to be remounted, measured on
# 15 October 2026. An attempt that itself took long, a connect timing out,
# holds the loop for that long, so those still back off to five minutes.
FAST_BACKOFF = 30.0
MAX_BACKOFF = 300.0
SLOW_ATTEMPT = 5.0
# How long a not-responding report from the kernel explains a disappearance.
# Generous on purpose: the report comes when the server stops answering, and
# macOS may drop the mount minutes later, after its own dialog times out.
TROUBLE_WINDOW = 600.0
# A wall clock that ran this much further than the monotonic one means the Mac
# slept. Well above any scheduling jitter, well below any real sleep.
SLEEP_GAP = 30.0
# After a wake, how long every pass retries a waiting connection at once.
RETRY_AFTER_WAKE = 30.0
# How often a connection that keeps failing says so. Without it, a failure was
# logged once when its message first appeared, and a run on 15 October 2026
# could not tell whether retries were still happening, or when one succeeded
# relative to the server returning.
RETRY_LOG_EVERY = 60.0

Connections = Callable[[], list[dict[str, Any]]]
Mount = Callable[[dict[str, Any]], str]
States = Callable[[list[dict[str, Any]]], None]

# The words a person is shown for a share the loop is deliberately leaving
# alone. `idle`, not a problem: on macOS a disconnected share is a choice, and
# `smbpal connection connect` or the window's Connect undoes it.
_DISCONNECTED = (
    IDLE,
    "disconnected; it stays disconnected until you connect it",
    False,
)
_EJECTED = (
    IDLE,
    "ejected; it stays disconnected until you connect it",
    False,
)


@dataclass
class _Track:
    key: tuple[str, str]
    mounted_at: str | None = None
    # Where it was last mounted, kept after it goes: a disconnect for a mount
    # that has already dropped names this path, and must still be honoured.
    last_at: str | None = None
    # Why it will not be mounted until somebody connects it, or None.
    held: str | None = None
    failures: int = 0
    next_try: float = 0.0
    # What was last logged about it, so a line is written when it changes and
    # not every five seconds.
    said: str | None = None
    # What a person is shown: `(state, message, retryable)` in the words of
    # `state/machine.py`, reported to the daemon whenever it changes.
    status: tuple[str, str, bool] = (UNKNOWN, "not checked yet", False)
    # The status that goes with `held`, which is not always the same kind of
    # thing: an eject is calm, a refused password is a problem.
    held_status: tuple[str, str, bool] | None = None
    # When "still retrying" was last logged, so a long outage leaves a trace
    # about once a minute rather than one line at its start.
    retry_logged: float = float("-inf")


class Reconnector:
    def __init__(
        self,
        *,
        uid: int,
        username: str,
        connections: Connections,
        mount: Mount,
        mounts: Callable[[], list[volumes.SmbMount]] = volumes.smb_mounts,
        events: Any = None,
        interval: float = DEFAULT_INTERVAL,
        wall: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        on_states: States | None = None,
    ) -> None:
        self.uid = uid
        self.username = username
        self._connections = connections
        self._mount = mount
        self._mounts = mounts
        self.events = events
        self.interval = interval
        self._wall = wall
        self._monotonic = monotonic
        self._tracks: dict[str, _Track] = {}
        self._last_list: list[dict[str, Any]] = []
        self._list_problem: str | None = None
        self._trouble_until = float("-inf")
        self._retry_now_until = float("-inf")
        self._last_clocks: tuple[float, float] | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Told the whole list when any of it changes; see `states`.
        self.on_states = on_states
        self._reported: list[dict[str, Any]] | None = None

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        if self.events is None:
            self.events = volumes.VolumeEvents()
        self._thread = threading.Thread(
            target=self._loop, name="smbpal-reconnect", daemon=True
        )
        self._thread.start()
        log.info("reconnecting %s's connections, checking every %gs",
                 self.username, self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 2)
            self._thread = None

    def _loop(self) -> None:
        flags = 0
        while not self._stop.is_set():
            try:
                self.tick(flags)
            except Exception:  # noqa: BLE001 - a loop that dies is worse
                log.exception("reconnect pass failed; continuing")
            flags = self.events.wait(self.interval)

    # --- what the agent's own methods tell it ------------------------------

    def released(self, mountpoint: str) -> None:
        """A disconnect asked for through SMBPal: hold it until a connect."""
        with self._lock:
            for track in self._tracks.values():
                if mountpoint in (track.mounted_at, track.last_at):
                    track.mounted_at = None
                    track.held = (
                        "it was disconnected through SMBPal; "
                        "`smbpal connection connect` brings it back"
                    )
                    track.held_status = _DISCONNECTED

    def connected(self, url: str, mountpoint: str) -> None:
        """A connect asked for through SMBPal: whatever held it, no longer."""
        key = volumes.key_for_url(url)
        with self._lock:
            for track in self._tracks.values():
                if track.key == key:
                    track.mounted_at = track.last_at = mountpoint
                    track.held = None
                    track.held_status = None
                    track.failures = 0
                    track.next_try = 0.0

    # --- one pass ----------------------------------------------------------

    def tick(self, flags: int = 0) -> None:
        now = self._monotonic()
        # Either opens the same window. macOS can drop a mount well after the
        # wake or the report — its own dialog has a timeout — so the first
        # pass after the event is too narrow a test.
        if self._slept(now):
            self._trouble_until = max(self._trouble_until, now + TROUBLE_WINDOW)
            # Retry at once on this pass, and on the next few: the network
            # can take some seconds to come up after a wake.
            self._retry_now_until = now + RETRY_AFTER_WAKE
        if flags & volumes.VQ_TROUBLE:
            self._trouble_until = max(self._trouble_until, now + TROUBLE_WINDOW)
            log.info("the kernel reported a volume not responding (flags %#x)", flags)
        # A network change or a wake is when a waiting connection is most
        # likely to succeed, so neither waits out its backoff. A sleep also
        # stops `time.monotonic`, so a backoff set before it would otherwise
        # run on after the wake.
        if flags & volumes.NETWORK_CHANGED or now < self._retry_now_until:
            if flags & volumes.NETWORK_CHANGED:
                log.info("the network changed; retrying waiting connections now")
            self._retry_waiting()
        trouble = now < self._trouble_until

        mine = [c for c in self._read_connections() if c.get("owner") == self.username]
        table = {
            m.key: m for m in self._mounts() if m.owner_uid == self.uid
        }
        seen: set[str] = set()
        for connection in mine:
            connection_id = str(connection.get("id"))
            seen.add(connection_id)
            self._consider(connection, table, now, trouble)
        with self._lock:
            for gone in set(self._tracks) - seen:
                del self._tracks[gone]
        self._report()

    def states(self) -> list[dict[str, Any]]:
        """Every connection's state, as `connection.watch` rows."""
        with self._lock:
            return [
                {
                    "id": connection_id,
                    "state": track.status[0],
                    "message": track.status[1],
                    "retryable": track.status[2],
                    "mountpoint": track.mounted_at,
                }
                for connection_id, track in sorted(self._tracks.items())
            ]

    def _report(self) -> None:
        """Hand the list on when it has changed, and only then."""
        current = self.states()
        if current == self._reported or self.on_states is None:
            return
        self._reported = current
        try:
            self.on_states(current)
        except Exception:  # noqa: BLE001 - reporting must not stop reconnecting
            log.exception("could not report connection states")

    def _retry_waiting(self) -> None:
        """Clear the backoff of every connection that is waiting to retry."""
        with self._lock:
            for track in self._tracks.values():
                if track.held is None and track.mounted_at is None:
                    track.next_try = 0.0

    def _consider(
        self,
        connection: dict[str, Any],
        table: dict[tuple[str, str], volumes.SmbMount],
        now: float,
        trouble: bool,
    ) -> None:
        connection_id = str(connection["id"])
        key = volumes.mount_key(str(connection.get("host", "")),
                                str(connection.get("share", "")))
        with self._lock:
            track = self._tracks.get(connection_id)
            if track is None or track.key != key:
                # New, or edited to point somewhere else: a new connection.
                track = self._tracks[connection_id] = _Track(key=key)

            mounted = table.get(key)
            if mounted is not None:
                if track.mounted_at != mounted.mountpoint:
                    self._say(track, connection_id, f"mounted at {mounted.mountpoint}")
                track.mounted_at = track.last_at = mounted.mountpoint
                # Mounted by anyone — this loop, Finder, `smbpal connect` — is
                # a mount somebody wanted, and whatever held it is over.
                track.held = None
                track.held_status = None
                track.failures = 0
                track.next_try = 0.0
                track.status = (CONNECTED, f"mounted at {mounted.mountpoint}", False)
                return

            if track.mounted_at is not None:
                gone_from = track.mounted_at
                track.mounted_at = None
                if trouble:
                    self._say(
                        track,
                        connection_id,
                        f"lost from {gone_from} after the Mac slept or a server "
                        "stopped responding; reconnecting",
                    )
                    track.status = (
                        RECONNECTING,
                        "the connection was lost; SMBPal is reconnecting",
                        True,
                    )
                else:
                    track.held = (
                        f"it was unmounted from {gone_from} while nothing said its "
                        "server had gone, which is how an eject looks; "
                        "`smbpal connection connect` brings it back"
                    )
                    track.held_status = _EJECTED

            if connection.get("disconnected"):
                # Recorded by the daemon, so it survives this agent restarting.
                # The in-memory hold below covers the moment between the agent
                # unmounting and the daemon writing this.
                track.held = (
                    "it was disconnected through SMBPal; "
                    "`smbpal connection connect` brings it back"
                )
                track.held_status = _DISCONNECTED
            if track.held is not None:
                self._say(track, connection_id, f"not reconnecting: {track.held}")
                track.status = track.held_status or _DISCONNECTED
                return
            if (connection.get("auto_connect") or "on_this_network") == "never":
                self._say(track, connection_id, "not connecting: auto_connect is never")
                track.status = (DISABLED, "not connected automatically", False)
                return
            if now < track.next_try:
                return

        # Outside the lock: a mount can take as long as NetFS's own timeout,
        # and `released`/`connected` must not wait behind it.
        started = self._monotonic()
        try:
            where = self._mount(connection)
        except NetFSError as exc:
            self._failed(connection_id, exc.message, retryable=exc.retryable,
                         now=now, kind=exc.state,
                         took=self._monotonic() - started)
            return
        except SmbpalError as exc:
            # The Keychain, the URL: nothing that names a refused credential,
            # so tried again later rather than given up on.
            self._failed(connection_id, exc.message, retryable=True, now=now,
                         took=self._monotonic() - started)
            return
        with self._lock:
            track = self._tracks.get(connection_id)
            if track is not None:
                track.mounted_at = track.last_at = where
                track.failures = 0
                track.next_try = 0.0
                track.status = (CONNECTED, f"mounted at {where}", False)
                self._say(track, connection_id, f"connected at {where}")

    def _failed(self, connection_id: str, message: str, *, retryable: bool,
                now: float, kind: str = FAILED, took: float = 0.0) -> None:
        with self._lock:
            track = self._tracks.get(connection_id)
            if track is None:
                return
            if not retryable:
                track.held = f"the mount was refused: {message}"
                # `auth_failed` keeps its own word, because the window offers
                # the password for it; anything else refused is `failed`.
                track.held_status = (
                    AUTH_FAILED if kind == AUTH_FAILED else FAILED,
                    f"{message}; SMBPal will not retry it until you connect it",
                    False,
                )
                track.status = track.held_status
                self._say(track, connection_id, f"not reconnecting: {track.held}",
                          warn=True)
                return
            track.failures += 1
            cap = MAX_BACKOFF if took >= SLOW_ATTEMPT else FAST_BACKOFF
            delay = min(self.interval * (2 ** track.failures), cap)
            track.next_try = now + delay
            # The machine's own rule: a retryable `failed` is `reconnecting`,
            # and `unreachable` keeps its word because it says why.
            track.status = (
                UNREACHABLE if kind == UNREACHABLE else RECONNECTING,
                f"{message}; SMBPal is trying again",
                True,
            )
            self._say(track, connection_id,
                      f"could not connect ({message}); trying again with backoff")
            if now - track.retry_logged >= RETRY_LOG_EVERY:
                track.retry_logged = now
                log.info(
                    "%s: still retrying, attempt %d (%s), next in %.0fs",
                    connection_id,
                    track.failures,
                    message,
                    delay,
                )

    # --- inputs ------------------------------------------------------------

    def _read_connections(self) -> list[dict[str, Any]]:
        """The daemon's list, or the last one it gave if it cannot be asked.

        A daemon restarting is not a reason to stop reconnecting what was
        configured a moment ago, and an empty list in its place would read as
        *nothing is configured* — the D14 shape again.
        """
        try:
            listed = self._connections()
        except SmbpalError as exc:
            if self._list_problem != exc.message:
                self._list_problem = exc.message
                log.warning("cannot read the connection list: %s", exc.message)
            return self._last_list
        if self._list_problem is not None:
            log.info("reading the connection list again")
            self._list_problem = None
        self._last_list = [c for c in listed if isinstance(c, dict)]
        return self._last_list

    def _slept(self, now: float) -> bool:
        wall = self._wall()
        previous = self._last_clocks
        self._last_clocks = (wall, now)
        if previous is None:
            return False
        gap = (wall - previous[0]) - (now - previous[1])
        if gap > SLEEP_GAP:
            log.info("the Mac slept for about %.0fs", gap)
            return True
        return False

    def _say(self, track: _Track, connection_id: str, line: str, *,
             warn: bool = False) -> None:
        if track.said == line:
            return
        track.said = line
        log.log(logging.WARNING if warn else logging.INFO, "%s: %s",
                connection_id, line)
