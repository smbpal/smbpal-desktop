"""Watching connections and pushing what changes.

D4's channel has carried events since the first commit and nothing has emitted
one until now. This is what emits them: clients are told when a connection's
state changes rather than asking repeatedly, which is what "pushed to clients
rather than polled" means from the client's side.

**The daemon does poll**, because systemd offers nothing better without a D-Bus
dependency the daemon does not otherwise need. What matters is that the polling
is cheap and cannot block:

- mountedness comes from `/proc/self/mountinfo`, a kernel table (M0 §4);
- `systemctl show` reads unit properties and never touches the mount;
- **`journalctl` is read only on a transition into failure**, never on every
  tick, because the journal is the expensive part and the reason does not change
  while the state does not.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable

from smbpal.config import ConfigStore
from smbpal.errors import SmbpalError
from smbpal.mounts import probe as probe_module
from smbpal.mounts import systemd, units
from smbpal.mounts.apply import Mounter
from smbpal.state.machine import ConnectionState, derive
from smbpal.state.translate import Cause, translate_journal
from smbpal.system.run import CommandRunner, run

log = logging.getLogger(__name__)

JOURNALCTL = "journalctl"
DEFAULT_INTERVAL = 5.0
_JOURNAL_LINES = "50"

Broadcast = Callable[[str, dict[str, Any]], None]


class StateMonitor:
    def __init__(
        self,
        store: ConfigStore,
        mounter: Mounter,
        *,
        broadcast: Broadcast | None = None,
        interval: float = DEFAULT_INTERVAL,
        runner: CommandRunner | None = None,
    ) -> None:
        self.store = store
        self.mounter = mounter
        self.broadcast = broadcast
        self.interval = interval
        self.runner = runner or mounter.runner
        self._states: dict[str, ConnectionState] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="smbpal-state", daemon=True
        )
        self._thread.start()
        log.info("watching connection state every %gs", self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 2)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll()
            except Exception:  # noqa: BLE001 - a monitor that dies is worse
                log.exception("state poll failed; continuing")
            self._stop.wait(self.interval)

    # --- polling -----------------------------------------------------------

    def snapshot(self) -> list[ConnectionState]:
        with self._lock:
            return list(self._states.values())

    def state_for(self, connection_id: str) -> ConnectionState | None:
        with self._lock:
            return self._states.get(connection_id)

    def poll(self) -> list[ConnectionState]:
        config = self.store.load()
        current: dict[str, ConnectionState] = {}
        changes: list[tuple[ConnectionState | None, ConnectionState]] = []

        # Once for the whole poll: it is one small read, and asking per
        # connection would give two connections to the same server answers
        # taken a moment apart.
        servers = self.mounter.probe.server_states()

        for connection in config.get("connections", []):
            state = self._state_of(connection, servers)
            current[state.id] = state
            with self._lock:
                previous = self._states.get(state.id)
            if previous is None or _differs(previous, state):
                changes.append((previous, state))

        with self._lock:
            gone = set(self._states) - set(current)
            self._states = current

        for previous, state in changes:
            self._emit(previous, state, connection_lookup(config, state.id))
        for connection_id in sorted(gone):
            self._push("connection.removed", {"id": connection_id})
        return list(current.values())

    def _state_of(
        self,
        connection: dict[str, Any],
        servers: dict[str, bool] | None = None,
    ) -> ConnectionState:
        mount_name, _ = units.unit_names(connection["mountpoint"])
        # Asked first: when it answers, `mounted` is True about a filesystem
        # that is not ours, and every question after it is the wrong one.
        intruder = self.mounter.foreign_occupant(connection)
        mounted = self.mounter.probe.is_mounted(connection["mountpoint"])
        armed = self.mounter.probe.is_armed(connection["mountpoint"])
        unit: dict[str, str] | None
        try:
            unit = systemd.show(mount_name, runner=self.runner)
        except SmbpalError:
            unit = None

        cause: Cause | None = None
        failed = unit is not None and (
            unit.get("ActiveState") == "failed"
            or (unit.get("Result") or "success") != "success"
        )
        if failed and not mounted:
            # Only here. The journal is the expensive read and its answer does
            # not change while the failure does not.
            cause = self._journal_cause(mount_name)
        return derive(
            connection,
            mounted=mounted,
            unit=unit,
            cause=cause,
            armed=armed,
            read_only=self.mounter.probe.is_read_only(connection["mountpoint"])
            if mounted
            else None,
            occupied_by=f"{intruder.source} ({intruder.fstype})"
            if intruder is not None
            else None,
            server_answering=probe_module.server_is_answering(
                connection.get("host", ""), servers
            )
            if mounted
            else None,
        )

    def _journal_cause(self, unit_name: str) -> Cause | None:
        execute = self.runner or run
        try:
            result = execute(
                [JOURNALCTL, "-u", unit_name, "-n", _JOURNAL_LINES, "--no-pager", "-o", "cat"]
            )
        except SmbpalError as exc:
            log.debug("could not read the journal for %s: %s", unit_name, exc.message)
            return None
        return translate_journal(result.stdout)

    # --- emitting ----------------------------------------------------------

    def _emit(
        self,
        previous: ConnectionState | None,
        state: ConnectionState,
        connection: dict[str, Any] | None,
    ) -> None:
        payload = state.to_wire()
        payload["previous"] = previous.state if previous else None
        if connection is not None:
            payload["mountpoint"] = connection.get("mountpoint")
            hint = fallback_hint(connection, state)
            if hint:
                payload["hint"] = hint
        if state.is_problem:
            log.warning("%s: %s (%s)", state.id, state.message, state.state)
        else:
            log.info("%s -> %s", state.id, state.state)
        self._push("state.changed", payload)

    def _push(self, event: str, data: dict[str, Any]) -> None:
        if self.broadcast is not None:
            self.broadcast(event, data)


def connection_lookup(config: dict[str, Any], connection_id: str) -> dict[str, Any] | None:
    for connection in config.get("connections", []):
        if connection.get("id") == connection_id:
            return connection
    return None


def fallback_hint(connection: dict[str, Any], state: ConnectionState) -> str | None:
    """§3e's recorded address, offered rather than used.

    The plan proposed preferring `.local` and keeping the IP as a fallback for a
    client whose mDNS is broken. Building it exposed why the fallback must not be
    automatic: **a DHCP lease can be reassigned.** The address recorded when the
    connection was added may now belong to a different machine, and silently
    failing over would send the stored credentials to whatever answers on port
    445. So the address is surfaced with the command that would use it, and a
    person decides.
    """
    fallback = connection.get("fallback_host")
    if not fallback or state.state != "unresolved":
        return None
    return (
        f"{fallback} was recorded as a fallback when this connection was added. "
        f"It may since have been reassigned to another machine, so SMBPal will "
        f"not switch on its own — run `smbpal connection use-fallback "
        f"{connection['id']}` if you are sure it is still the right host."
    )


def _differs(previous: ConnectionState, current: ConnectionState) -> bool:
    return (previous.state, previous.message) != (current.state, current.message)
