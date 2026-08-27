"""Turning connections into systemd units, and back again.

Same shape as the Samba side: generate whole, write atomically, reconcile what
is on disk against what is configured, and remove ours as a set so an uninstall
leaves nothing behind.

The units we wrote are identified by a marker in their first line rather than by
a naming convention, so a hand-written `mnt-something.mount` that happens to
share a name is never removed by us.
"""

from __future__ import annotations

import logging
import os
import pwd
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from smbpal.errors import SmbpalError
from smbpal.mounts import inventory
from smbpal.mounts import probe as probe_module
from smbpal.mounts import systemd, units
from smbpal.mounts.credentials import CredentialsStore
from smbpal.system import atomic
from smbpal.system.run import CommandRunner

log = logging.getLogger(__name__)

MARKER = inventory.MARKER

_WHERE = re.compile(r"^Where=(.*)$", re.MULTILINE)


def _where(path: Path) -> str | None:
    """The mountpoint a generated unit names, read back from the file."""
    try:
        match = _WHERE.search(path.read_text(encoding="utf-8"))
    except OSError:
        return None
    return match.group(1).strip() if match else None

# A mountpoint held by a filesystem that is not this connection's share. Not a
# failure of the mount — the mount is never attempted — so it reads as its own
# state rather than as an error from systemd.
OCCUPIED = "mountpoint in use"


def foreign_mount(
    entry: probe_module.MountEntry | None, connection: dict[str, Any]
) -> probe_module.MountEntry | None:
    """The mount holding this mountpoint, when it is not this connection's.

    **The comparison is against the source, not the path.** An armed automount
    and its cifs mount share a mountpoint, so "something is mounted here" is
    normal and says nothing; the question is *what*. `//host/share` over cifs
    is ours. A vfat stick udisks2 mounted at the same path is not, and stacking
    on top of it would hide someone's files behind our share.

    `fallback_host` counts too: `connection use-fallback` swaps it into `host`,
    so straight after a swap the mount that is up was made under the other
    name. It is still this share.
    """
    if entry is None:
        return None
    if entry.fstype != probe_module.CIFS:
        return entry
    sources = {units.mount_source(connection).lower()}
    fallback = connection.get("fallback_host")
    if fallback:
        sources.add(f"//{fallback}/{connection['share']}".lower())
    return None if entry.source.lower() in sources else entry


class MountError(SmbpalError):
    code = "mount_failed"


@dataclass(frozen=True)
class PlannedConnection:
    connection: dict[str, Any]
    mount_unit: str
    automount_unit: str
    state: str
    has_credentials: bool

    def to_wire(self) -> dict[str, Any]:
        return {
            **self.connection,
            "unit": self.mount_unit,
            "state": self.state,
            "has_credentials": self.has_credentials,
        }


@dataclass
class MountReport:
    connections: list[PlannedConnection] = field(default_factory=list)

    def to_wire(self) -> dict[str, Any]:
        return {"connections": [c.to_wire() for c in self.connections]}


class Mounter:
    def __init__(
        self,
        *,
        unit_dir: Path | str = systemd.DEFAULT_UNIT_DIR,
        credentials: CredentialsStore | None = None,
        probe: probe_module.MountProbe | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.unit_dir = Path(unit_dir)
        self.credentials = credentials or CredentialsStore()
        self.probe = probe or probe_module.MountProbe()
        self.runner = runner

    def foreign_occupant(
        self, connection: dict[str, Any]
    ) -> probe_module.MountEntry | None:
        """What is holding this connection's mountpoint, if it is not ours."""
        return foreign_mount(self.probe.occupant(connection["mountpoint"]), connection)

    # --- planning ----------------------------------------------------------

    def plan(self, config: dict[str, Any]) -> list[PlannedConnection]:
        """Describe each connection. **Never touches a mountpoint.**

        The state here comes from the kernel's mount table, not from stat()ing
        the path, so a NAS that is switched off cannot make `status` slow. That
        is M0 §4's requirement, and this is the call it governs.
        """
        planned = []
        for connection in config.get("connections", []):
            mount, automount = units.unit_names(connection["mountpoint"])
            has_credentials = bool(
                connection.get("credential_ref")
                and self.credentials.exists(connection["credential_ref"])
            )
            state = self.probe.state(connection["mountpoint"])
            if self.foreign_occupant(connection) is not None:
                # Ahead of the credentials check: a mountpoint someone else is
                # using is not fixed by supplying a password, and `state` would
                # otherwise say `mounted` — about their filesystem, not ours.
                state = OCCUPIED
            elif not has_credentials and connection.get("credential_ref"):
                state = "no credentials"
            planned.append(
                PlannedConnection(
                    connection=connection,
                    mount_unit=mount,
                    automount_unit=automount,
                    state=state,
                    has_credentials=has_credentials,
                )
            )
        return planned

    # --- applying ----------------------------------------------------------

    def apply(self, config: dict[str, Any]) -> MountReport:
        connections = config.get("connections", [])
        wanted: set[str] = set()
        blocked: set[str] = set()

        for connection in connections:
            mount_name, automount_name = units.unit_names(connection["mountpoint"])
            # Added to `wanted` before the check, so that a stick plugged in
            # this morning does not get the connection's units reaped as stale.
            # The connection is still configured; it is the mountpoint that is
            # unavailable, and that can stop being true at any moment.
            wanted.update({mount_name, automount_name})
            intruder = self.foreign_occupant(connection)
            if intruder is not None:
                log.error(
                    "%s is held by %s (%s), not by %s — leaving it alone",
                    connection["mountpoint"],
                    intruder.source,
                    intruder.fstype,
                    units.mount_source(connection),
                )
                blocked.add(connection["id"])
                continue
            self._ensure_mountpoint(connection["mountpoint"])
            credentials_path = self._credentials_path(connection)
            resolved = self._with_owner_ids(connection)
            self._write_unit(mount_name, units.mount_unit(resolved, credentials_path))
            self._write_unit(automount_name, units.automount_unit(resolved))

        removed = self._remove_stale_units(wanted)
        if wanted or removed:
            systemd.daemon_reload(runner=self.runner)

        for connection in connections:
            if connection["id"] in blocked:
                # Arming the automount would mount over whatever is there on
                # the next access, which is the thing being prevented.
                continue
            mount_name, automount_name = units.unit_names(connection["mountpoint"])
            if connection.get("auto_connect") == "never":
                systemd.disable(automount_name, runner=self.runner)
                continue
            # A mount that failed too often is refused before mount.cifs runs,
            # so re-arming a latched unit would arm something that cannot fire.
            # `apply` is the command people reach for after fixing whatever was
            # wrong; it has to actually give the mount another chance.
            systemd.reset_failed(mount_name, runner=self.runner)
            # `--now` starts the automount, which arms the trigger. It does not
            # mount: M0 §4 saw the mount happen on first access, which is what
            # keeps a switched-off NAS from delaying boot.
            systemd.enable(automount_name, runner=self.runner)

        return MountReport(connections=self.plan(config))

    def teardown(self) -> None:
        removed = self._remove_stale_units(set())
        if removed:
            systemd.daemon_reload(runner=self.runner)

    def forget_credentials(self, ref: str) -> None:
        self.credentials.remove(ref)

    # --- pieces ------------------------------------------------------------

    def _credentials_path(self, connection: dict[str, Any]) -> str | None:
        ref = connection.get("credential_ref")
        if not ref or not self.credentials.exists(ref):
            return None
        return str(self.credentials.path_for(ref))

    @staticmethod
    def _with_owner_ids(connection: dict[str, Any]) -> dict[str, Any]:
        owner = connection.get("owner")
        if not owner:
            return connection
        try:
            entry = pwd.getpwnam(owner)
        except KeyError:
            log.warning(
                "connection %s names owner %r, which does not exist; mounting "
                "without uid/gid options",
                connection["id"],
                owner,
            )
            return connection
        return {**connection, "uid": entry.pw_uid, "gid": entry.pw_gid}

    def _ensure_mountpoint(self, mountpoint: str) -> None:
        path = Path(mountpoint)
        if path.is_dir():
            # Mounting over a directory with content in it hides that content
            # until the unmount, which looks exactly like data loss.
            #
            # A warning rather than the refusal `foreign_mount` gets, and the
            # difference is what can be proved. A foreign *mount* is provably
            # not ours — the source says so. Loose files could equally be our
            # own leftovers from before an unmount, and refusing to apply over
            # those would strand the connection with no way back.
            try:
                if any(path.iterdir()) and self.probe.is_mounted(mountpoint) is not True:
                    log.warning(
                        "%s is not empty; mounting over it will hide what is there",
                        mountpoint,
                    )
            except OSError:
                pass
            return
        try:
            path.mkdir(parents=True, mode=0o755)
        except OSError as exc:
            raise MountError(f"cannot create {mountpoint}", detail=str(exc)) from exc

    def _write_unit(self, name: str, body: str) -> None:
        try:
            atomic.write_text(self.unit_dir / name, body, mode=0o644)
        except OSError as exc:
            raise MountError(
                f"cannot write {self.unit_dir / name}", detail=str(exc)
            ) from exc

    def _remove_stale_units(self, wanted: set[str]) -> list[str]:
        """Remove units we generated that are no longer configured.

        Identified by the marker in the file, never by the name: a hand-written
        `mnt-media.mount` that happens to collide is not ours to delete.
        """
        removed = []
        if not self.unit_dir.is_dir():
            return removed
        for path in sorted(self.unit_dir.iterdir()):
            if path.suffix not in (".mount", ".automount") or path.name in wanted:
                continue
            try:
                if MARKER not in path.read_text(encoding="utf-8"):
                    continue
            except OSError:
                continue
            if path.suffix == ".automount":
                systemd.disable(path.name, runner=self.runner)
            else:
                systemd.stop(path.name, runner=self.runner)
                where = _where(path)
                if where and self.probe.is_mounted(where):
                    # The unmount did not take — something has the mountpoint
                    # busy. Unlinking now would delete the marker, and the
                    # marker is the only evidence this mount was ours: a bare
                    # cifs line in mountinfo says nothing about who made it.
                    # Removing the file would demote an orphan we may clean up
                    # into an unmanaged mount we may not touch. Leave it.
                    log.warning(
                        "%s is still mounted at %s; keeping %s so it stays "
                        "identifiable as ours",
                        path.name,
                        where,
                        path.name,
                    )
                    continue
            try:
                path.unlink()
            except OSError as exc:
                log.warning("could not remove %s: %s", path, exc)
                continue
            removed.append(path.name)
            log.info("removed %s", path.name)
        return removed
