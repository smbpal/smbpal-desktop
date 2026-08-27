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

from smbpal.config import operations
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

# A connection that names a credential file which is not there. Distinct from
# `auth_failed`: nothing has been refused, because nothing has been offered.
NO_CREDENTIALS = "no credentials"


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
        managed_roots: frozenset[str] | None = None,
    ) -> None:
        self.unit_dir = Path(unit_dir)
        self.credentials = credentials or CredentialsStore()
        self.probe = probe or probe_module.MountProbe()
        self.runner = runner
        # Where a leftover mountpoint is ours to clear up. Injected for the
        # same reason unit_dir and mountinfo are: the real values are absolute
        # paths no test may write to.
        self.managed_roots = managed_roots or operations.MANAGED_ROOTS

    def occupied_mountpoints(self) -> set[str]:
        """Every path something is really mounted on. autofs triggers excluded.

        Offered to `add_connection` so a derived mountpoint skips a path that
        is already in use — the config cannot see this and the daemon can.
        """
        entries = probe_module.mount_entries(self.probe.mountinfo) or []
        return {
            os.path.normpath(e.mountpoint)
            for e in entries
            if e.fstype != probe_module.AUTOFS
        }

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
                state = NO_CREDENTIALS
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

    def apply(
        self, config: dict[str, Any], *, previous: dict[str, Any] | None = None
    ) -> MountReport:
        """Reconcile the units on disk against `config`.

        **`previous` decides what may be removed, and that is the whole point
        of it.** Without it, reaping means "delete every unit we wrote that is
        not in this config" — which is correct for an `smbpal apply` a person
        typed, and catastrophic for a daemon that opened the wrong config file.
        A Pi run on 27 August 2026 started against `--config
        /tmp/smbpal-test.json`, a path that does not survive a reboot, while
        the real connection sat in `/etc/smbpal/config.json`. One `connection
        add` would have committed against the empty document and reaped a
        working setup.

        So a commit passes the document it is replacing, and only mountpoints
        that *this change* dropped are removed. Units the config has never
        mentioned are left alone and reported by `inventory.survey` instead —
        the same rule `store.py` already states for the config file itself:
        starting empty looks exactly like "everything is gone", and acting on
        it makes that true.
        """
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

        removed = self._remove_stale_units(wanted, keep=self._untouched(config, previous))
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

    @staticmethod
    def _untouched(
        config: dict[str, Any], previous: dict[str, Any] | None
    ) -> set[str] | None:
        """Mountpoints this change is not entitled to remove.

        None means "no restriction" — an explicit apply, sweeping everything.
        """
        if previous is None:
            return None
        known = {
            os.path.normpath(c["mountpoint"])
            for doc in (config, previous)
            for c in doc.get("connections", [])
            if c.get("mountpoint")
        }
        return known

    def teardown(self) -> list[str]:
        """Remove every unit we wrote, and the mountpoints we chose with them.

        No `keep`: this is the deliberate sweep, the thing `apply`'s diff-bound
        reaping exists to *not* be.
        """
        removed = self._remove_stale_units(set())
        if removed:
            systemd.daemon_reload(runner=self.runner)
        return removed

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

    def _remove_stale_units(
        self, wanted: set[str], keep: set[str] | None = None
    ) -> list[str]:
        """Remove units we generated that are no longer configured.

        Identified by the marker in the file, never by the name: a hand-written
        `mnt-media.mount` that happens to collide is not ours to delete.

        `keep` is the set of mountpoints the caller is entitled to touch — see
        `apply`. A unit outside it is somebody else's business even though we
        wrote it, and it is reported rather than removed.
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
            where = _where(path)
            if keep is not None and os.path.normpath(where or "") not in keep:
                # This config has never mentioned the mountpoint, so this
                # change did not remove it — something else wrote it, or an
                # earlier run of SMBPal against a different config did.
                log.info(
                    "leaving %s alone: %s is not part of this change", path.name, where
                )
                continue
            if path.suffix == ".automount":
                systemd.disable(path.name, runner=self.runner)
            else:
                systemd.stop(path.name, runner=self.runner)
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
            if where and operations.in_managed_root(where, self.managed_roots):
                self._remove_empty_mountpoint(where)
        return removed

    def _remove_empty_mountpoint(self, mountpoint: str) -> None:
        """Clear up a mountpoint we chose, once nothing is using it.

        **Only inside a root we derive into**, because that is where a leftover
        does damage: udisks2 picks its mountpoint by testing whether the
        directory exists, so an abandoned `/media/<user>/Media` sends every
        future stick of that name to `Media1` — permanently, and long after
        SMBPal is gone. A stray empty directory at `/srv/backups` harms nobody
        and was probably there first.

        `rmdir` is the whole safety check. It refuses a directory with
        anything in it and refuses one that is still a mountpoint, so there is
        no window between asking and acting.
        """
        try:
            os.rmdir(mountpoint)
        except OSError as exc:
            log.debug("left %s in place: %s", mountpoint, exc)
            return
        log.info("removed the empty mountpoint %s", mountpoint)
