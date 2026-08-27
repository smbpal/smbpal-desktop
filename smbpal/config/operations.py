"""Structured edits to a config document.

Pure functions: they take a document and return a new one, so every invariant
here is testable without a daemon, a socket or root.

**There is deliberately no `config.set`.** Clients ask for a share to be added
or removed, never for a document to be replaced. If the wire could carry a whole
config, every invariant in this module would become advisory — enforced only for
clients that chose to go through the front door.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass
from typing import Any, Callable

from smbpal.config.schema import validate_or_raise
from smbpal.errors import AlreadyExists, InvalidParams, NotFound

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")
_MAX_ID_LEN = 64


@dataclass(frozen=True)
class MountpointStyle:
    """Where a platform's file manager expects a network volume to live.

    Not a cosmetic preference. On Linux the *path* decides whether the volume
    is shown at all: GIO displays a mount only under `/media/`,
    `/run/media/$USER/` or `$HOME` (3h), and `/mnt` is invisible. So the
    derived default has to land somewhere GIO will admit, or the connection
    works and nobody can see it.

    macOS reaches the same place by a different road. `/Volumes` is the
    convention, but visibility there is a *mount option* rather than a
    location: `mount_smbfs`'s `nobrowse` is what hides a volume from Finder
    and the Desktop, and every system mount sets it. A path rule alone would
    not port.

    Windows has no entry, deliberately. A mapped share is a drive letter, not
    a path, and `mountpoint` is schema-checked as absolute — widening that is
    Phase 2's problem and should be an explicit decision rather than a default
    that quietly stops meaning anything.
    """

    root: str
    # Whether the platform namespaces volumes per user. Debian-family udisks2
    # does (`/media/<user>/`); macOS's /Volumes is machine-wide.
    per_user: bool


# The roots SMBPal derives mountpoints into, across platforms. Used to decide
# which leftover directories are ours to tidy up: see `Mounter.managed_roots`.
MANAGED_ROOTS = frozenset({"/media", "/run/media", "/Volumes"})


def in_managed_root(mountpoint: str, roots: frozenset[str] = MANAGED_ROOTS) -> bool:
    """Is this a path SMBPal chose, and so is responsible for tidying up?

    **The distinction is about whose namespace it is, not who made the
    directory.** An empty directory left at `/srv/backups` is nobody's problem
    and was very likely there before SMBPal was; one left at
    `/media/<user>/Media` displaces udisks2's naming for good, because udisks2
    picks its mountpoint by testing whether the directory *exists*. Observed on
    a Pi on 27 August 2026: with the connection removed and nothing mounted, a
    stick labelled `Media` still went to `Media1`.

    String work only — `os.path` does not touch the filesystem, so this module
    stays as testable without one as the rest of it.
    """
    path = os.path.normpath(mountpoint)
    return any(path.startswith(os.path.normpath(root) + os.sep) for root in roots)


STYLES = {
    "linux": MountpointStyle(root="/media", per_user=True),
    "darwin": MountpointStyle(root="/Volumes", per_user=False),
}


def platform_style(platform: str | None = None) -> MountpointStyle:
    """The style for a platform, defaulting to Linux for anything unlisted.

    Linux is the fallback because it is what Phase 1 ships and what the daemon
    runs on; a development Mac deriving a Linux path is harmless, and a Mac
    silently deriving a `/Volumes` path for a Pi's config would not be.
    """
    return STYLES.get(platform or "linux", STYLES["linux"])


def _volume_name(share: str) -> str:
    """The share name, made safe to be the last component of a mountpoint.

    **Leading dots are the one that bites.** GIO hides any mount whose path
    contains `/.`, so a share called `.private` would mount somewhere the file
    manager refuses to show — the exact failure choosing `/media` exists to
    avoid. Finder hides them too.
    """
    cleaned = share.strip().strip(".").strip()
    return cleaned or "share"


def default_mountpoint(
    share: str,
    owner: str | None,
    taken: set[str],
    *,
    host: str | None = None,
    style: MountpointStyle | None = None,
) -> str:
    """Where a connection goes when the caller does not say.

    **The basename is not incidental — it is the name of the drive.** Both GIO
    and Finder label a volume by the last component of its mountpoint, and
    neither can be told otherwise from here: `x-gvfs-name=` is read from
    `/etc/fstab`, and `x-` options never reach the kernel, so a systemd unit
    cannot carry one. Naming the share therefore names the drive, which is why
    the share name is the default rather than the connection id.

    Collisions disambiguate by *host* before falling back to a number, because
    two machines exporting `Media` is the common case and `Media on rivendell`
    answers "which one" where `Media 2` does not.

    `taken` is whatever the caller can prove is unavailable. The config's own
    mountpoints always; the daemon adds the paths something is currently
    mounted on, which it can see and these pure functions cannot. **That
    second part came from a Pi run on 27 August 2026**: a USB stick labelled
    `Media` lands in `/media/<user>/Media`, and without it a connection to a
    share of the same name derives the one path it cannot use — apply then
    refuses, correctly, and the connection is stuck until somebody removes the
    stick or supplies a path by hand. udisks2 solves this by picking another
    name, and so should we.

    An *explicitly given* mountpoint is never second-guessed this way. A mount
    can go away a second later, and `foreign_mount` reports an occupied
    mountpoint at apply time rather than refusing to record the connection.
    """
    style = style or platform_style()
    if style.per_user and not owner:
        raise InvalidParams(
            "cannot work out where to mount this",
            detail=(
                f"{style.root}/<user> needs a local account and this connection "
                "has no owner. Pass a mountpoint instead."
            ),
        )
    base = f"{style.root}/{owner}" if style.per_user else style.root
    name = _volume_name(share)

    candidates = [name]
    if host:
        candidates.append(f"{name} on {host}")
    for candidate in candidates:
        if f"{base}/{candidate}" not in taken:
            return f"{base}/{candidate}"

    stem = candidates[-1]
    suffix = 2
    while f"{base}/{stem} {suffix}" in taken:
        suffix += 1
    return f"{base}/{stem} {suffix}"


def make_id(name: str, taken: set[str]) -> str:
    """Derive a readable, schema-legal id from a name, unique against `taken`."""
    slug = _SLUG_STRIP.sub("-", name.lower()).strip("-")[:_MAX_ID_LEN]
    if not slug or not slug[0].isalnum():
        slug = f"s{slug}" if slug else "share"
    if slug not in taken:
        return slug
    for suffix in range(2, 1000):
        candidate = f"{slug[: _MAX_ID_LEN - len(str(suffix)) - 1]}-{suffix}"
        if candidate not in taken:
            return candidate
    raise AlreadyExists(f"cannot derive a free id from {name!r}")


def all_ids(doc: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for key in ("shares", "connections"):
        for item in doc.get(key, []):
            value = item.get("id")
            if isinstance(value, str):
                ids.add(value)
    return ids


# --- shares ----------------------------------------------------------------


def add_share(
    doc: dict[str, Any],
    *,
    name: str,
    path: str,
    id: str | None = None,
    read_only: bool = False,
    credential_ref: str | None = None,
    enabled: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = copy.deepcopy(doc)
    shares = result.setdefault("shares", [])

    for existing in shares:
        if str(existing.get("name", "")).lower() == name.lower():
            raise AlreadyExists(
                f"a share named {existing['name']!r} is already configured",
                detail="SMB share names are case-insensitive, so these would be "
                "one share to every client.",
            )

    share_id = id or make_id(name, all_ids(result))
    if share_id in all_ids(result):
        raise AlreadyExists(f"id {share_id!r} is already in use")

    share = {
        "type": "os",
        "id": share_id,
        "name": name,
        "path": path,
        "read_only": read_only,
        "credential_ref": credential_ref,
        "enabled": enabled,
    }
    shares.append(share)
    # Validate the whole document, not the new record alone: uniqueness and
    # cross-references are properties of the document. Relabel so the caller
    # hears about `name`, not `shares[2].name`.
    validate_or_raise(
        result,
        source=f"cannot add share {name!r}",
        relabel=_strip_index("shares", len(shares) - 1),
    )
    return result, share


def remove_share(doc: dict[str, Any], ref: str) -> tuple[dict[str, Any], dict[str, Any]]:
    result = copy.deepcopy(doc)
    shares = result.setdefault("shares", [])
    index = _find(shares, ref, "name")
    if index is None:
        raise NotFound(f"no share called {ref!r}")
    removed = shares.pop(index)
    validate_or_raise(result, source=f"cannot remove share {ref!r}")
    return result, removed


# --- connections -----------------------------------------------------------


def add_connection(
    doc: dict[str, Any],
    *,
    host: str,
    share: str,
    mountpoint: str | None = None,
    id: str | None = None,
    credential_ref: str | None = None,
    auto_connect: str = "on_this_network",
    owner: str | None = None,
    fallback_host: str | None = None,
    in_use: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = copy.deepcopy(doc)
    connections = result.setdefault("connections", [])

    if mountpoint is None:
        # Derived here rather than in the CLI so that the GUI and any other
        # client get the same answer (D12: the daemon owns the config). The
        # result is written into the document explicitly — defaulting is an
        # input convenience, and a stored config whose mountpoint depends on
        # which version of this function last ran would not be a record of
        # anything.
        mountpoint = default_mountpoint(
            share,
            owner,
            {c.get("mountpoint") for c in connections} | (in_use or set()),
            host=host,
        )

    for existing in connections:
        if existing.get("mountpoint") == mountpoint:
            raise AlreadyExists(
                f"{mountpoint} is already the mountpoint for connection "
                f"{existing.get('id')!r}",
                detail="Two connections on one mountpoint would race each other.",
            )

    connection_id = id or make_id(f"{host}-{share}", all_ids(result))
    if connection_id in all_ids(result):
        raise AlreadyExists(f"id {connection_id!r} is already in use")

    connection = {
        "type": "os",
        "id": connection_id,
        "host": host,
        "share": share,
        "mountpoint": mountpoint,
        "credential_ref": credential_ref,
        "auto_connect": auto_connect,
        "owner": owner,
        "fallback_host": fallback_host,
    }
    connections.append(connection)
    validate_or_raise(
        result,
        source=f"cannot add connection to //{host}/{share}",
        relabel=_strip_index("connections", len(connections) - 1),
    )
    return result, connection


def remove_connection(
    doc: dict[str, Any], ref: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = copy.deepcopy(doc)
    connections = result.setdefault("connections", [])
    index = _find(connections, ref, "mountpoint")
    if index is None:
        raise NotFound(f"no connection called {ref!r}")
    removed = connections.pop(index)
    validate_or_raise(result, source=f"cannot remove connection {ref!r}")
    return result, removed


# --- lookup ----------------------------------------------------------------


def _strip_index(key: str, index: int) -> Callable[[str], str]:
    """Turn `shares[2].name` into `name` for the one record being added."""
    prefix = f"{key}[{index}]"

    def relabel(where: str) -> str:
        if where == prefix:
            return "this record"
        if where.startswith(prefix + "."):
            return where[len(prefix) + 1 :]
        return where

    return relabel


def _find(items: list[dict[str, Any]], ref: str, secondary: str) -> int | None:
    """Match on id first, then on the human-facing field, case-insensitively.

    Id first so that an id can always be used unambiguously, even if some other
    record's name happens to equal it.
    """
    for index, item in enumerate(items):
        if item.get("id") == ref:
            return index
    lowered = ref.lower()
    for index, item in enumerate(items):
        value = item.get(secondary)
        if isinstance(value, str) and value.lower() == lowered:
            return index
    return None
