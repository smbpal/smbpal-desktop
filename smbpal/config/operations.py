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
import re
from typing import Any, Callable

from smbpal.config.schema import validate_or_raise
from smbpal.errors import AlreadyExists, NotFound

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")
_MAX_ID_LEN = 64


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
    mountpoint: str,
    id: str | None = None,
    credential_ref: str | None = None,
    auto_connect: str = "on_this_network",
    owner: str | None = None,
    fallback_host: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = copy.deepcopy(doc)
    connections = result.setdefault("connections", [])

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
