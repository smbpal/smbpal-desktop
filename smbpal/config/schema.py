"""D7 config schema and its validation.

Hand-written rather than jsonschema, for three reasons that all matter here:
no dependency (D11), error messages that name the field and say what was
expected, and room for the rules a generic validator cannot express — a share
name that would break out of an `smb.conf` section, an id that would escape a
systemd unit name.

**Validation is about shape, not about the filesystem.** `/srv/media` is a valid
path whether or not it exists; whether it exists, and who owns it, is M3's
question (§3c). Keeping those apart means config loaded at boot does not fail
because a USB disk has not been mounted yet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from smbpal.errors import ConfigInvalid

SCHEMA_VERSION = 1

# Ids become filenames: systemd unit names, credential files under /etc/smbpal.
# Constrain them hard here and no downstream component has to sanitise again.
_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

# Samba share names. Excluded characters are the ones that break the file format
# or the section header: newline above all, which is what turns a share name
# into arbitrary smb.conf. `/` and NUL are rejected by Samba itself.
_SHARE_NAME_FORBIDDEN = set('\n\r\t/\\[]:;"\'`$%\x00')
_SHARE_NAME_MAX = 80

# Section names Samba gives its own meaning. A share called `global` would not be
# a share.
_RESERVED_SHARE_NAMES = frozenset({"global", "homes", "printers", "print$"})

# A host may be a name or an address. Reject anything that could carry structure
# into a UNC path or a mount command line.
_HOST_FORBIDDEN = set('\n\r\t /\\[]"\'`$%\x00')
_HOST_MAX = 253

AUTO_CONNECT_VALUES = ("always", "on_this_network", "never")

_SHARE_KEYS = {
    "type",
    "id",
    "name",
    "path",
    "read_only",
    "credential_ref",
    "enabled",
}
_CONNECTION_KEYS = {
    "type",
    "id",
    "host",
    "share",
    "mountpoint",
    "credential_ref",
    "auto_connect",
    "owner",
}
_TOP_KEYS = {"version", "shares", "connections"}


@dataclass(frozen=True)
class Problem:
    """One validation failure, addressed the way a user can act on."""

    where: str
    message: str

    def __str__(self) -> str:
        return f"{self.where}: {self.message}"


def empty_config() -> dict[str, Any]:
    """A valid config with nothing in it — what a first boot loads."""
    return {"version": SCHEMA_VERSION, "shares": [], "connections": []}


def validate(doc: Any) -> list[Problem]:
    """Return every problem with `doc`, or an empty list if it is valid.

    Every problem, not the first: a user fixing a hand-edited file should see
    the whole list rather than discovering the next one on each restart.
    """
    problems: list[Problem] = []

    if not isinstance(doc, dict):
        return [Problem("<document>", f"expected an object, got {_kind(doc)}")]

    _check_keys(problems, "<document>", doc, _TOP_KEYS, required={"version"})

    version = doc.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        problems.append(Problem("version", f"expected an integer, got {_kind(version)}"))
    elif version > SCHEMA_VERSION:
        problems.append(
            Problem(
                "version",
                f"is {version}, but this SMBPal understands up to {SCHEMA_VERSION}. "
                "This file was written by a newer version — upgrade rather than "
                "editing it down.",
            )
        )
    elif version < 1:
        problems.append(Problem("version", f"is {version}; the first schema version is 1"))

    seen_ids: dict[str, str] = {}
    _validate_list(problems, doc, "shares", _validate_share, seen_ids)
    _validate_list(problems, doc, "connections", _validate_connection, seen_ids)

    _check_unique_share_names(problems, doc.get("shares"))
    return problems


def validate_or_raise(
    doc: Any, *, source: str, relabel: Callable[[str], str] | None = None
) -> dict[str, Any]:
    """Validate and return `doc`, or raise ConfigInvalid naming every problem.

    `relabel` rewrites the `where` of each problem. A caller adding one record
    knows which one it is, and `shares[2].name` is an array index the person who
    typed a share name never saw. Turning it into `name` is the difference
    between a message they can act on and one they have to decode.
    """
    problems = validate(doc)
    if not problems:
        return doc
    labelled = [
        Problem(relabel(p.where) if relabel else p.where, p.message) for p in problems
    ]
    count = len(labelled)
    joined = "\n".join(f"  - {p}" for p in labelled)
    raise ConfigInvalid(
        source,
        detail=f"{count} problem{'' if count == 1 else 's'}:\n{joined}",
    )


# --- element validators ----------------------------------------------------


def _validate_list(
    problems: list[Problem],
    doc: dict[str, Any],
    key: str,
    validator: Any,
    seen_ids: dict[str, str],
) -> None:
    value = doc.get(key, [])
    if not isinstance(value, list):
        problems.append(Problem(key, f"expected a list, got {_kind(value)}"))
        return
    for index, item in enumerate(value):
        where = f"{key}[{index}]"
        if not isinstance(item, dict):
            problems.append(Problem(where, f"expected an object, got {_kind(item)}"))
            continue
        validator(problems, where, item)
        _check_id_unique(problems, where, item, seen_ids)


def _validate_share(problems: list[Problem], where: str, share: dict[str, Any]) -> None:
    _check_keys(
        problems,
        where,
        share,
        _SHARE_KEYS,
        required={"type", "id", "name", "path"},
    )
    _check_type_discriminator(problems, where, share)
    _check_id(problems, where, share)
    _check_share_name(problems, f"{where}.name", share.get("name"))
    _check_absolute_path(problems, f"{where}.path", share.get("path"))
    _check_optional_bool(problems, f"{where}.read_only", share.get("read_only"))
    _check_optional_bool(problems, f"{where}.enabled", share.get("enabled"))
    _check_optional_ref(problems, f"{where}.credential_ref", share.get("credential_ref"))


def _validate_connection(
    problems: list[Problem], where: str, connection: dict[str, Any]
) -> None:
    _check_keys(
        problems,
        where,
        connection,
        _CONNECTION_KEYS,
        required={"type", "id", "host", "share", "mountpoint"},
    )
    _check_type_discriminator(problems, where, connection)
    _check_id(problems, where, connection)
    _check_host(problems, f"{where}.host", connection.get("host"))
    _check_share_name(problems, f"{where}.share", connection.get("share"))
    _check_absolute_path(problems, f"{where}.mountpoint", connection.get("mountpoint"))
    _check_optional_ref(
        problems, f"{where}.credential_ref", connection.get("credential_ref")
    )
    _check_owner(problems, f"{where}.owner", connection.get("owner"))
    auto = connection.get("auto_connect")
    if auto is not None and auto not in AUTO_CONNECT_VALUES:
        problems.append(
            Problem(
                f"{where}.auto_connect",
                f"is {auto!r}; expected one of {', '.join(AUTO_CONNECT_VALUES)}",
            )
        )


# --- field checks ----------------------------------------------------------


def _check_keys(
    problems: list[Problem],
    where: str,
    obj: dict[str, Any],
    allowed: set[str],
    *,
    required: set[str],
) -> None:
    # Unknown keys are rejected rather than ignored. A typo that is silently
    # dropped is a setting the user believes they have set.
    for key in sorted(set(obj) - allowed):
        problems.append(
            Problem(f"{where}.{key}", "is not a recognised field"),
        )
    for key in sorted(required - set(obj)):
        problems.append(Problem(where, f"is missing required field {key!r}"))


def _check_type_discriminator(
    problems: list[Problem], where: str, obj: dict[str, Any]
) -> None:
    # D7 keeps `type` from the first record even though Phase 1 has one value,
    # because retrofitting a discriminator is expensive and Phase 4 adds "app".
    value = obj.get("type")
    if value is not None and value != "os":
        problems.append(
            Problem(f"{where}.type", f"is {value!r}; Phase 1 supports only 'os'")
        )


def _check_id(problems: list[Problem], where: str, obj: dict[str, Any]) -> None:
    value = obj.get("id")
    if value is None:
        return
    if not isinstance(value, str) or not _ID_RE.match(value):
        problems.append(
            Problem(
                f"{where}.id",
                "must be 1-64 characters of letters, digits, '-' or '_', starting "
                "with a letter or digit. Ids become systemd unit names and file "
                "paths, so anything else is a way out of them.",
            )
        )


def _check_id_unique(
    problems: list[Problem], where: str, obj: dict[str, Any], seen: dict[str, str]
) -> None:
    value = obj.get("id")
    if not isinstance(value, str):
        return
    if value in seen:
        problems.append(
            Problem(f"{where}.id", f"duplicates the id already used by {seen[value]}")
        )
    else:
        seen[value] = where


def _check_share_name(problems: list[Problem], where: str, value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        problems.append(Problem(where, f"expected a string, got {_kind(value)}"))
        return
    if not value:
        problems.append(Problem(where, "must not be empty"))
        return
    if len(value) > _SHARE_NAME_MAX:
        problems.append(Problem(where, f"is longer than {_SHARE_NAME_MAX} characters"))
    bad = sorted(_SHARE_NAME_FORBIDDEN & set(value))
    if bad:
        problems.append(
            Problem(
                where,
                "contains "
                + ", ".join(repr(c) for c in bad)
                + ". A share name is written into a section header, so a newline "
                "in it is arbitrary smb.conf.",
            )
        )
    if value.lower() in _RESERVED_SHARE_NAMES:
        problems.append(
            Problem(where, f"is {value!r}, which Samba reserves for its own section")
        )


def _check_host(problems: list[Problem], where: str, value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        problems.append(Problem(where, f"expected a string, got {_kind(value)}"))
        return
    if not value:
        problems.append(Problem(where, "must not be empty"))
        return
    if len(value) > _HOST_MAX:
        problems.append(Problem(where, f"is longer than {_HOST_MAX} characters"))
    bad = sorted(_HOST_FORBIDDEN & set(value))
    if bad:
        problems.append(
            Problem(where, "contains " + ", ".join(repr(c) for c in bad))
        )


def _check_absolute_path(problems: list[Problem], where: str, value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        problems.append(Problem(where, f"expected a string, got {_kind(value)}"))
        return
    if not value.startswith("/"):
        problems.append(Problem(where, f"is {value!r}; must be an absolute path"))
        return
    if "\x00" in value:
        problems.append(Problem(where, "contains a NUL byte"))
    if "\n" in value or "\r" in value:
        problems.append(
            Problem(where, "contains a newline, which would break every file we write")
        )
    if ".." in value.split("/"):
        problems.append(
            Problem(
                where,
                "contains a '..' component. Store the resolved path so that what is "
                "validated is what is used.",
            )
        )


def _check_owner(problems: list[Problem], where: str, value: Any) -> None:
    """The local account whose uid the mounted files appear as.

    Not a remote credential — that is `credential_ref`. This is who owns the
    files once they are mounted, which is why the daemon defaults it from the
    peer's own uid: the person adding a connection is the person who will use it.
    """
    if value is None:
        return
    if not isinstance(value, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value):
        problems.append(
            Problem(where, "must be null or a POSIX user name")
        )


def _check_optional_bool(problems: list[Problem], where: str, value: Any) -> None:
    if value is not None and not isinstance(value, bool):
        problems.append(Problem(where, f"expected true or false, got {_kind(value)}"))


def _check_optional_ref(problems: list[Problem], where: str, value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not _ID_RE.match(value):
        problems.append(
            Problem(
                where,
                "must be null or a reference of letters, digits, '-' or '_'. "
                "It names a credential; it never holds one.",
            )
        )


def _check_unique_share_names(problems: list[Problem], shares: Any) -> None:
    if not isinstance(shares, list):
        return
    seen: dict[str, int] = {}
    for index, share in enumerate(shares):
        if not isinstance(share, dict):
            continue
        name = share.get("name")
        if not isinstance(name, str):
            continue
        # SMB share names are case-insensitive; two shares differing only in case
        # are one share to every client.
        key = name.lower()
        if key in seen:
            problems.append(
                Problem(
                    f"shares[{index}].name",
                    f"is {name!r}, which collides with shares[{seen[key]}] — SMB "
                    "share names are case-insensitive",
                )
            )
        else:
            seen[key] = index


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    return {
        bool: "a boolean",
        int: "a number",
        float: "a number",
        str: "a string",
        list: "a list",
        dict: "an object",
    }.get(type(value), type(value).__name__)
