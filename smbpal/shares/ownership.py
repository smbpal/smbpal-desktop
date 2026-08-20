"""§3c: a share directory that exists and is exported is still not usable.

M0 §3 found it the hard way. `/srv/m0test` began `root:root` 755, the Mac
authenticated, saw the share, and was refused the write. After `chown pi:pi` the
same write succeeded.

**The decision (20 August 2026): read-only, with a message.** If SMBPal cannot
write to the directory as the serving user, the share is created read-only, the
reason is shown, and making it writable is an explicit action. SMBPal never
changes ownership of a directory without being asked to, in those words.

**The test runs as the serving identity, not as the daemon.** The daemon is
root and can write anywhere, so a root-side `os.access` would report every
directory writable and the share would fail from the client instead — the worst
version of this bug, because it moves the failure somewhere with no error
message. Permission is therefore computed from the mode against the serving
user's uid and groups.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path

from smbpal.errors import NotFound, SmbpalError


class OwnershipError(SmbpalError):
    code = "ownership"


@dataclass(frozen=True)
class ServingIdentity:
    """The POSIX identity a share is served as (§3b option 1)."""

    username: str
    uid: int
    gids: frozenset[int]


@dataclass(frozen=True)
class DirectoryStatus:
    path: str
    exists: bool
    is_dir: bool = False
    owner_uid: int | None = None
    owner_gid: int | None = None
    mode: int | None = None
    # None means "not determinable" — no serving user is assigned, so
    # writability depends on whoever authenticates. Not the same as False.
    writable: bool | None = None
    owner_name: str | None = None
    # Why not, in words the user can act on. "It belongs to someone else" and
    # "the owner has no write bit" have different fixes, and saying the wrong
    # one sends people to change the wrong thing.
    why_not_writable: str | None = None

    def to_wire(self) -> dict[str, object]:
        return {
            "path": self.path,
            "exists": self.exists,
            "is_dir": self.is_dir,
            "owner": self.owner_name,
            "mode": f"{self.mode:04o}" if self.mode is not None else None,
            "writable": self.writable,
            "why_not_writable": self.why_not_writable,
        }


def serving_identity(username: str) -> ServingIdentity:
    """Resolve a user to the uid and group set Samba will act with."""
    try:
        entry = pwd.getpwnam(username)
    except KeyError:
        raise NotFound(
            f"there is no system account called {username!r}",
            detail="Phase 1 serves as an existing user (§3b).",
        ) from None
    gids = {entry.pw_gid}
    for group in grp.getgrall():
        if username in group.gr_mem:
            gids.add(group.gr_gid)
    return ServingIdentity(username=username, uid=entry.pw_uid, gids=frozenset(gids))


def inspect_directory(
    path: str | Path, identity: ServingIdentity | None = None
) -> DirectoryStatus:
    """Report what the directory is and whether the serving user can write it."""
    path = Path(path)
    try:
        info = path.stat()
    except FileNotFoundError:
        return DirectoryStatus(path=str(path), exists=False)
    except OSError as exc:
        raise OwnershipError(f"cannot inspect {path}", detail=str(exc)) from exc

    owner_name: str | None
    try:
        owner_name = pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        owner_name = str(info.st_uid)

    writable = _writable_by(info, identity) if identity else None
    return DirectoryStatus(
        path=str(path),
        exists=True,
        is_dir=stat.S_ISDIR(info.st_mode),
        owner_uid=info.st_uid,
        owner_gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
        owner_name=owner_name,
        writable=writable,
        why_not_writable=(
            _why_not(path, info, identity, owner_name)
            if writable is False and identity
            else None
        ),
    )


def _why_not(
    path: Path, info: os.stat_result, identity: ServingIdentity, owner_name: str | None
) -> str:
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != identity.uid:
        return (
            f"{path} belongs to {owner_name}, not to {identity.username}, and its "
            f"mode ({mode:04o}) does not grant {identity.username} write access"
        )
    return (
        f"{path} belongs to {identity.username} but its mode ({mode:04o}) does not "
        "include write permission for the owner"
    )


def _writable_by(info: os.stat_result, identity: ServingIdentity) -> bool:
    """Compute the mode bits that apply to `identity`.

    Deliberately not `os.access`: that answers for the *calling* process, which
    is root. A directory also needs the execute bit to be entered at all, so
    both are required.

    Caveat worth knowing: this reads POSIX mode bits only. A directory carrying
    a POSIX ACL that grants write can read as unwritable here, and the share
    would be created read-only when it did not need to be. Erring toward
    read-only is the safe direction — nothing is changed on disk and the user
    is told why.
    """
    if identity.uid == 0:
        return True
    mode = info.st_mode
    if info.st_uid == identity.uid:
        return bool(mode & stat.S_IWUSR) and bool(mode & stat.S_IXUSR)
    if info.st_gid in identity.gids:
        return bool(mode & stat.S_IWGRP) and bool(mode & stat.S_IXGRP)
    return bool(mode & stat.S_IWOTH) and bool(mode & stat.S_IXOTH)


def effective_read_only(
    configured_read_only: bool, status: DirectoryStatus
) -> tuple[bool, str | None]:
    """Return (read_only, reason).

    §3c requires the UI to distinguish "you chose read-only" from "read-only
    because SMBPal cannot write here", because only the second has a fix
    attached. The reason string is that distinction.
    """
    if configured_read_only:
        return True, None
    if status.writable is False:
        return True, f"read-only: {status.why_not_writable}"
    return False, None


def create_directory(path: str | Path, identity: ServingIdentity) -> DirectoryStatus:
    """Create a directory SMBPal will own.

    The uncomplicated case in §3c: SMBPal made the thing, so it sets the
    ownership. No question to answer and nothing of the user's is touched.
    """
    path = Path(path)
    try:
        path.mkdir(parents=True, exist_ok=False, mode=0o755)
        os.chown(path, identity.uid, next(iter(sorted(identity.gids))))
    except FileExistsError:
        raise OwnershipError(f"{path} already exists") from None
    except OSError as exc:
        raise OwnershipError(f"cannot create {path}", detail=str(exc)) from exc
    return inspect_directory(path, identity)


def make_writable(path: str | Path, identity: ServingIdentity) -> DirectoryStatus:
    """The explicit action from §3c, and the only thing that changes a directory.

    Never called as a side effect of adding a share. That is the whole decision.

    It does two things, because doing only one does not achieve what was asked.
    Ownership is the obvious half; the mode is the half that is easy to miss — a
    directory can already belong to the serving user and still be `0500`, in
    which case a chown changes nothing and the share stays read-only while
    claiming to have been fixed.

    **Only the owner's bits are widened.** Group and other are left exactly as
    they were: the request was to let the share write, not to open the folder up.
    """
    path = Path(path)
    status = inspect_directory(path, identity)
    if not status.exists:
        raise NotFound(f"{path} does not exist")
    if not status.is_dir:
        raise OwnershipError(f"{path} is not a directory")

    current_mode = status.mode or 0
    try:
        if status.owner_uid != identity.uid:
            os.chown(path, identity.uid, next(iter(sorted(identity.gids))))
        wanted = current_mode | stat.S_IRWXU
        if wanted != current_mode:
            os.chmod(path, wanted)
    except PermissionError as exc:
        raise OwnershipError(
            f"not permitted to change {path}", detail=str(exc)
        ) from exc
    except OSError as exc:
        raise OwnershipError(f"cannot change {path}", detail=str(exc)) from exc

    result = inspect_directory(path, identity)
    if result.writable is False:
        raise OwnershipError(
            f"{path} is still not writable by {identity.username}",
            detail=result.why_not_writable,
        )
    return result
