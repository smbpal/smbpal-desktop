"""What SELinux makes of a directory SMBPal is about to serve.

**Read-only, always.** SMBPal reports what the policy says and hands over the
two commands that change it; it does not relabel anybody's filesystem. Sharing a
folder is one step, but silently rewriting system security policy to make that
true is not a step a file-sharing tool gets to take on its own.

Found on Fedora, 27 September 2026: a share under `/home` mounted and
authenticated from a Pi and then refused every write. The directory was
`drwxr-xr-x luke luke` — nothing wrong in Unix terms — and
`unconfined_u:object_r:user_home_t:s0` in SELinux terms, and Samba's policy only
lets `smbd` write `samba_share_t`. Nothing in the failure named SELinux, which
is the part worth fixing: the user sees a share that works until it doesn't.

Everything here is stdlib. `/sys/fs/selinux` is a filesystem and a context is an
extended attribute, so no `libselinux` binding and no `policycoreutils` are
needed to *ask* — only to act, which is the user's half.
"""

from __future__ import annotations

import os
from pathlib import Path

SELINUX_ROOT = Path("/sys/fs/selinux")

# The types Samba's own policy will serve. `samba_share_t` is the one
# `semanage` is told to apply; the two public types are what somebody who has
# already been down this road may have used, and refusing to recognise them
# would send them to fix what is not broken.
SERVEABLE = frozenset(
    {"samba_share_t", "public_content_t", "public_content_rw_t"}
)

# A boolean that makes the label moot. Rather than assume either way, ask: a
# machine with this on is one where somebody has already made this decision.
EXPORT_ALL = "samba_export_all_rw"
HOME_DIRS = "samba_enable_home_dirs"


def enforcing(*, root: Path = SELINUX_ROOT) -> bool:
    """Whether SELinux is on and enforcing, rather than absent or permissive.

    Permissive counts as off here. A permissive machine logs the denial and
    allows the write, so a note telling somebody to fix a label would be
    describing a problem they do not have.
    """
    try:
        return (root / "enforce").read_text().strip() == "1"
    except OSError:
        return False


def boolean(name: str, *, root: Path = SELINUX_ROOT) -> bool:
    """One SELinux boolean's current value.

    `/sys/fs/selinux/booleans/<name>` holds "current pending"; the first is what
    is in force now.
    """
    try:
        return (root / "booleans" / name).read_text().split()[0] == "1"
    except (OSError, IndexError):
        return False


def context_type(path: str) -> str | None:
    """The type field of a path's SELinux context, or None if it has none."""
    try:
        raw = os.getxattr(path, "security.selinux")
    except (OSError, AttributeError):
        # AttributeError: os.getxattr does not exist on every platform, and the
        # GUI's tests run on some of them.
        return None
    parts = raw.decode("utf-8", "replace").rstrip("\x00").split(":")
    return parts[2] if len(parts) > 2 else None


def unserveable(path: str, *, root: Path = SELINUX_ROOT) -> dict[str, str] | None:
    """Why Samba will not be allowed to serve `path`, or None if it will be.

    None is also the answer on every machine without SELinux, which is most of
    them: this must cost nothing and say nothing on Debian.
    """
    if not enforcing(root=root):
        return None
    if boolean(EXPORT_ALL, root=root):
        return None
    kind = context_type(path)
    if kind is None or kind in SERVEABLE:
        return None
    if kind in {"user_home_t", "user_home_dir_t"} and boolean(HOME_DIRS, root=root):
        # The boolean that exists for exactly this directory. On, and the
        # policy already allows it.
        return None
    return {
        "path": path,
        "type": kind,
        "wanted": "samba_share_t",
        "label": f'sudo semanage fcontext -a -t samba_share_t "{path}(/.*)?"',
        "restore": f"sudo restorecon -Rv {path}",
    }
