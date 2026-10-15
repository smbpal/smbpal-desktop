"""macOS's mount table, read without blocking, and the kernel's word on volumes.

Two things the reconnect loop (`agent/reconnect.py`) needs and the Linux side
gets from `/proc/self/mountinfo` and systemd: **what is mounted**, and **what
just happened to a volume**.

**What is mounted comes from `getfsstat(2)` with `MNT_NOWAIT`.** That flag is
the M0 §4 requirement restated for this platform: `MNT_WAIT` asks every
filesystem for fresh statistics, and a network volume whose server has gone
answers that the way a cifs mount answers `ls` — eventually, which is long
enough to look like a hang. `MNT_NOWAIT` returns what the kernel already holds
and never touches the server. Read from Python through `ctypes`, the same
technique `netfs.py` uses, so the agent stays free of PyObjC. Measured on
15 October 2026: the structure below is 2168 bytes, which is `sizeof(struct
statfs)` for the 64-bit-inode layout, and the entries it returned matched
`mount(8)` line for line.

**What happened comes from a kqueue `EVFILT_FS` filter**, which delivers the
`VQ_*` flags from `sys/mount.h` whenever any volume is mounted, unmounted, or
stops responding. It carries no volume identity — it says *something* changed,
and the table says what. Measured on 15 October 2026 with a disk image:
`VQ_MOUNT` (0x8) on attach and `VQ_UNMOUNT` (0x10) on unmount, both delivered
to Homebrew's interpreter with no grant of any kind. **`VQ_NOTRESP` and
`VQ_DEAD` are not yet measured against an SMB server going away**, and they are
the flags the loop's eject-versus-lost decision leans on; see that module.

Neither works on Linux, and neither is asked to: the agent exists only on
macOS, and the suite substitutes both.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import select
import sys
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

log = logging.getLogger(__name__)

# `sys/mount.h`.
MNT_NOWAIT = 2
VQ_NOTRESP = 0x0001
VQ_NEEDAUTH = 0x0002
VQ_MOUNT = 0x0008
VQ_UNMOUNT = 0x0010
VQ_DEAD = 0x0020
VQ_NOTRESPLOCK = 0x0080
# The flags that mean a volume's server stopped answering, as opposed to a
# volume coming or going. One mask, so the loop has one question to ask.
VQ_TROUBLE = VQ_NOTRESP | VQ_DEAD | VQ_NOTRESPLOCK

# `EVFILT_FS` from `sys/event.h`. Python's `select` exports the other filters
# as `KQ_FILTER_*` and not this one, so it is named here.
EVFILT_FS = -9

_MAXPATHLEN = 1024
_MFSTYPENAMELEN = 16


class _Statfs(ctypes.Structure):
    """`struct statfs`, the 64-bit-inode layout every current Mac uses."""

    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * _MFSTYPENAMELEN),
        ("f_mntonname", ctypes.c_char * _MAXPATHLEN),
        ("f_mntfromname", ctypes.c_char * _MAXPATHLEN),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


@dataclass(frozen=True)
class SmbMount:
    """One mounted SMB share, as the kernel describes it."""

    host: str
    share: str
    mountpoint: str
    owner_uid: int

    @property
    def key(self) -> tuple[str, str]:
        return mount_key(self.host, self.share)


def mount_key(host: str, share: str) -> tuple[str, str]:
    """What identifies a share across the config and the mount table.

    **Both halves are compared without case.** A hostname is
    case-insensitive by definition, and an SMB share name is case-insensitive
    on every server SMBPal talks to — so `nas.local/Media` in the config and
    `NAS.local/media` in the table are the same mount, and treating them as
    different would have the loop mount a second copy beside the first.
    """
    return (host.strip("[]").lower(), share.lower())


def key_for_url(url: str) -> tuple[str, str]:
    """`mount_key` for an `smb://host/share` URL, as `netfs.smb_url` builds it."""
    parts = urlsplit(url)
    return mount_key(parts.hostname or "", unquote(parts.path.lstrip("/").split("/")[0]))


def parse_from_name(source: str) -> tuple[str, str] | None:
    """`(host, share)` from an smbfs `f_mntfromname`, or None.

    The kernel writes `//user@host/share`, or `//host/share` for a guest, with
    the share percent-encoded the way the mount URL had it. A user name can
    carry a domain (`DOMAIN;user@`), which the `@` split absorbs.
    """
    if not source.startswith("//"):
        return None
    rest = source[2:]
    authority, slash, path = rest.partition("/")
    if not slash or not path:
        return None
    host = authority.rpartition("@")[2]
    share = unquote(path.split("/", 1)[0])
    if not host or not share:
        return None
    return host, share


def available() -> bool:
    return sys.platform == "darwin"


def smb_mounts() -> list[SmbMount]:
    """Every mounted SMB share, without asking any server anything."""
    if not available():
        return []
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    # Asked twice because the table can grow between the count and the read;
    # the slack absorbs a mount landing in between, and a shortfall simply
    # means the next tick sees it.
    count = libc.getfsstat(None, 0, MNT_NOWAIT)
    if count < 0:
        log.warning("getfsstat failed with errno %d", ctypes.get_errno())
        return []
    buffer = (_Statfs * (count + 8))()
    count = libc.getfsstat(buffer, ctypes.sizeof(buffer), MNT_NOWAIT)
    if count < 0:
        log.warning("getfsstat failed with errno %d", ctypes.get_errno())
        return []
    found: list[SmbMount] = []
    for entry in buffer[:count]:
        if entry.f_fstypename.decode(errors="replace") != "smbfs":
            continue
        parsed = parse_from_name(entry.f_mntfromname.decode(errors="replace"))
        if parsed is None:
            continue
        found.append(
            SmbMount(
                host=parsed[0],
                share=parsed[1],
                mountpoint=entry.f_mntonname.decode(errors="replace"),
                owner_uid=int(entry.f_owner),
            )
        )
    return found


class VolumeEvents:
    """Waits for the kernel to say a volume changed, or for a timeout.

    `wait` returns the `VQ_*` flags that arrived, OR-ed together, or 0 when the
    timeout passed quietly. Where there is no kqueue — Linux, where the suite
    runs — it simply waits, so the loop above it reads the same either way.
    """

    def __init__(self) -> None:
        self._queue: Any = None
        self._idle = threading.Event()
        if available() and hasattr(select, "kqueue"):
            try:
                self._queue = select.kqueue()
                self._queue.control(
                    [
                        select.kevent(
                            0,
                            filter=EVFILT_FS,
                            flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                        )
                    ],
                    0,
                    0,
                )
            except OSError as exc:
                # Not fatal: the loop still polls on its interval, and only
                # loses the early wake and the not-responding hint.
                log.warning("cannot watch volume events (%s); polling only", exc)
                self._queue = None

    def wait(self, timeout: float) -> int:
        if self._queue is None:
            self._idle.wait(timeout)
            return 0
        flags = 0
        for event in self._queue.control(None, 8, timeout):
            flags |= int(event.fflags)
        return flags

    def close(self) -> None:
        if self._queue is not None:
            self._queue.close()
            self._queue = None
