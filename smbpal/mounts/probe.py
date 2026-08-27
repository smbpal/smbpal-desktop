"""Asking about a mountpoint without ever blocking on it.

**This module exists because of one observation in M0 §4.** With the remote
unplugged, `ls /mnt/m0` blocked for a protracted period before `soft` let it
fail with `Host is down`. The mount did not hang forever, which is the important
half; the other half is that "eventually" is long enough to be
indistinguishable from a hang to whoever is watching.

The design follows from a distinction that is easy to miss: **"is it mounted?"
and "is it reachable?" are different questions with different costs.**

*Mounted* is answered from `/proc/self/mountinfo`, which is a kernel table. It
never touches the remote filesystem, so it cannot block, and it is the question
almost every caller actually has.

**But the mountpoint appearing in that table is not the answer.** An armed
automount *is* a mount: autofs occupies the mountpoint from the moment the unit
is enabled, whether or not the cifs mount underneath has ever happened. When the
real mount succeeds, both appear, stacked on the same path. So the filesystem
type is the thing that matters, and the first version of this module — which
matched on the path alone — reported every armed automount as connected. It
survived its tests because the fixture contained only `cifs` lines: it agreed
with the assumption instead of testing it. Found on real hardware.

*Reachable* requires touching the filesystem, so it can block for as long as the
kernel decides. It runs on a throwaway thread with our own timeout, and the
caller gets an answer — including "still checking" — within that timeout no
matter what the network is doing. **The blocked thread is never joined**: it
cannot be cancelled, so it is left as a daemon thread to finish or die with the
process, and at most one is in flight per mountpoint.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_MOUNTINFO = Path("/proc/self/mountinfo")
DEFAULT_TIMEOUT = 2.0
DEFAULT_CACHE_SECONDS = 10.0

# mountinfo escapes space, tab, newline and backslash as octal.
_OCTAL = re.compile(r"\\(\d{3})")

# autofs is the trigger, not the filesystem. Anything else at the mountpoint is
# a real mount.
AUTOFS = "autofs"

# What mount.cifs registers as. Anything else holding one of our mountpoints
# belongs to somebody else.
CIFS = "cifs"

MOUNTED = "mounted"
UNREACHABLE = "unreachable"
NOT_MOUNTED = "not mounted"
CHECKING = "checking"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Reachability:
    value: bool | None
    checked_at: float


@dataclass(frozen=True)
class MountEntry:
    mountpoint: str
    fstype: str
    source: str
    # Field 5 of mountinfo: the per-mount options, which always begin with
    # `ro` or `rw`. Not the same as the superblock options after the source,
    # and it is this one that decides whether a write reaches the server.
    options: str = ""

    @property
    def read_only(self) -> bool:
        return "ro" in self.options.split(",")


def mount_entries(
    mountinfo: Path | str = DEFAULT_MOUNTINFO,
) -> list[MountEntry] | None:
    """Every mount the kernel currently has, or None if we cannot tell.

    Reading this file does not touch any mounted filesystem, so a dead NAS
    cannot make this call slow. That is the whole reason it is used in
    preference to `os.path.ismount`, which stats the path and its parent.

    The filesystem type comes from after the `-` separator, which is what
    distinguishes an armed automount from a mount that actually happened.
    """
    try:
        text = Path(mountinfo).read_text(encoding="utf-8")
    except OSError:
        # No procfs — a development Mac. "Unknown" is honest; guessing is not.
        return None

    entries: list[MountEntry] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            # A variable number of optional fields sits between the mount
            # options and the separator, so the separator is found rather than
            # counted to. Searching from 6 avoids matching an earlier field
            # that happens to be a bare "-".
            separator = fields.index("-", 6)
        except ValueError:
            continue
        if len(fields) < separator + 3:
            continue
        entries.append(
            MountEntry(
                mountpoint=_unescape(fields[4]),
                fstype=fields[separator + 1],
                source=_unescape(fields[separator + 2]),
                options=fields[5],
            )
        )
    return entries


def mounted_paths(mountinfo: Path | str = DEFAULT_MOUNTINFO) -> set[str] | None:
    """Mountpoints carrying a real filesystem — autofs triggers excluded."""
    entries = mount_entries(mountinfo)
    if entries is None:
        return None
    return {e.mountpoint for e in entries if e.fstype != AUTOFS}


def _unescape(value: str) -> str:
    return _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), value)


class MountProbe:
    """Answers about mountpoints, never blocking the caller past `timeout`."""

    def __init__(
        self,
        *,
        mountinfo: Path | str = DEFAULT_MOUNTINFO,
        timeout: float = DEFAULT_TIMEOUT,
        cache_seconds: float = DEFAULT_CACHE_SECONDS,
    ) -> None:
        self.mountinfo = Path(mountinfo)
        self.timeout = timeout
        self.cache_seconds = cache_seconds
        self._lock = threading.Lock()
        self._inflight: set[str] = set()
        self._results: dict[str, Reachability] = {}

    # --- the cheap question ------------------------------------------------

    def is_mounted(self, mountpoint: str) -> bool | None:
        """Is a real filesystem mounted here — not merely an automount trigger."""
        return self._has(mountpoint, autofs=False)

    def is_armed(self, mountpoint: str) -> bool | None:
        """Is an automount waiting here? Healthy, and not the same as mounted."""
        return self._has(mountpoint, autofs=True)

    def occupant(self, mountpoint: str) -> MountEntry | None:
        """The real filesystem mounted here, if any. autofs triggers excluded.

        `is_mounted` answers *whether* something is mounted; this answers
        *what*, which is the only way to tell our own share from a USB stick
        udisks2 happened to mount on the same path. Mounting on top of one
        would hide it and leave udisks2 still believing it is reachable there.

        None covers both "nothing is mounted" and "no procfs to read", which
        are not worth distinguishing here: the caller's next move is to write
        systemd units, and a machine without `/proc/self/mountinfo` has no
        systemd either.
        """
        entries = mount_entries(self.mountinfo)
        if entries is None:
            return None
        wanted = os.path.normpath(mountpoint)
        for entry in entries:
            if (
                os.path.normpath(entry.mountpoint) == wanted
                and entry.fstype != AUTOFS
            ):
                return entry
        return None

    def is_read_only(self, mountpoint: str) -> bool | None:
        """Is the mount here read-only? None when we cannot tell.

        **This answers less than it looks like it does, deliberately.** `False`
        means the mount is not itself read-only — it does *not* mean a write
        will succeed, because the server decides that and the only way to ask
        is to try. So `True` is reported as a reason and `False` is reported as
        nothing at all: claiming "writable" would be the same mistake as
        claiming an armed automount is connected.
        """
        entry = self.occupant(mountpoint)
        return entry.read_only if entry is not None else None

    def _has(self, mountpoint: str, *, autofs: bool) -> bool | None:
        entries = mount_entries(self.mountinfo)
        if entries is None:
            return None
        wanted = os.path.normpath(mountpoint)
        return any(
            os.path.normpath(e.mountpoint) == wanted
            and (e.fstype == AUTOFS) == autofs
            for e in entries
        )

    # --- the expensive one -------------------------------------------------

    def reachable(self, mountpoint: str) -> bool | None:
        """True, False, or None for "no answer yet".

        Returns within `timeout` whatever the remote is doing. A fresh result is
        reused for `cache_seconds` so that a status call in a loop does not
        start a probe every time.
        """
        now = time.monotonic()
        with self._lock:
            cached = self._results.get(mountpoint)
            if cached and now - cached.checked_at < self.cache_seconds:
                return cached.value
            already_running = mountpoint in self._inflight
            if not already_running:
                self._inflight.add(mountpoint)

        if already_running:
            # Someone else is already blocked on this path. Starting a second
            # probe would only add a second blocked thread.
            return cached.value if cached else None

        done = threading.Event()
        outcome: dict[str, bool] = {}

        def check() -> None:
            try:
                os.stat(mountpoint)
                outcome["value"] = True
            except OSError:
                # `Host is down`, `Permission denied`, anything: the mountpoint
                # is not usable, which is the only distinction this makes.
                outcome["value"] = False
            finally:
                done.set()
                with self._lock:
                    self._inflight.discard(mountpoint)
                    self._results[mountpoint] = Reachability(
                        outcome.get("value"), time.monotonic()
                    )

        # Daemon thread, never joined. It cannot be cancelled — a blocked stat
        # on a cifs mount is uninterruptible until the kernel gives up — so it
        # is left to finish on its own or die with the process.
        threading.Thread(
            target=check, name=f"smbpal-probe-{mountpoint}", daemon=True
        ).start()

        if not done.wait(self.timeout):
            log.debug("probe of %s did not answer within %ss", mountpoint, self.timeout)
            return None
        return outcome.get("value")

    # --- what callers actually want ----------------------------------------

    def state(self, mountpoint: str, *, deep: bool = False) -> str:
        """One word for the UI.

        `deep=False` — the default — answers from the kernel's mount table alone
        and cannot block at all. Only pass `deep=True` somewhere that can afford
        to wait up to `timeout`, and never from a thread the GUI or the IPC
        socket depends on.
        """
        mounted = self.is_mounted(mountpoint)
        if mounted is None:
            return UNKNOWN
        if not mounted:
            return NOT_MOUNTED
        if not deep:
            return MOUNTED
        reachable = self.reachable(mountpoint)
        if reachable is None:
            return CHECKING
        return MOUNTED if reachable else UNREACHABLE
