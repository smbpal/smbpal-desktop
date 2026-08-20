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

MOUNTED = "mounted"
UNREACHABLE = "unreachable"
NOT_MOUNTED = "not mounted"
CHECKING = "checking"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Reachability:
    value: bool | None
    checked_at: float


def mounted_paths(mountinfo: Path | str = DEFAULT_MOUNTINFO) -> set[str] | None:
    """Every mountpoint the kernel currently has, or None if we cannot tell.

    Reading this file does not touch any mounted filesystem, so a dead NAS
    cannot make this call slow. That is the whole reason it is used in
    preference to `os.path.ismount`, which stats the path and its parent.
    """
    try:
        text = Path(mountinfo).read_text(encoding="utf-8")
    except OSError:
        # No procfs — a development Mac. "Unknown" is honest; guessing is not.
        return None
    paths: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 5:
            paths.add(_unescape(fields[4]))
    return paths


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
        paths = mounted_paths(self.mountinfo)
        if paths is None:
            return None
        return os.path.normpath(mountpoint) in {os.path.normpath(p) for p in paths}

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
