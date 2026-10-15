"""Which of this person's mounts SMBPal made.

**Why it exists.** Removing a connection should unmount what SMBPal mounted for
it, as it does on Linux, and must not unmount a share the person opened in
Finder. The mount table cannot tell the two apart: same user, same server, same
share. So the agent writes down each mount it makes, and on removal unmounts
only those. It is §10.6's rule for Keychain items -- remove what SMBPal
created, never what was already there -- applied to mounts. Found on
15 October 2026: a removed connection's share stayed mounted, and an
unconditional unmount would have taken Finder's mount of the same share with it.

**Keyed by `f_fsid`, not by path.** A share ejected and mounted again in Finder
can land at the same path; only the filesystem id says it is a different
mount. Entries whose mount has gone are pruned whenever the ledger is read.

**Kept in a file**, `mounts.json` beside the agent's socket, because an agent
restart must not forget what it mounted. Without a path it is kept in memory,
which is what the suite uses.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from smbpal.mounts import volumes

log = logging.getLogger(__name__)

FILE_NAME = "mounts.json"


class MountLedger:
    def __init__(
        self,
        path: Path | None = None,
        *,
        mounts: Callable[[], list[volumes.SmbMount]] = volumes.smb_mounts,
    ) -> None:
        self.path = path
        self._mounts = mounts
        self._lock = threading.Lock()
        self._entries: list[dict[str, Any]] = self._load()

    def record(self, mount: volumes.SmbMount) -> None:
        """Remember a mount SMBPal just made."""
        with self._lock:
            self._prune()
            if any(_fsid(e) == mount.fsid for e in self._entries):
                return
            self._entries.append(
                {
                    "host": mount.host,
                    "share": mount.share,
                    "mountpoint": mount.mountpoint,
                    "fsid": list(mount.fsid),
                }
            )
            self._save()

    def owns(self, mount: volumes.SmbMount) -> bool:
        with self._lock:
            return any(_fsid(e) == mount.fsid for e in self._entries)

    def forget(self, mount: volumes.SmbMount) -> None:
        with self._lock:
            kept = [e for e in self._entries if _fsid(e) != mount.fsid]
            if len(kept) != len(self._entries):
                self._entries = kept
                self._save()

    # --- storage -----------------------------------------------------------

    def _prune(self) -> None:
        """Drop entries whose mount is no longer in the table."""
        live = {m.fsid for m in self._mounts()}
        kept = [e for e in self._entries if _fsid(e) in live]
        if len(kept) != len(self._entries):
            self._entries = kept
            self._save()

    def _load(self) -> list[dict[str, Any]]:
        if self.path is None:
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as exc:
            # A ledger that cannot be read means nothing is known to be ours,
            # which leaves mounts in place: the safe direction.
            log.warning("cannot read %s (%s); treating no mount as SMBPal's", self.path, exc)
            return []
        return [e for e in data if isinstance(e, dict) and _fsid(e) is not None] if isinstance(data, list) else []

    def _save(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".mounts-")
            with os.fdopen(handle, "w", encoding="utf-8") as out:
                json.dump(self._entries, out, indent=1)
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except OSError as exc:
            log.warning("cannot write %s: %s", self.path, exc)


def _fsid(entry: dict[str, Any]) -> tuple[int, int] | None:
    value = entry.get("fsid")
    if (
        isinstance(value, list)
        and len(value) == 2
        and all(isinstance(v, int) and not isinstance(v, bool) for v in value)
    ):
        return (value[0], value[1])
    return None
