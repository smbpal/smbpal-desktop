"""The one thing the window remembers about the person using it.

**This is the GUI's only writable state, and it is deliberately not config.**
`smbpal.gui.app` says the window holds no state the daemon does not hold and
writes no config, and that stays true: nothing here describes a share, a
connection or a mount, nothing here is read by the daemon or the CLI, and
deleting the file loses nothing but a dismissal. What it records is whether
somebody has told a notice to stop appearing — an answer that belongs to the
person and their desktop, not to the machine's configuration, which is why it
is in `$XDG_CONFIG_HOME` under their own account rather than in
`/etc/smbpal`.

**A flat file of keys, not JSON and not GSettings.** GSettings would want a
schema compiled at install time in both the `.deb` and the `.rpm` for a single
boolean; JSON would want a parser and a corruption story. One key per line
needs neither, and a line nobody recognises is ignored rather than fatal, so a
future version can add and drop notices without migrating anything.

**Uninstalling SMBPal does not remove it.** A package must not reach into
somebody's home directory, so purge leaves this file where it is — which is
also the behaviour anyone would want from a reinstall, and it is one line of
text either way.

**Every failure here is silent on purpose.** A read-only home, a full disk, or
a `$HOME` that does not exist must not stop the window opening — the worst
case of a failed write is that a notice appears again next time, which is the
behaviour of not having dismissed it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

FILE_NAME = "dismissed"


def config_dir() -> Path:
    """`$XDG_CONFIG_HOME/smbpal`, falling back to the spec's default."""
    base = os.environ.get("XDG_CONFIG_HOME") or ""
    root = Path(base) if base.startswith("/") else Path.home() / ".config"
    return root / "smbpal"


def _path() -> Path:
    return config_dir() / FILE_NAME


def dismissed() -> frozenset[str]:
    """The keys somebody has said they do not want to see again."""
    try:
        text = _path().read_text(encoding="utf-8")
    except OSError:
        return frozenset()
    return frozenset(line.strip() for line in text.splitlines() if line.strip())


def is_dismissed(key: str) -> bool:
    return key in dismissed()


def dismiss(key: str) -> None:
    """Remember it, or carry on without remembering it.

    Re-reads before writing rather than keeping the set in memory: two windows
    can be open at once, and the last one to write should not drop what the
    other dismissed.
    """
    keys = set(dismissed())
    if key in keys:
        return
    keys.add(key)
    try:
        directory = config_dir()
        directory.mkdir(parents=True, exist_ok=True)
        (directory / FILE_NAME).write_text(
            "".join(f"{one}\n" for one in sorted(keys)), encoding="utf-8"
        )
    except OSError as exc:
        log.warning("could not remember the dismissal of %s: %s", key, exc)
