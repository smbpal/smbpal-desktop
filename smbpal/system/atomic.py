"""Writing a file so that no reader ever sees half of it.

Write a temporary in the same directory, fsync it, `os.replace` it into place,
fsync the directory. `os.replace` is atomic within a filesystem, so a reader
sees the old file or the new one and never something in between.

Every file the daemon owns goes through here: the config, the generated
`smbpal.conf`, `smb.conf` itself, and the Avahi service file — Avahi watches its
directory and would happily read a half-written one.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_text(
    path: Path | str,
    text: str,
    *,
    mode: int = 0o644,
    dir_mode: int = 0o755,
    make_parents: bool = True,
) -> None:
    """Atomically replace `path` with `text`. Raises OSError; callers wrap."""
    path = Path(path)
    directory = path.parent
    if make_parents:
        directory.mkdir(parents=True, exist_ok=True, mode=dir_mode)

    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}-")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except OSError:
        tmp_path.unlink(missing_ok=True)
        raise
    _fsync_directory(directory)


def _fsync_directory(directory: Path) -> None:
    # Without this the directory entry can be lost to a power cut even though
    # the file's contents were synced.
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return  # Best effort; the data is already synced.
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
