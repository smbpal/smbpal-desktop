"""Loading and saving the config file, atomically, from the first commit.

Two rules this module exists to enforce.

**A partially written config must never be observable.** Write to a temporary
file in the same directory, fsync it, `os.replace` it into place, then fsync the
directory. `os.replace` is atomic within a filesystem, so a reader sees the old
file or the new one and never half of either.

**A config that does not parse is never overwritten.** It is the user's data.
The daemon refuses to start rather than starting empty, because starting empty
looks identical to "all your shares are gone" and the next save would make that
true.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from smbpal.config.schema import empty_config, validate_or_raise
from smbpal.errors import ConfigInvalid, ConfigIOError
from smbpal.system import atomic

DEFAULT_CONFIG_PATH = Path("/etc/smbpal/config.json")

# The config holds no credentials — `credential_ref` names one, it never carries
# one (DoD: "No credential in a process argument, a log line, or the config
# file"). It is still 0600 root-owned: nothing but the daemon reads it, since
# D12 makes every other component a client.
_CONFIG_MODE = 0o600
_CONFIG_DIR_MODE = 0o750


class ConfigStore:
    """Owns the config file. The daemon owns this (D12); nothing else writes."""

    def __init__(self, path: Path | str = DEFAULT_CONFIG_PATH) -> None:
        self.path = Path(path)

    # --- read --------------------------------------------------------------

    def load(self) -> dict[str, Any]:
        """Return the validated config.

        A missing file is a first boot, not an error, and yields an empty config.
        A file that exists and does not parse or does not validate raises.
        """
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return empty_config()
        except OSError as exc:
            raise ConfigIOError(
                f"cannot read {self.path}", detail=str(exc)
            ) from exc

        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigInvalid(
                f"{self.path} is not valid JSON",
                detail=f"line {exc.lineno}, column {exc.colno}: {exc.msg}",
            ) from exc

        return validate_or_raise(doc, source=str(self.path))

    # --- write -------------------------------------------------------------

    def save(self, doc: dict[str, Any]) -> None:
        """Validate then atomically replace the config file.

        Validation happens before anything touches the disk: an invalid document
        must not be able to reach the file even as a temporary.
        """
        validate_or_raise(doc, source="the new config")
        body = json.dumps(doc, indent=2, sort_keys=True) + "\n"

        try:
            atomic.write_text(
                self.path, body, mode=_CONFIG_MODE, dir_mode=_CONFIG_DIR_MODE
            )
        except OSError as exc:
            raise ConfigIOError(f"cannot write {self.path}", detail=str(exc)) from exc
