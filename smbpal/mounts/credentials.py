"""The cifs credentials file.

§10.6 and M0 §9 between them settle the whole design: the credential lives in a
`0600` root-owned file and only its *path* is ever an argument. M0 confirmed
this works — `ps` during a mount showed only kernel threads, and the single
journalled `password=` line in the entire run was `sudo`'s own audit record of
the deliberately-wrong test, not anything cifs did.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from smbpal.errors import InvalidParams, SmbpalError
from smbpal.system import atomic

log = logging.getLogger(__name__)

DEFAULT_CREDENTIALS_DIR = Path("/etc/smbpal/credentials")

_CREDENTIALS_MODE = 0o600
_CREDENTIALS_DIR_MODE = 0o700

# A value ending up in this file becomes a line in it. A newline in a password
# would inject a second directive, so the file format's own rule is enforced
# rather than assumed.
_FORBIDDEN = re.compile(r"[\r\n\x00]")


class CredentialsError(SmbpalError):
    code = "credentials"


class CredentialsStore:
    def __init__(self, directory: Path | str = DEFAULT_CREDENTIALS_DIR) -> None:
        self.directory = Path(directory)

    def path_for(self, ref: str) -> Path:
        # `ref` is a schema-validated id: [A-Za-z0-9_-], so it cannot escape
        # this directory. Checked again here because this builds a filesystem
        # path from something that arrived over the wire.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", ref):
            raise InvalidParams(f"{ref!r} is not a usable credential reference")
        return self.directory / ref

    def write(
        self, ref: str, *, username: str, password: str, domain: str | None = None
    ) -> Path:
        for label, value in (("username", username), ("password", password)):
            if not value:
                raise InvalidParams(f"the {label} must not be empty")
            if _FORBIDDEN.search(value):
                raise InvalidParams(
                    f"the {label} contains a line break or NUL",
                    detail="cifs reads this file one directive per line.",
                )
        if domain and _FORBIDDEN.search(domain):
            raise InvalidParams("the domain contains a line break or NUL")

        body = f"username={username}\npassword={password}\n"
        if domain:
            body += f"domain={domain}\n"

        path = self.path_for(ref)
        try:
            atomic.write_text(
                path,
                body,
                mode=_CREDENTIALS_MODE,
                dir_mode=_CREDENTIALS_DIR_MODE,
            )
        except OSError as exc:
            raise CredentialsError(f"cannot write {path}", detail=str(exc)) from exc
        # The password is never logged — only that one exists.
        log.info("wrote credentials for %s (username %s)", ref, username)
        return path

    def remove(self, ref: str) -> None:
        path = self.path_for(ref)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise CredentialsError(f"cannot remove {path}", detail=str(exc)) from exc

    def exists(self, ref: str) -> bool:
        return self.path_for(ref).exists()

    def username_for(self, ref: str) -> str | None:
        """Read back only the username. The password is never read out again."""
        try:
            for line in self.path_for(ref).read_text(encoding="utf-8").splitlines():
                if line.startswith("username="):
                    return line.split("=", 1)[1]
        except OSError:
            return None
        return None
