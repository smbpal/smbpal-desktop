"""Running external commands.

Two rules, both from M0 §9.

**Never a shell.** Every command is an argv list. Nothing user-supplied is
interpolated into a string that something else will parse.

**Never a credential in argv.** `sudo` journals the full command line of
everything it runs, readable by anyone in `adm`, and `ps` shows arguments to
anyone at all. Commands that need a secret read it on stdin — which is why
`input` exists here and why it is never logged.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from typing import Callable, Sequence

from smbpal.errors import SmbpalError

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0


class CommandFailed(SmbpalError):
    code = "command_failed"


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def check(self) -> "CommandResult":
        if self.ok:
            return self
        raise CommandFailed(
            f"{self.argv[0]} failed",
            detail=(self.stderr or self.stdout).strip()
            or f"exit status {self.returncode}",
        )


# Injected in tests so nothing here needs root, Samba, or a network.
CommandRunner = Callable[..., CommandResult]


def run(
    argv: Sequence[str],
    *,
    input: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> CommandResult:
    argv = tuple(argv)
    # Safe to log: by construction no argv here carries a secret. The one that
    # would — smbpasswd — takes its password on stdin, and stdin is never logged.
    log.debug("running %s", " ".join(argv))
    try:
        completed = subprocess.run(
            argv,
            input=input,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CommandFailed(
            f"{argv[0]} is not installed",
            detail=str(exc),
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandFailed(
            f"{argv[0]} did not finish within {timeout:g}s"
        ) from exc
    except OSError as exc:
        raise CommandFailed(f"cannot run {argv[0]}", detail=str(exc)) from exc
    return CommandResult(
        argv=argv,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
