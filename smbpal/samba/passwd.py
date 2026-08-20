"""SMB credentials: `smbpasswd` and `pdbedit`.

Two constraints, both from M0.

**§3b — the POSIX account must exist first.** `smbpasswd -a` cannot create a
user that is not in `/etc/passwd`; Samba's passdb attaches an SMB password to a
POSIX account rather than replacing one. And it prompts for the password twice
*before* failing:

    New SMB password:
    Retype new SMB password:Failed to add entry for user nosuchuser.

So the account is checked before anything asks for a secret, or the user types
a password that is then thrown away and gets an error too late to mean anything.

**§9 — the password goes on stdin, never in argv.** `sudo` journals full command
lines and `ps` shows arguments. `smbpasswd -s` reads from stdin, which is why it
is used here.
"""

from __future__ import annotations

import logging
import pwd
import re

from smbpal.errors import InvalidParams, NotFound, SmbpalError
from smbpal.system.run import CommandRunner, run

log = logging.getLogger(__name__)

SMBPASSWD = "smbpasswd"
PDBEDIT = "pdbedit"

_USERNAME = re.compile(r"\A[a-z_][a-z0-9_-]{0,31}\Z")


class CredentialError(SmbpalError):
    code = "credential"


def posix_user_exists(username: str) -> bool:
    try:
        pwd.getpwnam(username)
    except KeyError:
        return False
    return True


def require_posix_user(username: str) -> None:
    """Check before prompting. §3b: the failure otherwise arrives too late."""
    if not _USERNAME.match(username):
        raise InvalidParams(
            f"{username!r} is not a valid POSIX user name",
            detail="Lower-case letters, digits, '-' and '_', starting with a "
            "letter or underscore.",
        )
    if not posix_user_exists(username):
        raise NotFound(
            f"there is no system account called {username!r}",
            detail="Samba attaches an SMB password to an existing POSIX account; "
            "it cannot create one. Phase 1 shares as an existing user (§3b), so "
            "pick an account that already exists.",
        )


def set_password(
    username: str, password: str, *, runner: CommandRunner | None = None
) -> None:
    """Create or update the SMB password for an existing POSIX account."""
    require_posix_user(username)
    if not password:
        raise InvalidParams("the password must not be empty")

    execute = runner or run
    # -a add (a no-op update if already present), -s read from stdin.
    # The password is written to stdin twice because smbpasswd asks twice.
    # It never appears in argv, and stdin is never logged.
    result = execute(
        [SMBPASSWD, "-a", "-s", username], input=f"{password}\n{password}\n"
    )
    if not result.ok:
        raise CredentialError(
            f"could not set the SMB password for {username!r}",
            detail=(result.stderr or result.stdout).strip()
            or f"{SMBPASSWD} exited {result.returncode}",
        )
    log.info("set SMB password for %s", username)


def remove_user(username: str, *, runner: CommandRunner | None = None) -> None:
    """Remove the SMB account, leaving the POSIX account alone.

    M0 §2 confirmed the separation: after `pdbedit -x`, `id` and `getent passwd`
    both returned the account intact with all its groups.
    """
    execute = runner or run
    result = execute([PDBEDIT, "-x", "-u", username])
    if not result.ok:
        raise CredentialError(
            f"could not remove the SMB account for {username!r}",
            detail=(result.stderr or result.stdout).strip()
            or f"{PDBEDIT} exited {result.returncode}",
        )
    log.info("removed SMB account for %s", username)


def list_users(*, runner: CommandRunner | None = None) -> list[str]:
    """List SMB accounts.

    Plain `-L`. **Never `-L -w`**, which prints password hashes — and §11.3
    publishes full history, so a hash that reaches a log or a capture is a hash
    that is published.
    """
    execute = runner or run
    result = execute([PDBEDIT, "-L"]).check()
    users = []
    for line in result.stdout.splitlines():
        name = line.split(":", 1)[0].strip()
        if name:
            users.append(name)
    return users
