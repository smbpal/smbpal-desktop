"""Asking Samba what it thinks, and telling it to re-read.

The important function here is `verify_present`, and M0 §1 is the reason it
exists rather than a `testparm` exit-status check:

    testparm reported `Loaded services file OK.` when the included file was
    malformed **and** when it did not exist at all.

So `testparm`'s verdict says nothing about our file. What it *does* do reliably
is dump the effective configuration — and a share either appears in that dump
or it does not. **We validate by presence.** A typo yields a share that silently
does not exist, and the caller has to be able to report that as a failure.
"""

from __future__ import annotations

import logging
import re

from smbpal.errors import SmbpalError
from smbpal.system.run import CommandRunner, run

log = logging.getLogger(__name__)

TESTPARM = "testparm"
SMBCONTROL = "smbcontrol"

_SECTION = re.compile(r"^\[([^\]]+)\]\s*$")


class ReloadFailed(SmbpalError):
    code = "reload_failed"


class ShareNotServed(SmbpalError):
    """The share was written and Samba reloaded, and it still is not there."""

    code = "share_not_served"


def effective_share_names(*, runner: CommandRunner | None = None) -> set[str]:
    """Every section Samba is actually serving, from `testparm -s`.

    `-s` suppresses the "Press enter" prompt. Diagnostics go to stderr and the
    dump to stdout, so only stdout is parsed.
    """
    execute = runner or run
    result = execute([TESTPARM, "-s"]).check()
    names: set[str] = set()
    for line in result.stdout.splitlines():
        match = _SECTION.match(line.strip())
        if match:
            names.add(match.group(1))
    return names


def reload_config(*, runner: CommandRunner | None = None) -> None:
    """Re-read configuration without restarting.

    M0 §1: `smbcontrol all reload-config` was enough — the share appeared to a
    real client with no `smbd` restart. **M3 never restarts the daemon**, which
    would drop every live session to add a share.
    """
    execute = runner or run
    result = execute([SMBCONTROL, "all", "reload-config"])
    if not result.ok:
        raise ReloadFailed(
            "Samba would not reload its configuration",
            detail=(result.stderr or result.stdout).strip()
            or f"{SMBCONTROL} exited {result.returncode}",
        )


def verify_present(names: set[str], *, runner: CommandRunner | None = None) -> None:
    """Confirm every expected share is in Samba's effective config.

    This is the check that replaces trusting `testparm`'s exit status.
    """
    serving = effective_share_names(runner=runner)
    missing = sorted(set(names) - serving)
    if missing:
        raise ShareNotServed(
            "Samba reloaded but is not serving " + ", ".join(repr(n) for n in missing),
            detail="testparm reports OK even when the included file is malformed "
            "or missing (M0 §1a), so its verdict proves nothing. This check reads "
            "the effective configuration instead, and the share is not in it.",
        )
