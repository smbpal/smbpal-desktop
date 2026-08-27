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
from typing import Iterable

from smbpal.config.schema import RESERVED_SHARE_NAMES
from smbpal.errors import SmbpalError
from smbpal.system.run import CommandRunner, run

log = logging.getLogger(__name__)

TESTPARM = "testparm"
SMBCONTROL = "smbcontrol"

_SECTION = re.compile(r"^\[([^\]]+)\]\s*$")
_PATH = re.compile(r"^path\s*=\s*(.*)$", re.IGNORECASE)


class ReloadFailed(SmbpalError):
    code = "reload_failed"


class ShareNotServed(SmbpalError):
    """The share was written and Samba reloaded, and it still is not there."""

    code = "share_not_served"


def effective_shares(*, runner: CommandRunner | None = None) -> dict[str, str]:
    """Every section Samba is serving, mapped to its path, from `testparm -s`.

    `-s` suppresses the "Press enter" prompt. Diagnostics go to stderr and the
    dump to stdout, so only stdout is parsed.

    The path is read because a share name on its own does not tell anyone which
    directory a hand-written section is exposing, and that is the first thing
    they will want to know about one they did not create.
    """
    execute = runner or run
    result = execute([TESTPARM, "-s"]).check()
    shares: dict[str, str] = {}
    current: str | None = None
    for line in result.stdout.splitlines():
        stripped = line.strip()
        match = _SECTION.match(stripped)
        if match:
            current = match.group(1)
            shares.setdefault(current, "")
            continue
        if current is None:
            continue
        path = _PATH.match(stripped)
        if path:
            shares[current] = path.group(1).strip()
    return shares


def effective_share_names(*, runner: CommandRunner | None = None) -> set[str]:
    """Every section Samba is actually serving."""
    return set(effective_shares(runner=runner))


def unmanaged_shares(
    configured: Iterable[str], *, runner: CommandRunner | None = None
) -> dict[str, str]:
    """Sections Samba serves that SMBPal did not write.

    **§8 parks adopting these, which is not the same as ignoring them.** The
    definition of done requires that a hand-written share is visible and marked
    rather than quietly absent — someone looking at a list that shows two of
    their five shares will conclude SMBPal broke the other three.

    Samba's own sections are excluded: `[global]` is not a share, and `homes`,
    `printers` and `print$` are machinery.

    Names compare case-insensitively, because Samba resolves them that way and
    a `[media]` that shadows a `[Media]` is the same collision to a client.
    """
    mine = {name.lower() for name in configured}
    return {
        name: path
        for name, path in effective_shares(runner=runner).items()
        if name.lower() not in mine and name.lower() not in RESERVED_SHARE_NAMES
    }


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
