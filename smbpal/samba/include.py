"""The one line SMBPal adds to somebody else's `smb.conf`.

M0 §1 settled the shape: a marked block, inserted at the top of `[global]`,
removed as a block so no blank line is left behind, and idempotent because the
daemon rewrites config on every share change.

Everything here is a pure string transform, so the properties that matter —
insert twice is insert once, remove after insert is byte-identical — are tested
without a Samba installation or root.
"""

from __future__ import annotations

import re

from smbpal.errors import SmbpalError

SMBPAL_CONF = "/etc/samba/smbpal.conf"
BEGIN_MARKER = "# >>> smbpal >>>"
END_MARKER = "# <<< smbpal <<<"
INCLUDE_LINE = f"include = {SMBPAL_CONF}"

# Samba section names are case-insensitive, and leading whitespace is allowed.
_GLOBAL_HEADER = re.compile(r"^[ \t]*\[global\][ \t]*$", re.IGNORECASE)


class SmbConfError(SmbpalError):
    code = "smb_conf"


def has_include(text: str) -> bool:
    return BEGIN_MARKER in text


def insert_include(text: str, *, include_line: str = INCLUDE_LINE) -> str:
    """Insert the marked block at the top of `[global]`, exactly once.

    Idempotent: M0 ran the insertion twice and got two blocks. Samba tolerated
    it — last definition wins — but the daemon writes config on every share
    change, so "exactly once" has to survive restarts, upgrades and interrupted
    writes.
    """
    if has_include(text):
        return text

    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if _GLOBAL_HEADER.match(line.rstrip("\r\n")):
            ending = _line_ending(line)
            block = [
                f"{BEGIN_MARKER}{ending}",
                f"{include_line}{ending}",
                f"{END_MARKER}{ending}",
            ]
            return "".join(lines[: index + 1] + block + lines[index + 1 :])

    # Refusing beats guessing. Appending is what M0 did, and the line became a
    # parameter of [print$] — the last section of Debian's stock file — where it
    # silently did nothing.
    raise SmbConfError(
        "smb.conf has no [global] section",
        detail="SMBPal will not append the include to the end of the file: it "
        "would become a parameter of whichever section happens to be last.",
    )


def remove_include(text: str, *, include_line: str = INCLUDE_LINE) -> str:
    """Remove the marked block, and any stray bare include of our file.

    Removed as a block, so `smb.conf` comes back byte-identical to what we
    found. M0's line-based removal left a blank line behind and the uninstall
    diff blamed it.

    The stray-line sweep exists because M0 produced duplicate bare includes
    before the guard did. A file that never had one round-trips exactly.
    """
    lines = text.splitlines(keepends=True)
    result: list[str] = []
    inside = False
    for line in lines:
        stripped = line.strip()
        if not inside and stripped == BEGIN_MARKER:
            inside = True
            continue
        if inside:
            if stripped == END_MARKER:
                inside = False
            continue
        if stripped == include_line:
            continue
        result.append(line)

    if inside:
        raise SmbConfError(
            "smb.conf has an unterminated SMBPal block",
            detail=f"{BEGIN_MARKER} with no matching {END_MARKER}. Refusing to "
            "guess where it ends; fix it by hand.",
        )
    return "".join(result)


def _line_ending(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    return "\n"  # last line with no terminator: give the block a real one
