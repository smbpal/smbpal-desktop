"""SMBPal — daemon, CLI and GUI as one installable (D4: no version skew)."""

__version__ = "0.1.0"

# The IPC wire version, sent as `v` on every message from the first commit (D4).
# Independent of __version__: the application can move without the protocol moving.
PROTOCOL_VERSION = 1

COPYRIGHT = "Copyright (C) 2026 Luke Hynek"
SOURCE_URL = "https://github.com/smbpal/smbpal-desktop"

# GPLv3 section 6(d) lets a public repository stand in for a source tarball, but
# only if the directions to it travel *with* the object code. The .deb carries
# them in /usr/share/doc/smbpal/copyright; this is the same directions reachable
# from the program itself, which is the copy a user who has lost the package can
# still find. One string, read by every entry point, for the same reason the
# version is one string: three copies of a legal notice is three chances to
# ship a stale one.
LICENCE_NOTICE = f"""{COPYRIGHT}
Licence GPL-3.0-or-later: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Source: {SOURCE_URL}"""


def version_banner(program: str) -> str:
    """The `--version` text: the GNU convention, name and version on line one."""
    return f"{program} {__version__}\n{LICENCE_NOTICE}"
