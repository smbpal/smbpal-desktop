"""A stand-in for Samba that reads the files we wrote.

Deliberately not a rubber stamp. `testparm` here parses `smb.conf`, follows the
`include =` line, and reports the sections it actually finds — so if the include
block is missing or the generated file is malformed, the share does not appear
and `verify_present` fails for the real reason. That is the M0 §1a finding under
test rather than merely commented.
"""

from __future__ import annotations

import re
from pathlib import Path

from smbpal.system.run import CommandResult

_SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*$")
_INCLUDE = re.compile(r"^\s*include\s*=\s*(\S+)\s*$", re.IGNORECASE)


class FakeSamba:
    """Callable with the CommandRunner signature."""

    def __init__(self, smb_conf: Path) -> None:
        self.smb_conf = smb_conf
        self.calls: list[tuple[str, ...]] = []
        self.stdin: list[str | None] = []
        self.smb_users: list[str] = []
        self.reload_count = 0
        self.reload_fails = False

    def __call__(
        self, argv, *, input: str | None = None, timeout: float | None = None
    ) -> CommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        self.stdin.append(input)
        handler = getattr(self, f"_{argv[0].replace('-', '_')}", None)
        if handler is None:
            return CommandResult(argv, 127, "", f"{argv[0]}: not found")
        return handler(argv, input)

    # --- commands ----------------------------------------------------------

    def _testparm(self, argv, _input) -> CommandResult:
        sections = self._resolve_sections()
        dump = "\n".join(f"[{name}]" for name in sections)
        return CommandResult(argv, 0, dump + "\n", "Loaded services file OK.\n")

    def _smbcontrol(self, argv, _input) -> CommandResult:
        if self.reload_fails:
            return CommandResult(argv, 1, "", "Failed to send message\n")
        self.reload_count += 1
        return CommandResult(argv, 0, "", "")

    def _smbpasswd(self, argv, stdin) -> CommandResult:
        username = argv[-1]
        if stdin is None or len(stdin.splitlines()) != 2:
            return CommandResult(argv, 1, "", "expected the password twice on stdin\n")
        if username not in self.smb_users:
            self.smb_users.append(username)
        return CommandResult(argv, 0, "", "")

    def _pdbedit(self, argv, _input) -> CommandResult:
        if "-x" in argv:
            username = argv[argv.index("-u") + 1]
            if username not in self.smb_users:
                return CommandResult(argv, 1, "", f"Username not found: {username}\n")
            self.smb_users.remove(username)
            return CommandResult(argv, 0, "", "")
        listing = "".join(f"{u}:1000:\n" for u in self.smb_users)
        return CommandResult(argv, 0, listing, "")

    # --- the part that makes this a real check -----------------------------

    def _resolve_sections(self) -> list[str]:
        """Parse smb.conf the way Samba would: sections, following one include."""
        return self._sections_of(self.smb_conf, depth=0)

    def _sections_of(self, path: Path, depth: int) -> list[str]:
        if depth > 4:
            return []
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            # M0 §1a: a missing include is silent. Samba starts, testparm says
            # OK, and the share simply is not there.
            return []
        found: list[str] = []
        for line in text.splitlines():
            section = _SECTION.match(line)
            if section:
                found.append(section.group(1))
                continue
            included = _INCLUDE.match(line)
            if included:
                found.extend(self._sections_of(Path(included.group(1)), depth + 1))
        return found
