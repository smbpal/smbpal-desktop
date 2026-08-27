"""Stand-ins for the system commands the daemon runs.

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
_PATH = re.compile(r"^path\s*=\s*(.*)$", re.IGNORECASE)
_INCLUDE = re.compile(r"^\s*include\s*=\s*(\S+)\s*$", re.IGNORECASE)


class FakeSamba:
    """Callable with the CommandRunner signature.

    Covers `testparm`, `smbcontrol`, `smbpasswd`, `pdbedit` and `systemctl` —
    everything the daemon shells out to.
    """

    def __init__(self, smb_conf: Path) -> None:
        self.smb_conf = smb_conf
        self.calls: list[tuple[str, ...]] = []
        self.stdin: list[str | None] = []
        self.smb_users: list[str] = []
        self.reload_count = 0
        self.reload_fails = False
        self.journals: dict[str, str] = {}
        self.unit_state: dict[str, dict[str, str]] = {}
        self.enabled_units: set[str] = set()
        self.started_units: set[str] = set()
        # Units systemd has given up on. A real one refuses `start`
        # outright until `reset-failed`, so this fake does too — a fake
        # that quietly starts them would agree with the bug.
        self.latched: set[str] = set()
        self.daemon_reloads = 0

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
        # Paths as well as names, because real `testparm -s` emits them and a
        # fake that leaves out a field the code reads hides whatever depends
        # on it. See TESTPARM_DUMP in tests/test_samba.py for the real shape.
        lines: list[str] = []
        for name, path in self._resolve_sections():
            lines.append(f"[{name}]")
            if path:
                lines.append(f"\tpath = {path}")
        return CommandResult(argv, 0, "\n".join(lines) + "\n", "Loaded services file OK.\n")

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

    def _systemctl(self, argv, _input) -> CommandResult:
        verb = argv[1]
        if verb == "daemon-reload":
            self.daemon_reloads += 1
            return CommandResult(argv, 0, "", "")
        unit = argv[2] if verb == "show" else argv[-1]
        if verb == "enable":
            self.enabled_units.add(unit)
            if "--now" in argv:
                self.started_units.add(unit)
        elif verb == "disable":
            self.enabled_units.discard(unit)
            self.started_units.discard(unit)
        elif verb == "start":
            if unit in self.latched:
                return CommandResult(
                    argv, 1, "", f"Job failed. See \"journalctl -xe -u {unit}\".\n"
                )
            self.started_units.add(unit)
        elif verb == "reset-failed":
            self.latched.discard(unit)
            if unit in self.unit_state:
                self.unit_state[unit] = {
                    **self.unit_state[unit],
                    "ActiveState": "inactive",
                    "Result": "success",
                }
        elif verb == "stop":
            self.started_units.discard(unit)
        elif verb == "is-active":
            active = "active" if unit in self.started_units else "inactive"
            return CommandResult(argv, 0 if unit in self.started_units else 3, active + "\n", "")
        elif verb == "show":
            properties = self.unit_state.get(
                unit, {"ActiveState": "inactive", "Result": "success"}
            )
            dump = "".join(f"{k}={v}\n" for k, v in properties.items())
            return CommandResult(argv, 0, dump, "")
        return CommandResult(argv, 0, "", "")

    def _journalctl(self, argv, _input) -> CommandResult:
        unit = argv[argv.index("-u") + 1]
        return CommandResult(argv, 0, self.journals.get(unit, ""), "")

    # --- the part that makes this a real check -----------------------------

    def _resolve_sections(self) -> list[tuple[str, str]]:
        """Parse smb.conf the way Samba would: sections, following one include."""
        return self._sections_of(self.smb_conf, depth=0)

    def _sections_of(self, path: Path, depth: int) -> list[tuple[str, str]]:
        if depth > 4:
            return []
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            # M0 §1a: a missing include is silent. Samba starts, testparm says
            # OK, and the share simply is not there.
            return []
        found: list[tuple[str, str]] = []
        for line in text.splitlines():
            section = _SECTION.match(line)
            if section:
                found.append((section.group(1), ""))
                continue
            path_line = _PATH.match(line.strip())
            if path_line and found:
                name, _ = found[-1]
                found[-1] = (name, path_line.group(1).strip())
                continue
            included = _INCLUDE.match(line)
            if included:
                found.extend(self._sections_of(Path(included.group(1)), depth + 1))
        return found
