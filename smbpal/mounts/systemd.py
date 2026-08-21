"""Driving systemd units.

M0 §4 established the two rules that matter here. The automount is what keeps
boot from waiting on a NAS — the mount happened on first access, 80 s after
boot, at 541 ms, well behind `NetworkManager-wait-online`. And an unreachable
host retried seven times at 5-second intervals while a wrong password produced
exactly one attempt, which is the distinction M5 will surface and which nothing
here should flatten.
"""

from __future__ import annotations

import logging
from pathlib import Path

from smbpal.errors import SmbpalError
from smbpal.system.run import CommandRunner, run

log = logging.getLogger(__name__)

SYSTEMCTL = "systemctl"
DEFAULT_UNIT_DIR = Path("/etc/systemd/system")


class SystemdError(SmbpalError):
    code = "systemd"


def daemon_reload(*, runner: CommandRunner | None = None) -> None:
    execute = runner or run
    result = execute([SYSTEMCTL, "daemon-reload"])
    if not result.ok:
        raise SystemdError(
            "systemd would not reload its unit files",
            detail=(result.stderr or result.stdout).strip(),
        )


def enable(unit: str, *, now: bool = True, runner: CommandRunner | None = None) -> None:
    execute = runner or run
    argv = [SYSTEMCTL, "enable"] + (["--now"] if now else []) + [unit]
    result = execute(argv)
    if not result.ok:
        raise SystemdError(
            f"could not enable {unit}",
            detail=(result.stderr or result.stdout).strip(),
        )


def disable(unit: str, *, now: bool = True, runner: CommandRunner | None = None) -> None:
    execute = runner or run
    argv = [SYSTEMCTL, "disable"] + (["--now"] if now else []) + [unit]
    result = execute(argv)
    # A unit that was never enabled is not a failure to disable.
    if not result.ok and "not loaded" not in (result.stderr or "").lower():
        log.warning("could not disable %s: %s", unit, (result.stderr or "").strip())


def stop(unit: str, *, runner: CommandRunner | None = None) -> None:
    execute = runner or run
    execute([SYSTEMCTL, "stop", unit])


def reset_failed(unit: str, *, runner: CommandRunner | None = None) -> None:
    """Clear a latched failure so systemd will try the unit again.

    **A Pi run found why this has to exist.** After five failed mounts in ten
    seconds systemd stops trying and says so:

        mnt-smbpal\\x2dtest.mount: Start request repeated too quickly.

    The unit is then refused *before* mount.cifs runs, so fixing the password
    changes nothing — every later attempt fails identically and for a reason
    that is no longer true. Only `reset-failed` clears the counter. Anything
    that gives the mount a fresh chance must clear it first, or it is offering
    a retry that cannot happen.

    Never an error: a unit that is not failed has nothing to reset.
    """
    execute = runner or run
    execute([SYSTEMCTL, "reset-failed", unit])


def start(unit: str, *, runner: CommandRunner | None = None) -> None:
    execute = runner or run
    result = execute([SYSTEMCTL, "start", unit])
    if not result.ok:
        raise SystemdError(
            f"could not start {unit}",
            detail=(result.stderr or result.stdout).strip(),
        )


def show(unit: str, *properties: str, runner: CommandRunner | None = None) -> dict[str, str]:
    """`systemctl show` as a dict.

    The source for M5's errno translation: a rejected password reaches the user
    as `No such device` from the automount, while `Result=` and the unit's
    journal carry the real `Permission denied` (M0 §4).
    """
    execute = runner or run
    wanted = properties or (
        "ActiveState",
        "SubState",
        "Result",
        "StatusErrno",
        "ExecMainStatus",
    )
    result = execute(
        [SYSTEMCTL, "show", unit, "--property=" + ",".join(wanted)]
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key] = value
    return values


def is_active(unit: str, *, runner: CommandRunner | None = None) -> bool:
    execute = runner or run
    return execute([SYSTEMCTL, "is-active", unit]).stdout.strip() == "active"
