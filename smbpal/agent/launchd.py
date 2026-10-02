"""Installing the agent as a LaunchAgent, and the plist that describes it.

**Why this is generated rather than shipped.** The `.deb` can ship a static
`smbpald.service` because `/usr/bin/smbpald` is `/usr/bin/smbpald` on every
Debian machine. A Homebrew prefix is `/opt/homebrew` on Apple silicon and
`/usr/local` on Intel (D11 ships macOS as a formula, §11.1), so a static plist
would name a path that is wrong on one of the two architectures. The plist is
therefore written at install time from the path of the program doing the
installing.

**The path recorded is the symlink, not its target.** Homebrew's `bin` is
symlinks into `Cellar/smbpal/<version>/bin`, so resolving the link would pin
the plist to the version installed today and leave launchd pointing into an
empty Cellar directory after the next `brew upgrade`. `os.path.abspath` makes
the path absolute — which launchd requires — without following the link.

**`KeepAlive` is conditional on purpose.** `{"SuccessfulExit": false}` restarts
the agent if it dies, and leaves it stopped after a clean exit, which is what
`launchctl bootout` and a SIGTERM at logout produce. The cost is that a program
path that no longer exists — `brew uninstall` without `--uninstall` first, or a
prefix that moved — becomes a spawn failure every ten seconds forever. Hence
`status()`, which compares the plist against what an install would write now,
and says so rather than reporting a healthy-looking job that cannot start.

**No credential appears here.** The plist is world-readable by convention and
holds a program path, a socket path and a log path. D13 puts the credential in
the login Keychain and passes it as a `CFString`; nothing about the job
definition needs to know it exists.
"""

from __future__ import annotations

import logging
import os
import plistlib
import shutil
import sys
import time
from pathlib import Path

from smbpal.errors import SmbpalError
from smbpal.system.run import CommandRunner, run

log = logging.getLogger(__name__)

LAUNCHCTL = "launchctl"

# §13 fixes the reverse-DNS identifiers on `app.smbpal.*`, and this is the
# per-user half of the pair: `app.smbpal.SMBPal.Helper` is the privileged
# helper, deferred with the `.app`.
LABEL = "app.smbpal.SMBPal.Agent"

PROGRAM_NAME = "smbpal-agent"


class LaunchdError(SmbpalError):
    code = "launchd"


def plist_path(*, home: Path | None = None) -> Path:
    """`~/Library/LaunchAgents`, which is the per-user domain and needs no root."""
    return (home or Path.home()) / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def log_path(*, home: Path | None = None) -> Path:
    """Where launchd will send stdout and stderr.

    A launchd job's output goes to `/dev/null` unless the plist says otherwise,
    so without these keys the startup line and every error the agent prints are
    discarded. `~/Library/Logs` is where Console.app looks.
    """
    return (home or Path.home()) / "Library" / "Logs" / "SMBPal" / "agent.log"


def domain(*, uid: int | None = None) -> str:
    """`gui/<uid>`, not `user/<uid>`.

    The two differ in exactly the way that matters here: the GUI domain exists
    only for a logged-in Aqua session, which is the session whose login
    Keychain is unlocked and whose Finder shows the mount. An agent in
    `user/<uid>` would also be loaded for an SSH login, where it can do neither.
    """
    return f"gui/{os.getuid() if uid is None else uid}"


def service_target(*, uid: int | None = None) -> str:
    return f"{domain(uid=uid)}/{LABEL}"


def _checked(path: str) -> str:
    """Refuse a program launchd could only fail to run."""
    if not Path(path).exists():
        raise LaunchdError(
            "that program is not there",
            detail=f"{path} does not exist, and launchd would retry it forever",
        )
    if not os.access(path, os.X_OK):
        raise LaunchdError(
            "that program is not executable",
            detail=f"{path} exists but has no execute bit, so launchd cannot run it",
        )
    return path


def program_path(override: str | os.PathLike[str] | None = None) -> str:
    """The absolute path to put in `ProgramArguments`, symlinks intact.

    Tried in order: what the caller asked for; `sys.argv[0]` when this really is
    the installed console script rather than `python -m`; and `PATH`. The error
    names the flag that fixes it, because the one case that reaches it — a
    checkout run with `python -m smbpal.agent.main` and nothing installed — is a
    developer who can answer the question.

    An explicit `--program` is checked for existence and the execute bit, since
    `KeepAlive` would otherwise turn a typo into a job launchd respawns every
    ten seconds for as long as the account exists.
    """
    if override:
        return _checked(os.path.abspath(os.fspath(override)))
    argv0 = sys.argv[0] if sys.argv else ""
    if argv0 and Path(argv0).name == PROGRAM_NAME and Path(argv0).exists():
        return os.path.abspath(argv0)
    found = shutil.which(PROGRAM_NAME)
    if found:
        return os.path.abspath(found)
    raise LaunchdError(
        f"cannot tell where {PROGRAM_NAME} is installed",
        detail=(
            f"{PROGRAM_NAME} is not on PATH and this is not it, so there is no "
            "absolute path to write into the plist. Pass --program with the "
            "path launchd should run."
        ),
    )


def plist(
    *,
    program: str,
    socket: Path,
    log_file: Path,
) -> dict[str, object]:
    """The job definition. Every key here is one we can say why we set."""
    return {
        "Label": LABEL,
        # The socket is named rather than left to the default so that the plist
        # is a complete description of how the agent runs, and so `status()`
        # can notice when the two have drifted apart.
        "ProgramArguments": [program, "--socket", str(socket)],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        # The default for an agent, stated because it is load-bearing: see
        # `domain()`.
        "LimitLoadToSessionType": "Aqua",
        "StandardOutPath": str(log_file),
        "StandardErrorPath": str(log_file),
    }


def write_plist(
    *,
    program: str,
    socket: Path,
    log_file: Path,
    path: Path,
) -> dict[str, object]:
    contents = plist(program=program, socket=socket, log_file=log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    # A temporary file and a rename, so an interrupted write cannot leave
    # launchd a half-written plist to refuse at the next login.
    temporary = path.with_suffix(".plist.new")
    with temporary.open("wb") as handle:
        plistlib.dump(contents, handle)
    temporary.replace(path)
    return contents


# launchd's own `exit timeout` prints as 5 seconds, so this is that with room.
GONE_TIMEOUT = 10.0
_POLL_SECONDS = 0.1


def bootout(
    *,
    uid: int | None = None,
    runner: CommandRunner | None = None,
    timeout: float = GONE_TIMEOUT,
) -> bool:
    """Unload the job and wait for it to actually be gone.

    **`launchctl bootout` returns before launchd has finished.** It sends the
    running process SIGTERM and allows it `exit timeout` seconds to go, so an
    immediate `bootstrap` of the same label fails with *Bootstrap failed: 5:
    Input/output error* — which reads like a disk problem and means "that label
    is still loaded". Found on 2 October 2026 by reinstalling over an agent that
    was running rather than one that was merely scheduled, which is why the
    first reinstall test passed and the second did not.

    False if it was not loaded, which is not a failure.
    """
    execute = runner or run
    result = execute([LAUNCHCTL, "bootout", service_target(uid=uid)])
    if not result.ok:
        output = (result.stderr or result.stdout).lower()
        if "no such process" in output or "not find" in output:
            return False
        # Anything else is worth saying out loud, but it must not stop an
        # install: the bootstrap that follows will fail loudly if it mattered.
        log.warning("bootout said: %s", (result.stderr or result.stdout).strip())
        return False

    deadline = time.monotonic() + timeout
    while print_job(uid=uid, runner=runner) is not None:
        if time.monotonic() >= deadline:
            raise LaunchdError(
                "launchd still has the old agent loaded",
                detail=(
                    f"`launchctl bootout {service_target(uid=uid)}` succeeded but "
                    f"the job was still there {timeout:g} seconds later. Something "
                    "is refusing to exit; `launchctl print` will say what"
                ),
            )
        time.sleep(_POLL_SECONDS)
    return True


def bootstrap(
    *, path: Path, uid: int | None = None, runner: CommandRunner | None = None
) -> None:
    execute = runner or run
    result = execute([LAUNCHCTL, "bootstrap", domain(uid=uid), str(path)])
    if not result.ok:
        raise LaunchdError(
            "launchd would not load the agent",
            detail=(result.stderr or result.stdout).strip()
            or f"launchctl bootstrap exited {result.returncode}",
        )


def print_job(
    *, uid: int | None = None, runner: CommandRunner | None = None
) -> str | None:
    """`launchctl print` for the job, or None if launchd does not have it."""
    execute = runner or run
    result = execute([LAUNCHCTL, "print", service_target(uid=uid)])
    return result.stdout if result.ok else None


def _field(printed: str, name: str) -> str | None:
    """One `key = value` line out of `launchctl print`.

    The output is a nested block format with no parser anywhere in the system,
    so this reads the lines it needs and ignores the rest. A key that moves
    between macOS releases makes a field `None` rather than breaking the caller.
    Top-level keys come before the nested blocks, and several names recur inside
    them (`state` most of all), so the first match is the job's own.
    """
    for line in printed.splitlines():
        key, sep, value = line.strip().partition(" = ")
        if sep and key == name:
            return value.strip()
    return None


def _why_not_running(printed: str, *, log_file: Path) -> str:
    """Why a loaded job is not running, in the terms launchd actually reports.

    Measured on macOS 26.6 on 2 October 2026, because the three cases are not
    distinguishable from `state` alone and guessing between them is the defect
    D14 names:

    - **`last exit code = N`, N non-zero.** It ran and failed. `KeepAlive` means
      launchd will try again after `minimum runtime`, which prints as 10
      seconds, so this is a loop rather than a one-off.
    - **No `last exit code` at all, with `runs` at 1 or more.** It ran and was
      killed by a signal rather than exiting: launchd drops the key entirely,
      which is the only way to tell this from the case above.
    - **`last exit code = 0`.** It exited cleanly and `KeepAlive`'s
      `SuccessfulExit: false` is doing its job by leaving it alone.
    """
    code = _field(printed, "last exit code")
    runs = _field(printed, "runs")
    if code is not None and code.isdigit() and code != "0":
        return (
            f"it is failing: last exit code {code}, and launchd keeps retrying. "
            f"{log_file} says why"
        )
    if code is None and runs is not None and runs.isdigit() and int(runs) > 0:
        return (
            "it ran and was killed rather than exiting — launchd reports no exit "
            f"code at all. {log_file} may say why"
        )
    if code == "0":
        return (
            "it exited cleanly and launchd is leaving it stopped, which is what "
            "KeepAlive is set to do. Start it with: launchctl kickstart "
            f"{service_target()}"
        )
    return "launchd has it but it is not running, and reports no reason yet"


def install(
    *,
    program: str | os.PathLike[str] | None = None,
    socket: Path,
    home: Path | None = None,
    uid: int | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, object]:
    """Write the plist, load it, and then check that launchd really has it.

    The verification is not ceremony. `launchctl bootstrap` has historically
    exited 0 having done nothing, and an installer that reports success it has
    not confirmed is the failure mode that cost an afternoon on the options
    probe.
    """
    resolved = program_path(program)
    path = plist_path(home=home)
    contents = write_plist(
        program=resolved,
        socket=socket,
        log_file=log_path(home=home),
        path=path,
    )
    # Reinstalling over a loaded job: bootstrap refuses while the old one is
    # there, so unload first. Whether it was loaded is not interesting.
    was_loaded = bootout(uid=uid, runner=runner)
    bootstrap(path=path, uid=uid, runner=runner)
    printed = print_job(uid=uid, runner=runner)
    if printed is None:
        raise LaunchdError(
            "launchd accepted the agent and then did not have it",
            detail=(
                f"`launchctl bootstrap {domain(uid=uid)} {path}` succeeded but "
                f"`launchctl print {service_target(uid=uid)}` found nothing"
            ),
        )
    return {
        "label": LABEL,
        "plist": str(path),
        "program": resolved,
        "socket": str(socket),
        "log": str(log_path(home=home)),
        "replaced": was_loaded,
        "pid": _field(printed, "pid"),
        "contents": contents,
    }


def uninstall(
    *,
    home: Path | None = None,
    uid: int | None = None,
    socket: Path | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, object]:
    """Unload and remove. Idempotent, and it says which parts were there.

    Logs and `Application Support` are left alone: they are the user's, and
    nothing about them starts a process. The socket goes, because with the job
    unloaded nobody owns it and a stale socket file is a thing a later version
    would have to guess about.
    """
    was_loaded = bootout(uid=uid, runner=runner)
    path = plist_path(home=home)
    existed = path.exists()
    path.unlink(missing_ok=True)
    socket_removed = False
    if socket is not None and socket.exists():
        socket.unlink()
        socket_removed = True
    return {
        "label": LABEL,
        "plist": str(path),
        "was_loaded": was_loaded,
        "plist_existed": existed,
        "socket_removed": socket_removed,
    }


def status(
    *,
    socket: Path,
    program: str | os.PathLike[str] | None = None,
    home: Path | None = None,
    uid: int | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, object]:
    """What launchd has, what the plist says, and whether they still agree.

    `stale` is the field with a reason to exist. `KeepAlive` means a job whose
    program has moved — `brew uninstall`, or an Intel prefix on a migrated
    machine — is respawned and fails every ten seconds, and `launchctl print`
    describes that as a job that exists. Comparing the plist against what an
    install would write now turns it into a sentence somebody can act on.
    """
    path = plist_path(home=home)
    recorded: dict[str, object] | None = None
    if path.exists():
        try:
            with path.open("rb") as handle:
                recorded = plistlib.load(handle)
        except (plistlib.InvalidFileException, ValueError) as exc:
            raise LaunchdError(
                "the agent's plist is there but is not a plist",
                detail=f"{path}: {exc}",
            ) from exc

    printed = print_job(uid=uid, runner=runner)
    arguments = list(recorded.get("ProgramArguments", [])) if recorded else []
    recorded_program = arguments[0] if arguments else None
    recorded_socket = arguments[2] if len(arguments) > 2 else None

    drift: list[str] = []
    if recorded_program is not None:
        if not Path(recorded_program).exists():
            drift.append(f"the plist runs {recorded_program}, which is not there")
        else:
            try:
                expected = program_path(program)
            except LaunchdError:
                expected = recorded_program
            if expected != recorded_program:
                drift.append(
                    f"the plist runs {recorded_program} and this is {expected}"
                )
    if recorded_socket is not None and recorded_socket != str(socket):
        drift.append(
            f"the plist names {recorded_socket} and the default is now {socket}"
        )

    state = _field(printed, "state") if printed else None
    # `state = running` is the only value that means the agent can answer, and
    # the first version of this function returned success for `spawn scheduled`
    # on a job that had never once started. That is the whole reason --status
    # exists, so it is the one line here that is not bookkeeping.
    failing: str | None = None
    if printed is not None and state != "running":
        failing = _why_not_running(printed, log_file=log_path(home=home))

    return {
        "label": LABEL,
        "plist": str(path),
        "installed": recorded is not None,
        "loaded": printed is not None,
        "pid": _field(printed, "pid") if printed else None,
        "last_exit_code": _field(printed, "last exit code") if printed else None,
        "runs": _field(printed, "runs") if printed else None,
        "state": state,
        "program": recorded_program,
        "socket": recorded_socket,
        "log": str(log_path(home=home)),
        "socket_present": socket.exists(),
        "stale": drift,
        "failing": failing,
        "ok": recorded is not None
        and printed is not None
        and failing is None
        and not drift,
    }
