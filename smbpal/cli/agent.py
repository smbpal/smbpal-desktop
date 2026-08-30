"""Registering a text-mode polkit agent, so the CLI can be authorised at all.

**Without this, adding polkit would have broken the CLI rather than secured
it.** polkit prompts through an *agent*, and an agent belongs to a session. A
desktop session has one; an ssh session has none, and the Pi is driven over
ssh. The daemon would ask, polkit would find nobody to ask, and every
`smbpal share add` would come back "requires authorisation" with no way for the
person typing it to say yes. The only remaining route would have been
`sudo smbpal ...`, which takes the uid 0 short-circuit and skips the check
entirely — polkit installed, and nothing ever asked.

`pkttyagent` is polkit's answer and this is the same dance `systemctl` does:
spawn it holding one end of a pipe, and wait. It closes that end once it has
registered, which is the only reliable "ready" signal — starting the request
before then is a race whose loser is a prompt that never appears.

`--fallback` matters as much as the rest: it means *use me only if this session
has no agent already*. Run from a desktop terminal, the GUI's agent still gets
the prompt, in the window, where the user is looking.

**Nothing here is started speculatively.** The agent is spawned on a refusal
and not before, so `smbpal status` costs no fork, and the retry that follows is
the only request that pays for it.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys

from smbpal.daemon.polkit import start_time

log = logging.getLogger(__name__)

# Long enough to be a hung agent rather than a slow one. This is the wait for
# `pkttyagent` to *register*, not for the user to type anything.
READY_TIMEOUT = 10.0


class TtyAgent:
    """A `pkttyagent` for this process's session, for as long as it is held."""

    def __init__(self, pkttyagent: str = "pkttyagent") -> None:
        self.pkttyagent = pkttyagent
        self.process: subprocess.Popen[bytes] | None = None

    def usable(self) -> bool:
        """Is there any point? Three ways there is not, all of them normal."""
        if os.getuid() == 0:
            # root never reaches the polkit path in the daemon at all.
            return False
        if not sys.stdin.isatty():
            # A prompt with nobody able to answer it is worse than a refusal:
            # it hangs a script that would otherwise have failed and said why.
            return False
        return shutil.which(self.pkttyagent) is not None

    def start(self) -> bool:
        if self.process is not None:
            return False
        if not self.usable():
            return False
        read_fd, write_fd = os.pipe()
        os.set_inheritable(write_fd, True)
        try:
            self.process = subprocess.Popen(
                [
                    self.pkttyagent,
                    "--notify-fd",
                    str(write_fd),
                    "--fallback",
                    "--process",
                    f"{os.getpid()},{start_time(os.getpid())}",
                ],
                pass_fds=(write_fd,),
                close_fds=True,
            )
        except (OSError, ValueError) as exc:
            os.close(read_fd)
            os.close(write_fd)
            log.debug("could not start %s: %s", self.pkttyagent, exc)
            return False
        # Ours must go, or the read below waits for a writer that is us.
        os.close(write_fd)
        try:
            self._wait_for(read_fd)
        finally:
            os.close(read_fd)
        if self.process.poll() is not None:
            # It closed the pipe by dying. Nothing is registered.
            self.process = None
            return False
        return True

    def _wait_for(self, read_fd: int) -> None:
        import selectors

        selector = selectors.DefaultSelector()
        selector.register(read_fd, selectors.EVENT_READ)
        try:
            selector.select(timeout=READY_TIMEOUT)
        finally:
            selector.close()

    def stop(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)
        self.process = None

    def __enter__(self) -> TtyAgent:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
