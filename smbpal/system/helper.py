"""Talking to the privileged helper, which until now nothing did.

Job A built the server side and left no client: `share.list` had been served
since the helper first ran and there was nothing in `smbpal/` that could ask it.
This is the other half.

**The protocol is lines until `END`, and a status line back.** It is written out
in `helper/smbpal-helper.c`, which is the authority; this module is the second
implementation and the one that must not drift, so a test reads the verbs out of
the C.

**The daemon relays the form and does not inspect it.** §10 put the verify in
the helper because §9 established that `smbpald` is admin-writable code: a
helper that trusted the daemon's verdict would be a root-escalation service with
a socket on it. So the 32 bytes travel as hex and the answer comes from the
other end — this module's job is carriage, not judgement.

**Anything but a clean `OK` is a no.** A refusal, a malformed frame, a helper
that is not running and a socket that is not there all arrive at the caller as
"not authorised". There is deliberately no path where a broken helper means
everything is permitted; the same rule `daemon/polkit.py` states for `pkcheck`,
for the same reason.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass

from smbpal.errors import SmbpalError

log = logging.getLogger(__name__)

SOCKET_PATH = "/var/run/smbpal/helper.sock"

# Long enough for `sharing -l` to answer on a machine with a slow disk, short
# enough that a wedged helper does not park a daemon thread for ever. There is
# no prompt at the far end -- §11 measured that the helper cannot prompt even if
# it wanted to -- so nothing here is waiting for a person.
DEFAULT_TIMEOUT = 10.0


# §13's verdicts, in the helper's order. They are also the error tokens
# `share.publish` refuses with, so a refusal can be explained in the same words
# as an inspection. A test reads `PATH_VERDICTS` out of the C.
PATH_VERDICTS = (
    "ok",
    "not-found",
    "not-directory",
    "outside-roots",
    "home-root",
    "system-owned",
)


class HelperError(SmbpalError):
    """The helper did not answer `OK`. The caller's correct response is to stop."""

    def __init__(
        self, message: str, *, detail: str | None = None, token: str | None = None
    ) -> None:
        super().__init__(message, detail=detail)
        # The helper's own word for the refusal, when it gave one. Kept apart
        # from `detail` so a caller can branch on it without parsing prose.
        self.token = token


@dataclass(frozen=True)
class PathFacts:
    """What `path.inspect` reports. Everything but `verdict` is None when the
    path does not resolve, because the helper says nothing more about it."""

    verdict: str
    resolved: str | None = None
    uid: int | None = None
    gid: int | None = None
    mode: int | None = None
    owner: str | None = None
    has_acl: bool = False
    # Only when an account was named: whether an ACE lets it write here
    # ("allow"), stops it ("deny"), or neither ("none").
    access: str | None = None

    @property
    def exists(self) -> bool:
        return self.verdict != "not-found"


def parse_path_facts(payload: bytes) -> PathFacts:
    """Read `path.inspect`'s `key value` lines, refusing anything surprising.

    **A key said twice is a malformed answer, not a correction.** The helper
    refuses to describe a path containing a newline precisely so that a field
    cannot be forged; accepting the last of two `verdict` lines here would hand
    that forgery back.
    """
    fields: dict[str, str] = {}
    known = {"verdict", "resolved", "uid", "gid", "mode", "owner", "acl", "access"}
    for line in payload.decode("utf-8", errors="strict").splitlines():
        key, sep, value = line.partition(" ")
        if not sep or key in fields or key not in known:
            raise HelperError("the helper's path.inspect answer is malformed")
        fields[key] = value
    verdict = fields.get("verdict")
    if verdict not in PATH_VERDICTS:
        raise HelperError("the helper's path.inspect answer has no known verdict")
    if verdict == "not-found":
        return PathFacts(verdict=verdict)
    try:
        return PathFacts(
            verdict=verdict,
            resolved=fields["resolved"],
            uid=int(fields["uid"]),
            gid=int(fields["gid"]),
            mode=int(fields["mode"], 8),
            owner=fields["owner"],
            has_acl=fields["acl"] == "1",
            access=_access(fields.get("access")),
        )
    except (KeyError, ValueError) as exc:
        raise HelperError("the helper's path.inspect answer is malformed") from exc


class Helper:
    """One connection per request, because the helper serves one and closes.

    Not a long-lived connection: `serve_one` is the whole conversation, which
    keeps the root component's state per client at nothing.
    """

    def __init__(
        self, *, path: str = SOCKET_PATH, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        self.path = path
        self.timeout = timeout

    def available(self) -> bool:
        """Whether there is a socket to talk to, for the startup note.

        Deliberately not a `connect`: a probe that opens a connection to decide
        whether it can open a connection is a race with its own answer.
        """
        import os
        import stat

        try:
            return stat.S_ISSOCK(os.stat(self.path).st_mode)
        except OSError:
            return False

    def _frame(self, verb: str, auth: bytes | None, args: tuple[str, ...]) -> bytes:
        # Before building it, not after. The helper rejects these too, and that
        # is the point -- it does not trust this side. Checking here as well
        # turns a refusal that reads as "the helper said no" into a message that
        # names the actual mistake.
        for arg in (verb, *args):
            if "\n" in arg or "\r" in arg:
                raise HelperError(
                    f"{verb} was given an argument containing a newline",
                    detail="it would end the line and be read as a truncated frame",
                )
        lines = [f"VERB {verb}"]
        if auth is not None:
            lines.append(f"AUTH {auth.hex()}")
        lines.extend(f"ARG {arg}" for arg in args)
        lines.append("END")
        return ("\n".join(lines) + "\n").encode()

    def call(
        self, verb: str, *args: str, auth: bytes | None = None
    ) -> bytes:
        """Send one request and return its payload, or raise.

        An empty payload is normal: `auth.check` answers with the status line
        and nothing else.
        """
        frame = self._frame(verb, auth, args)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout)
                client.connect(self.path)
                client.sendall(frame)
                # The helper reads until `END`, so there is nothing to half-close
                # for: shutting down the write side here would be indistinguishable
                # from a truncated request if `END` had not arrived yet.
                chunks: list[bytes] = []
                while True:
                    block = client.recv(65536)
                    if not block:
                        break
                    chunks.append(block)
        except FileNotFoundError as exc:
            raise HelperError(
                "the privileged helper is not running",
                detail=f"no socket at {self.path}; run `smbpal setup`",
            ) from exc
        except PermissionError as exc:
            # The first error a person hits, measured by hitting it: the socket
            # is `0600` and owned by the service account, so only the daemon may
            # ask. Worth a sentence rather than a bare EACCES.
            raise HelperError(
                "only the daemon may talk to the privileged helper",
                detail=(
                    f"{self.path} is 0600 and owned by the service account; "
                    "even root is refused, by the peer check behind the mode"
                ),
            ) from exc
        except socket.timeout as exc:
            raise HelperError(
                f"the helper did not answer {verb} within {self.timeout}s"
            ) from exc
        except OSError as exc:
            raise HelperError(f"could not ask the helper for {verb}", detail=str(exc)) from exc

        answer = b"".join(chunks)
        status, _, payload = answer.partition(b"\n")
        if status == b"OK":
            return payload
        if status.startswith(b"ERR "):
            # The token is the helper's whole vocabulary of failure and is not
            # an echo of the request, so it is safe to pass on verbatim.
            token = status[4:].decode(errors="replace")
            raise HelperError(f"the helper refused {verb}", detail=token, token=token)
        raise HelperError(
            f"the helper answered {verb} with something unrecognised",
            detail=f"{answer[:40]!r}",
        )

    def check_grant(self, right: str, auth: bytes) -> bool:
        """Whether `auth` carries `right`. Any failure is `False`.

        **Not called `check`, which is what it was first.** `Polkit.check`
        takes `(peer, action)` and answers the same question from an identity,
        and `Authoriser` reaches both through one `self.checker`. Two
        incompatible contracts behind one name is a trap for whoever wires up a
        checker next: a mismatch would pass a right where a peer was expected
        and only be caught by whatever attribute the wrong object lacked.
        Different names make the mismatch an obvious `AttributeError` at the
        call rather than a puzzle.
        """
        try:
            self.call("auth.check", right, auth=auth)
        except HelperError as exc:
            # With the detail: "could not ask the helper" alone hid a helper
            # the kernel had killed, and the errno behind it is the reading
            # that says whether anything is listening (12 October 2026).
            log.info("helper refused %s: %s (%s)", right, exc, exc.detail)
            return False
        return True

    def share_list(self) -> bytes:
        """`sharing -l -f json`, as JSON bytes. No authorisation: it is a read."""
        return self.call("share.list")

    def path_inspect(self, path: str, *, user: str | None = None) -> PathFacts:
        """§15: the daemon cannot `stat` inside a home directory, so it asks.

        With `user`, the answer also says whether an ACE lets that account
        write here -- the macOS half of "is this share writable".
        """
        args = (path,) if user is None else (path, user)
        return parse_path_facts(self.call("path.inspect", *args))

    def account_smb(self, user: str) -> bool:
        """Whether `user` can sign in over SMB at all (`SMB-NT` in its
        HASHLIST). The helper answers one bit; the attribute never leaves it."""
        payload = self.call("account.smb", user).decode("utf-8").strip()
        if payload not in ("smb-nt 0", "smb-nt 1"):
            raise HelperError("the helper's account.smb answer is malformed")
        return payload == "smb-nt 1"

    def share_grant(self, path: str, user: str, *, auth: bytes) -> None:
        """`chmod +a` for an existing person: `share.make_writable` on macOS."""
        self.call("share.grant", path, user, auth=auth)

    def share_owned(self) -> list[str]:
        """The sharepoint record names SMBPal published, from the helper's list."""
        return [
            line for line in self.call("share.owned").decode("utf-8").splitlines() if line
        ]

    def share_publish(
        self, name: str, path: str, *, auth: bytes, read_only: bool = False
    ) -> None:
        """`sharing -a`, with §13 applied at the far end. Raises on any refusal.

        `read_only` adds the helper's one fixed token, which becomes `-R 1`.
        Left out entirely when false, so a writable publish is the same
        request it always was and an older helper still understands it.
        """
        extra = ("read-only",) if read_only else ()
        self.call("share.publish", name, path, *extra, auth=auth)

    def share_unpublish(self, name: str, *, auth: bytes) -> None:
        """`sharing -r`, for a record the helper published and nothing else."""
        self.call("share.unpublish", name, auth=auth)


def _access(value: str | None) -> str | None:
    if value is None:
        return None
    if value not in ("allow", "deny", "none"):
        raise HelperError("the helper's path.inspect answer has an unknown access state")
    return value
