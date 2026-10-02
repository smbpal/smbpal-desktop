"""What the agent will answer, and what it refuses to become.

**Four methods.** Mount, unmount, the URL that would remount something, and a
ping. It holds no configuration, writes no files and makes no decisions: the
daemon decides what should be mounted and this does the mounting, because on
macOS the mounting is the part that cannot be done from root.

**Authorisation is one line, and it is not a simplification.** The daemon has
polkit, a group-guarded socket and an `Authoriser`, because it acts for
everyone and must decide whether this caller may. The agent acts for exactly
one person — the one whose Keychain it can read and whose session it runs in —
so the only question is whether the peer is that person. `ipc/peer.py` answers
it from the kernel, and it already implements macOS: `getpeereid(2)` gives uid
and gid, and its docstring says why `pid` is optional rather than a lie.

**And root, which is the caller this exists for.** The daemon asks on behalf of
whoever asked it (`agent/client.py`), so it arrives as uid 0. Admitting root is
not a hole: root can `launchctl asuser` into this session and run anything at
all in it, including something that reads the Keychain, so refusing it here
would protect nothing and would leave the daemon unable to mount. Every other
uid stays refused, which is the question the kernel's answer actually settles.

**A credential never lands here.** `mount` takes a password and hands it
straight to `netfs.mount`, which makes it a `CFString` for the length of one
call. It is not stored, not logged, and not echoed in an error — the detail on
a failure is the status number, never the request.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable

from smbpal.errors import SmbpalError
from smbpal.ipc.protocol import Request, encode_failure, encode_success, parse_request
from smbpal.ipc.transport import Connection
from smbpal.mounts import netfs

log = logging.getLogger(__name__)


class NotYours(SmbpalError):
    code = "not_yours"


class UnknownMethod(SmbpalError):
    code = "unknown_method"


def _require_str(params: dict[str, Any], name: str) -> str:
    value = params.get(name)
    if not isinstance(value, str) or not value:
        raise SmbpalError(f"{name} is required and must be a string")
    return value


class AgentDispatcher:
    """One user's mounting, behind the same protocol the daemon speaks."""

    def __init__(self, *, uid: int | None = None, mounter: Any = netfs) -> None:
        # Injected so the suite can run on Linux, where NetFS does not exist
        # and where CI runs. The default is the real thing.
        self.uid = os.getuid() if uid is None else uid
        self.mounter = mounter

    # --- the methods -------------------------------------------------------

    def _ping(self, _request: Request) -> dict[str, Any]:
        return {"ok": True, "uid": self.uid, "platform_supported": netfs.available()}

    def _mount(self, request: Request) -> dict[str, Any]:
        url = _require_str(request.params, "url")
        where = self.mounter.mount(
            url,
            user=request.params.get("user") or None,
            password=request.params.get("password") or None,
        )
        # The URL is safe to log and the password was never in the message we
        # keep: `request.params` is not logged anywhere, and this line names
        # only what a mount table would show anyway.
        log.info("mounted %s at %s", url, where)
        return {"url": url, "mountpoint": where}

    def _unmount(self, request: Request) -> dict[str, Any]:
        mountpoint = _require_str(request.params, "mountpoint")
        # `unmount` is idempotent and says which it was, so the caller can tell
        # a person "unmounted" from "there was nothing mounted there" rather
        # than reporting the first for both.
        unmounted = bool(self.mounter.unmount(mountpoint))
        return {"mountpoint": mountpoint, "unmounted": unmounted}

    def _remount_url(self, request: Request) -> dict[str, Any]:
        mountpoint = _require_str(request.params, "mountpoint")
        return {
            "mountpoint": mountpoint,
            "url": self.mounter.remount_url(mountpoint),
        }

    # --- who may ask -------------------------------------------------------

    def _may(self, uid: int) -> bool:
        """The owner, and root. Nobody else, which is the real question.

        See the module docstring for why root is not a loophole. Kept as a
        method rather than inlined so that the one-line rule has one place to
        be read, and so a test can state it as a rule rather than as a case.
        """
        return uid in (self.uid, 0)

    # --- the wire ----------------------------------------------------------

    def handle(self, connection: Connection, frame: bytes) -> bytes | None:
        request: Request | None = None
        try:
            request = parse_request(frame)
            # Existence before ownership, for the reason the daemon gives:
            # answering "not yours" for a method that does not exist sends
            # somebody hunting a permission problem they do not have.
            method = self._methods().get(request.method)
            if method is None:
                raise UnknownMethod(f"no such method: {request.method}")
            if not self._may(connection.peer.uid):
                raise NotYours(
                    "this agent serves one person and you are not them",
                    detail=(
                        f"the socket belongs to uid {self.uid} and the caller "
                        f"is uid {connection.peer.uid}"
                    ),
                )
            return encode_success(request.id, method(request))
        except SmbpalError as exc:
            # **The agent's stderr is a log file**, which is the whole point of
            # the plist's `StandardErrorPath` — and until now a refused mount
            # wrote nothing to it. The only record of why was the reply, which
            # goes to the daemon and is gone. Found on 2 October 2026, by
            # reading an empty log after a mount that failed. The method and the
            # code; never the params, one of which can be a password.
            log.info(
                "%s -> %s: %s",
                request.method if request else "<unparsed>",
                exc.code,
                exc.message,
            )
            return encode_failure(request.id if request else None, exc)
        except Exception as exc:  # pragma: no cover - the last resort
            log.exception("agent failed to handle a request")
            return encode_failure(
                request.id if request else None,
                SmbpalError("the agent could not do that", detail=str(exc)),
            )

    def _methods(self) -> dict[str, Callable[[Request], dict[str, Any]]]:
        return {
            "agent.ping": self._ping,
            "agent.mount": self._mount,
            "agent.unmount": self._unmount,
            "agent.remount_url": self._remount_url,
        }
