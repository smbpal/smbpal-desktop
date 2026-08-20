"""Error codes shared by the daemon, the IPC layer and (later) the CLI and GUI.

Codes are a closed set of stable strings, not messages. M0 §4 is the reason: a
failed mount reaches the user as `No such device` while the real cause,
`Permission denied`, sits in the unit's journal. A client that receives a code
can say something true about what happened; a client that receives only prose
can only pass it on.
"""

from __future__ import annotations


class SmbpalError(Exception):
    """Base for every error that is safe to report to a client."""

    code = "internal"

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_wire(self) -> dict[str, object]:
        error: dict[str, object] = {"code": self.code, "message": self.message}
        if self.detail is not None:
            error["detail"] = self.detail
        return error


class BadRequest(SmbpalError):
    """The frame was not a request we can even parse."""

    code = "bad_request"


class UnsupportedVersion(SmbpalError):
    """The client speaks a protocol version this daemon does not."""

    code = "unsupported_version"


class UnknownMethod(SmbpalError):
    code = "unknown_method"


class InvalidParams(SmbpalError):
    code = "invalid_params"


class ConfigInvalid(SmbpalError):
    """The config file exists but does not validate. Never overwritten silently."""

    code = "config_invalid"


class ConfigIOError(SmbpalError):
    code = "config_io"


class NotPermitted(SmbpalError):
    """Authorisation refused. The socket's group guard says *may talk*, not *may act*."""

    code = "not_permitted"


class DaemonUnreachable(SmbpalError):
    """Client-side: no daemon at the socket.

    D12's stated consequence — the CLI cannot work when the daemon is stopped —
    and the plan requires a clear error rather than a stack trace.
    """

    code = "daemon_unreachable"
