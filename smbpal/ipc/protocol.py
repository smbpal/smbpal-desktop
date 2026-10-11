"""The wire format: newline-delimited JSON, one message per line (D4).

Three message shapes, told apart by their keys rather than by a type field:

    request   {"v":1, "id":"...", "method":"...", "params":{...}}
    response  {"v":1, "id":"...", "ok":true,  "result":{...}}
              {"v":1, "id":"...", "ok":false, "error":{"code":..., "message":...}}
    event     {"v":1, "event":"...", "data":{...}}          server → client

**Events exist from the first commit even though nothing emits one yet.** M5
pushes connection state to clients rather than having them poll, and a
request/response-only protocol that later grows a push channel grows it badly.
An event has no `id` because nothing is waiting for it.

Everything arriving on the socket is untrusted input, including the length of a
line: a client that never sends a newline must not be able to make the daemon
allocate without bound.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from smbpal import PROTOCOL_VERSION
from smbpal.errors import BadRequest, SmbpalError, UnsupportedVersion

# One mebibyte. Far above any legitimate request and far below anything that
# threatens the daemon.
MAX_FRAME_BYTES = 1024 * 1024


# `kAuthorizationExternalFormLength`. Stated here rather than imported from
# `smbpal.system.authorization`, because that module is macOS-only and this one
# parses every request on every platform.
AUTH_FORM_BYTES = 32


@dataclass(frozen=True)
class Request:
    id: str
    method: str
    params: dict[str, Any] = field(default_factory=dict)
    # macOS only, and `None` everywhere else. The 32 bytes of an
    # `AuthorizationExternalForm`, relayed to the privileged helper untouched:
    # §10 put the verify in the helper because the daemon is admin-writable
    # code, so this field is carriage and the daemon forms no opinion about it.
    # Not in `params`, because it is not a parameter of any method -- every
    # mutating method would have to declare it, and one that forgot would look
    # like a method that needed no authorisation.
    auth: bytes | None = None


def parse_request(line: bytes) -> Request:
    """Parse one framed line into a Request, or raise a reportable error."""
    if len(line) > MAX_FRAME_BYTES:
        raise BadRequest(
            f"request is larger than the {MAX_FRAME_BYTES} byte limit"
        )
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BadRequest("request is not valid UTF-8", detail=str(exc)) from exc

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BadRequest("request is not valid JSON", detail=exc.msg) from exc

    if not isinstance(doc, dict):
        raise BadRequest("request must be a JSON object")

    version = doc.get("v")
    if version != PROTOCOL_VERSION:
        raise UnsupportedVersion(
            f"this daemon speaks protocol version {PROTOCOL_VERSION}, "
            f"the request declared {version!r}"
        )

    request_id = doc.get("id")
    if not isinstance(request_id, str) or not request_id:
        raise BadRequest("request needs a non-empty string 'id'")

    method = doc.get("method")
    if not isinstance(method, str) or not method:
        raise BadRequest("request needs a non-empty string 'method'")

    params = doc.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise BadRequest("'params' must be an object when present")

    auth = doc.get("auth")
    if auth is None:
        form = None
    elif not isinstance(auth, str):
        raise BadRequest("'auth' must be a hex string when present")
    else:
        # Checked here as well as in the helper. The helper does not trust this
        # side and re-decodes the hex itself, but a malformed field should be
        # named by whoever can name it rather than travelling on to come back
        # as an opaque refusal.
        try:
            form = bytes.fromhex(auth)
        except ValueError as exc:
            raise BadRequest("'auth' is not valid hex", detail=str(exc)) from exc
        if len(form) != AUTH_FORM_BYTES:
            raise BadRequest(
                f"'auth' must be {AUTH_FORM_BYTES} bytes as hex, got {len(form)}"
            )

    return Request(id=request_id, method=method, params=params, auth=form)


def encode_success(request_id: str, result: Any) -> bytes:
    return _encode({"v": PROTOCOL_VERSION, "id": request_id, "ok": True, "result": result})


def encode_failure(request_id: str | None, error: SmbpalError) -> bytes:
    # request_id is None when the frame was too broken to carry one. The client
    # cannot match it to a call, but it can still report what went wrong.
    return _encode(
        {
            "v": PROTOCOL_VERSION,
            "id": request_id,
            "ok": False,
            "error": error.to_wire(),
        }
    )


def encode_event(event: str, data: Any = None) -> bytes:
    return _encode(
        {"v": PROTOCOL_VERSION, "event": event, "data": data if data is not None else {}}
    )


def _encode(message: dict[str, Any]) -> bytes:
    # No embedded newline can survive json.dumps of a dict, so one line out is
    # guaranteed by construction rather than by hoping.
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
