"""Method dispatch, and the one place authorisation happens.

Every request is untrusted, every reply is framed, and every method passes the
authoriser before it runs. Adding a method should need a new entry in the table
and no new security thinking.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable

from smbpal import PROTOCOL_VERSION, __version__
from smbpal.config import ConfigStore
from smbpal.config import operations as ops
from smbpal.discovery import discover
from smbpal.errors import InvalidParams, NotFound, NotPermitted, SmbpalError, UnknownMethod
from smbpal.samba import control, passwd
from smbpal.samba.apply import Applier
from smbpal.shares import ownership
from smbpal.ipc.peer import PeerCredentials
from smbpal.ipc.protocol import Request, encode_failure, encode_success, parse_request
from smbpal.ipc.transport import Connection

log = logging.getLogger(__name__)
audit = logging.getLogger("smbpal.audit")

Method = Callable[["Dispatcher", Request, PeerCredentials], Any]


class Authoriser:
    """Decides *may act*, which the socket's group guard does not answer (D4).

    **Interim policy, and stated rather than implied.** The plan's answer is
    polkit, which ships with the policy file at M7. Until then, mutating
    methods require root or a peer that got through the socket's 0660
    root:smbpal guard — which is to say, for now *may talk* and *may act* are
    the same answer. The seam is this one method, so replacing it is a local
    change, and every mutation is audited in the meantime.
    """

    READ_ONLY = frozenset(
        {
            "ping",
            "version",
            "config.get",
            "status",
            "share.list",
            "connection.list",
            "credential.list",
            "browse",
        }
    )

    def __init__(self, *, allow_group_mutation: bool = True) -> None:
        self.allow_group_mutation = allow_group_mutation

    def policy_note(self) -> str:
        if self.allow_group_mutation:
            return (
                "authorisation: mutations allowed for any peer past the socket's "
                "group guard (polkit lands with the policy file at M7)"
            )
        return "authorisation: mutations require uid 0"

    def check(self, peer: PeerCredentials, method: str) -> None:
        if method in self.READ_ONLY:
            return
        if peer.uid == 0 or self.allow_group_mutation:
            return
        raise NotPermitted(
            f"{method} requires authorisation",
            detail=f"peer {peer.describe()} is not permitted to perform this action",
        )


class Dispatcher:
    """Turns framed bytes into framed bytes. Owns nothing it does not need to."""

    def __init__(
        self,
        store: ConfigStore,
        *,
        authoriser: Authoriser | None = None,
        applier: Applier | None = None,
    ) -> None:
        self.store = store
        self.authoriser = authoriser or Authoriser()
        # None means config-only: useful on a development machine with no
        # Samba, and the reason --no-apply exists.
        self.applier = applier

    def handle(self, connection: Connection, frame: bytes) -> bytes | None:
        request: Request | None = None
        try:
            request = parse_request(frame)
            # Existence before permission. Answering "requires authorisation"
            # for a method that does not exist sends someone hunting for a
            # permission problem they do not have — the same failure mode M0 §4
            # found in `No such device` for a rejected password. The socket is
            # group-guarded, so method names are not a secret from anyone who
            # can ask.
            method = _METHODS.get(request.method)
            if method is None:
                raise UnknownMethod(f"no such method: {request.method}")
            self.authoriser.check(connection.peer, request.method)
            result = method(self, request, connection.peer)
            return encode_success(request.id, result)
        except SmbpalError as exc:
            log.info(
                "%s -> %s: %s",
                request.method if request else "<unparsed>",
                exc.code,
                exc.message,
            )
            return encode_failure(request.id if request else None, exc)
        except Exception:  # noqa: BLE001 - a handler bug must not kill the daemon
            log.exception(
                "unhandled error in %s", request.method if request else "<unparsed>"
            )
            return encode_failure(
                request.id if request else None,
                SmbpalError("the daemon hit an internal error; see its journal"),
            )

    # --- applying ----------------------------------------------------------

    def _commit(
        self, previous: dict[str, Any], updated: dict[str, Any]
    ) -> Any:
        """Save, then apply — and undo the save if applying fails.

        D12: "a config edit that the daemon has not applied is a lie". So
        being in the config means being applied. If Samba will not take the
        change, the config goes back to what it was and the previous state is
        re-applied, rather than leaving a record of a share that is not served.
        """
        self.store.save(updated)
        if self.applier is None:
            return None
        try:
            return self.applier.apply(updated)
        except SmbpalError:
            log.warning("apply failed; rolling the config back")
            self.store.save(previous)
            try:
                self.applier.apply(previous)
            except SmbpalError:
                log.exception("could not re-apply the previous config after rollback")
            raise

    def _describe(self, share: dict[str, Any], report: Any) -> dict[str, Any]:
        """Merge §3c's effective state into the record the caller gets back."""
        if report is None:
            return share
        for planned in report.shares:
            if planned.share.get("id") == share.get("id"):
                return planned.to_wire()
        return share

    # --- diagnostics -------------------------------------------------------

    def _ping(self, _request: Request, _peer: PeerCredentials) -> dict[str, Any]:
        return {"pong": True}

    def _version(self, _request: Request, _peer: PeerCredentials) -> dict[str, Any]:
        return {"version": __version__, "protocol": PROTOCOL_VERSION}

    def _config_get(self, _request: Request, _peer: PeerCredentials) -> dict[str, Any]:
        # Read through rather than from a cache: the daemon is the only writer
        # (D12), so the file and memory cannot disagree, and reading proves it.
        return self.store.load()

    def _status(self, _request: Request, _peer: PeerCredentials) -> dict[str, Any]:
        config = self.store.load()
        return {
            "daemon": {
                "version": __version__,
                "protocol": PROTOCOL_VERSION,
                "pid": os.getpid(),
                "config": str(self.store.path),
                "applying": self.applier is not None,
            },
            "shares": self._share_states(config),
            # Still "unknown": nothing mounts until M4, and a status line that
            # claims otherwise is the lie D12 warns about. M5 replaces this with
            # real state, pushed rather than polled.
            "connections": [
                {**conn, "state": "unknown"} for conn in config.get("connections", [])
            ],
        }

    def _share_states(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        if self.applier is None:
            return [{**s, "state": "not applied"} for s in config.get("shares", [])]

        # Ask Samba what it is actually serving rather than assuming our own
        # writes took (M0 §1a: testparm's verdict proves nothing about our file).
        try:
            serving = control.effective_share_names(runner=self.applier.runner)
        except SmbpalError:
            serving = None

        rows = []
        for planned in self.applier.plan(config):
            row = planned.to_wire()
            if not planned.share.get("enabled", True):
                row["state"] = "disabled"
            elif serving is None:
                row["state"] = "unknown"
            elif planned.share["name"] in serving:
                row["state"] = "read-only" if planned.read_only else "serving"
            else:
                row["state"] = "not served"
            rows.append(row)
        return rows

    # --- shares ------------------------------------------------------------

    def _share_list(self, _request: Request, _peer: PeerCredentials) -> list[Any]:
        return self.store.load().get("shares", [])

    def _share_add(self, request: Request, peer: PeerCredentials) -> dict[str, Any]:
        params = request.params
        name = _require_str(params, "name")
        path = _require_str(params, "path")
        previous = self.store.load()
        updated, share = ops.add_share(
            previous,
            name=name,
            path=path,
            id=_optional_str(params, "id"),
            read_only=_optional_bool(params, "read_only", default=False),
            credential_ref=_optional_str(params, "credential_ref"),
            enabled=_optional_bool(params, "enabled", default=True),
        )
        report = self._commit(previous, updated)
        _audit(peer, "share.add", share["id"])
        return self._describe(share, report)

    def _share_remove(self, request: Request, peer: PeerCredentials) -> dict[str, Any]:
        ref = _require_str(request.params, "ref")
        previous = self.store.load()
        updated, share = ops.remove_share(previous, ref)
        self._commit(previous, updated)
        _audit(peer, "share.remove", share["id"])
        return share

    def _share_apply(self, _request: Request, peer: PeerCredentials) -> dict[str, Any]:
        """Re-apply the whole config. Idempotent, and the retry after a failure."""
        if self.applier is None:
            raise SmbpalError("this daemon was started with --no-apply")
        report = self.applier.apply(self.store.load())
        _audit(peer, "share.apply", f"{len(report.served)} share(s)")
        return report.to_wire()

    def _share_make_writable(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        """§3c's explicit action — the only thing that changes a directory's owner.

        Never a side effect of adding a share. That is the whole decision.
        """
        ref = _require_str(request.params, "ref")
        config = self.store.load()
        share = _find_share(config, ref)
        user = share.get("credential_ref")
        if not user:
            raise InvalidParams(
                f"share {share['id']!r} has no user assigned",
                detail="Assign one with --user so there is an identity to give "
                "the directory to.",
            )
        identity = ownership.serving_identity(user)
        status = ownership.make_writable(share["path"], identity)
        _audit(peer, "share.make_writable", share["id"])
        if self.applier is not None:
            self.applier.apply(config)
        return {"share": share, "directory": status.to_wire()}

    # --- connections -------------------------------------------------------

    def _connection_list(self, _request: Request, _peer: PeerCredentials) -> list[Any]:
        return self.store.load().get("connections", [])

    def _connection_add(self, request: Request, peer: PeerCredentials) -> dict[str, Any]:
        params = request.params
        updated, connection = ops.add_connection(
            self.store.load(),
            host=_require_str(params, "host"),
            share=_require_str(params, "share"),
            mountpoint=_require_str(params, "mountpoint"),
            id=_optional_str(params, "id"),
            credential_ref=_optional_str(params, "credential_ref"),
            auto_connect=_optional_str(params, "auto_connect") or "on_this_network",
        )
        self.store.save(updated)
        _audit(peer, "connection.add", connection["id"])
        return connection

    def _connection_remove(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        ref = _require_str(request.params, "ref")
        updated, connection = ops.remove_connection(self.store.load(), ref)
        self.store.save(updated)
        _audit(peer, "connection.remove", connection["id"])
        return connection

    # --- credentials -------------------------------------------------------

    def _credential_list(self, _request: Request, _peer: PeerCredentials) -> list[str]:
        runner = self.applier.runner if self.applier else None
        return passwd.list_users(runner=runner)

    def _credential_set(self, request: Request, peer: PeerCredentials) -> dict[str, Any]:
        # `password` is the only parameter in the whole protocol that carries a
        # secret. It is never logged, never echoed back, and never reaches an
        # argv — smbpasswd reads it on stdin (M0 §9).
        username = _require_str(request.params, "username")
        password = request.params.get("password")
        if not isinstance(password, str) or not password:
            raise InvalidParams("'password' is required and must be a non-empty string")
        runner = self.applier.runner if self.applier else None
        passwd.set_password(username, password, runner=runner)
        _audit(peer, "credential.set", username)
        return {"username": username}

    def _credential_remove(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        username = _require_str(request.params, "username")
        runner = self.applier.runner if self.applier else None
        passwd.remove_user(username, runner=runner)
        _audit(peer, "credential.remove", username)
        return {"username": username}

    # --- discovery ---------------------------------------------------------

    def _browse(self, request: Request, _peer: PeerCredentials) -> list[Any]:
        # §3e: the browse belongs to the daemon, not the GUI — the CLI needs it
        # too, and M5 already owns a channel to push a live list over.
        timeout = request.params.get("timeout", 5.0)
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise InvalidParams("'timeout' must be a number of seconds")
        timeout = max(1.0, min(float(timeout), 30.0))
        return [machine.to_wire() for machine in discover(timeout=timeout)]


def _find_share(config: dict[str, Any], ref: str) -> dict[str, Any]:
    for share in config.get("shares", []):
        if share.get("id") == ref or str(share.get("name", "")).lower() == ref.lower():
            return share
    raise NotFound(f"no share called {ref!r}")


def _audit(peer: PeerCredentials, method: str, subject: str) -> None:
    # An audit line carries who and what, never any parameter that could hold a
    # secret. M0 §9: sudo journals the full command line, and anyone in `adm`
    # can read it.
    audit.info("%s %s by %s", method, subject, peer.describe())


def _require_str(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value:
        raise InvalidParams(f"'{key}' is required and must be a non-empty string")
    return value


def _optional_str(params: dict[str, Any], key: str) -> str | None:
    value = params.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidParams(f"'{key}' must be a string when present")
    return value


def _optional_bool(params: dict[str, Any], key: str, *, default: bool) -> bool:
    value = params.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise InvalidParams(f"'{key}' must be true or false when present")
    return value


_METHODS: dict[str, Method] = {
    "ping": Dispatcher._ping,
    "version": Dispatcher._version,
    "status": Dispatcher._status,
    "config.get": Dispatcher._config_get,
    "share.list": Dispatcher._share_list,
    "share.add": Dispatcher._share_add,
    "share.remove": Dispatcher._share_remove,
    "share.apply": Dispatcher._share_apply,
    "share.make_writable": Dispatcher._share_make_writable,
    "credential.list": Dispatcher._credential_list,
    "credential.set": Dispatcher._credential_set,
    "credential.remove": Dispatcher._credential_remove,
    "connection.list": Dispatcher._connection_list,
    "connection.add": Dispatcher._connection_add,
    "connection.remove": Dispatcher._connection_remove,
    "browse": Dispatcher._browse,
}
