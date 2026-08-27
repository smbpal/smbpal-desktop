"""Method dispatch, and the one place authorisation happens.

Every request is untrusted, every reply is framed, and every method passes the
authoriser before it runs. Adding a method should need a new entry in the table
and no new security thinking.
"""

from __future__ import annotations

import logging
import os
import pwd
from typing import Any, Callable

from smbpal import PROTOCOL_VERSION, __version__
from smbpal.config import ConfigStore
from smbpal.config import operations as ops
from smbpal.discovery import discover
from smbpal.errors import (
    AlreadyExists,
    InvalidParams,
    NotFound,
    NotPermitted,
    SmbpalError,
    UnknownMethod,
)
from smbpal.mounts import inventory, systemd, units
from smbpal.mounts.apply import Mounter
from smbpal.samba import control, passwd
from smbpal.samba.apply import Applier
from smbpal.shares import ownership
from smbpal.state.monitor import StateMonitor, fallback_hint
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
            "connection.live",
            "credential.list",
            "connection.watch",
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
        mounter: Mounter | None = None,
        monitor: StateMonitor | None = None,
    ) -> None:
        self.store = store
        self.authoriser = authoriser or Authoriser()
        # None means config-only: useful on a development machine with no
        # Samba, and the reason --no-apply exists.
        self.applier = applier
        self.mounter = mounter
        self.monitor = monitor

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
        if self.applier is None and self.mounter is None:
            return None
        try:
            report = self.applier.apply(updated) if self.applier else None
            if self.mounter is not None:
                # `previous` bounds what this change may remove. Without it a
                # commit against a config that never mentioned the units on
                # disk would reap them — see Mounter.apply.
                self.mounter.apply(updated, previous=previous)
            return report
        except SmbpalError:
            log.warning("apply failed; rolling the config back")
            self.store.save(previous)
            try:
                if self.applier is not None:
                    self.applier.apply(previous)
                if self.mounter is not None:
                    self.mounter.apply(previous, previous=updated)
            except SmbpalError:
                log.exception("could not re-apply the previous config after rollback")
            raise

    def _describe(self, share: dict[str, Any], report: Any) -> dict[str, Any]:
        """Merge §3c's effective state into the record the caller gets back."""
        if report is None:
            # D12: "a config edit that the daemon has not applied is a lie."
            # Under --no-apply every edit is exactly that, so the record says so
            # rather than reporting a bare success the caller would read as
            # "it is being served".
            if self.applier is None and self.mounter is None:
                return {
                    **share,
                    "applied": False,
                    "note": "recorded only — this daemon was started with "
                    "--no-apply and is not touching Samba",
                }
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
            "connections": self._connection_states(config),
            # Reported without being asked for. The case this exists for is one
            # nobody would think to ask about: a connection removed from the
            # config whose automount is still enabled and still mounting.
            "unaccounted": self._unaccounted(config),
        }

    def _unaccounted(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        """Mounts and units on this machine that `config` does not describe."""
        if self.mounter is None:
            return []
        findings = inventory.survey(
            config,
            unit_dir=self.mounter.unit_dir,
            mountinfo=self.mounter.probe.mountinfo,
        )
        return [{**f.to_wire(), "message": f.message} for f in findings]

    def _connection_live(
        self, _request: Request, _peer: PeerCredentials
    ) -> list[dict[str, Any]]:
        return self._unaccounted(self.store.load())

    def _connection_states(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        if self.mounter is None:
            return [
                {**conn, "state": "not applied"}
                for conn in config.get("connections", [])
            ]
        # Shallow by construction: `plan` answers from the kernel's mount table
        # and never stats a mountpoint, so a switched-off NAS cannot make
        # `status` slow (M0 §4).
        rows = [planned.to_wire() for planned in self.mounter.plan(config)]
        if self.monitor is None:
            return rows
        # The monitor's view is the real one — it has read the unit and, where
        # it failed, the journal. Reuse it rather than deriving a second opinion
        # that can disagree with the events already pushed to clients.
        for row in rows:
            state = self.monitor.state_for(row["id"])
            if state is None:
                continue
            row.update(
                {
                    "state": state.state,
                    "message": state.message,
                    "errno": state.errno,
                    "read_only": state.read_only,
                    "is_problem": state.is_problem,
                }
            )
            hint = fallback_hint(row, state)
            if hint:
                row["hint"] = hint
        return rows

    def _share_states(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        if self.applier is None:
            return [{**s, "state": "not applied"} for s in config.get("shares", [])]

        # Ask Samba what it is actually serving rather than assuming our own
        # writes took (M0 §1a: testparm's verdict proves nothing about our file).
        try:
            effective = control.effective_shares(runner=self.applier.runner)
        except SmbpalError:
            effective = None
        serving = None if effective is None else set(effective)

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

        if effective is not None:
            # §8 parks adopting these; it does not license hiding them. A list
            # showing two of someone's five shares reads as SMBPal having
            # broken the other three.
            configured = [s.get("name", "") for s in config.get("shares", [])]
            for name, path in sorted(
                control.unmanaged_shares(
                    configured, runner=self.applier.runner
                ).items()
            ):
                rows.append(
                    {
                        "id": "-",
                        "name": name,
                        "path": path or "?",
                        "enabled": True,
                        "state": "unmanaged",
                        "managed": False,
                    }
                )
        return rows

    # --- shares ------------------------------------------------------------

    def _share_list(self, _request: Request, _peer: PeerCredentials) -> list[Any]:
        return self.store.load().get("shares", [])

    def _share_add(self, request: Request, peer: PeerCredentials) -> dict[str, Any]:
        params = request.params
        name = _require_str(params, "name")
        path = _require_str(params, "path")
        previous = self.store.load()
        self._refuse_to_shadow(name, previous)
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

    def _refuse_to_shadow(self, name: str, config: dict[str, Any]) -> None:
        """Do not write a section that shadows one somebody else wrote.

        **This is the enforcing half of "never modified".** SMBPal only ever
        writes `smbpal.conf`, so it cannot edit a hand-written section — but it
        can add a second `[Media]` after theirs, and Samba resolves a duplicate
        by taking the last one. Their share stops working and nothing says so.
        The config's own duplicate check cannot see this: it only knows about
        shares SMBPal put there.
        """
        if self.applier is None:
            return
        try:
            unmanaged = control.unmanaged_shares(
                [s.get("name", "") for s in config.get("shares", [])],
                runner=self.applier.runner,
            )
        except SmbpalError:
            # Cannot ask, so cannot prove a collision. Refusing on a failed
            # testparm would make an unrelated Samba problem look like a name
            # clash.
            return
        for existing in unmanaged:
            if existing.lower() == name.lower():
                raise AlreadyExists(
                    f"Samba is already serving a share called {existing!r} that "
                    f"SMBPal did not create",
                    detail=(
                        f"It is at {unmanaged[existing] or 'an unrecorded path'}. "
                        "Adding a second section with this name would shadow it — "
                        "Samba takes the last one — and SMBPal does not adopt or "
                        "modify shares it did not write. Choose another name."
                    ),
                )

    def _share_remove(self, request: Request, peer: PeerCredentials) -> dict[str, Any]:
        ref = _require_str(request.params, "ref")
        previous = self.store.load()
        updated, share = ops.remove_share(previous, ref)
        self._commit(previous, updated)
        _audit(peer, "share.remove", share["id"])
        return share

    def _apply(self, _request: Request, peer: PeerCredentials) -> dict[str, Any]:
        """Re-apply the whole config. Idempotent, and the retry after a failure.

        **It has to mean the whole config, and until 27 August 2026 it did
        not.** This only ever called the Samba applier, so `smbpal apply` did
        nothing at all to connections — while three separate messages told
        people to run it for exactly that:

        - the state machine, when an automount is not armed: *"nothing will
          mount on access — try `smbpal apply`"*
        - `inventory`, for an orphaned unit: *"`smbpal apply` removes it"*
        - `Mounter.apply` itself clears a latched unit with `reset-failed`,
          on the reasoning that apply is "the command people reach for after
          fixing whatever was wrong"

        None of those worked. A Pi run made it visible from the other side:
        `s apply` answered `serving nothing` with two connections mounted,
        which was true about shares and silent about everything it had not
        done.

        No `previous` is passed: a person typed this, so the full sweep is
        what they asked for. See `Mounter.apply`.
        """
        if self.applier is None:
            raise SmbpalError("this daemon was started with --no-apply")
        config = self.store.load()
        report = self.applier.apply(config)
        wire = report.to_wire()
        wire["connections"] = (
            self.mounter.apply(config).to_wire()["connections"]
            if self.mounter is not None
            else []
        )
        _audit(
            peer,
            "apply",
            f"{len(report.served)} share(s), {len(wire['connections'])} connection(s)",
        )
        return wire

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
        return {
            "share": share,
            "directory": status.to_wire(),
            # Samba applies share parameters at tree connect. A client that was
            # already connected when the share was read-only keeps what it
            # negotiated, and `smbcontrol all reload-config` does not change
            # that. Confirmed on real hardware: a Windows client connecting
            # fresh could write while a Mac holding an older session could not.
            # "I made it writable and it is still read-only" reads as the app
            # being broken, so the app says it first.
            "note": "clients already connected keep the old permissions until "
            "they reconnect",
        }

    # --- connections -------------------------------------------------------

    def _connection_list(self, _request: Request, _peer: PeerCredentials) -> list[Any]:
        return self.store.load().get("connections", [])

    def _connection_add(self, request: Request, peer: PeerCredentials) -> dict[str, Any]:
        params = request.params
        previous = self.store.load()
        updated, connection = ops.add_connection(
            previous,
            host=_require_str(params, "host"),
            share=_require_str(params, "share"),
            # Optional: omitted means "put it where the file manager will
            # show it", which only the daemon can work out (3h).
            mountpoint=_optional_str(params, "mountpoint"),
            id=_optional_str(params, "id"),
            credential_ref=_optional_str(params, "credential_ref"),
            auto_connect=_optional_str(params, "auto_connect") or "on_this_network",
            owner=_optional_str(params, "owner") or _owner_from(peer),
            fallback_host=_optional_str(params, "fallback_host"),
            # Only the daemon can see what is already mounted, and a derived
            # mountpoint that lands on a USB stick is one apply will refuse.
            in_use=(
                self.mounter.occupied_mountpoints() if self.mounter is not None else None
            ),
        )
        self._commit(previous, updated)
        _audit(peer, "connection.add", connection["id"])
        return connection

    def _connection_remove(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        ref = _require_str(request.params, "ref")
        previous = self.store.load()
        updated, connection = ops.remove_connection(previous, ref)
        self._commit(previous, updated)
        if self.mounter is not None and connection.get("credential_ref"):
            self.mounter.forget_credentials(connection["credential_ref"])
        _audit(peer, "connection.remove", connection["id"])
        return connection

    def _connection_set_credentials(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        """Store the remote username and password for a connection.

        `password` is the second and last parameter in the protocol that carries
        a secret. It goes straight into a 0600 root-owned file and is never
        logged, echoed back, or placed in an argv — cifs takes the file's *path*
        (§10.6, M0 §9).
        """
        if self.mounter is None:
            raise SmbpalError("this daemon was started with --no-apply")
        ref = _require_str(request.params, "ref")
        username = _require_str(request.params, "username")
        password = request.params.get("password")
        if not isinstance(password, str) or not password:
            raise InvalidParams("'password' is required and must be a non-empty string")

        previous = self.store.load()
        connection = _find_connection(previous, ref)
        credential_ref = connection.get("credential_ref") or connection["id"]
        self.mounter.credentials.write(
            credential_ref,
            username=username,
            password=password,
            domain=_optional_str(request.params, "domain"),
        )
        updated = {
            **previous,
            "connections": [
                {**c, "credential_ref": credential_ref} if c["id"] == connection["id"] else c
                for c in previous["connections"]
            ],
        }
        # The commit applies, and applying clears any latched failure — which
        # matters here more than anywhere: this is the path someone takes after
        # a rejected password, and new credentials are worthless against a unit
        # systemd has stopped starting. Covered by a test so that stays true.
        self._commit(previous, updated)
        _audit(peer, "connection.set_credentials", connection["id"])
        return {"id": connection["id"], "username": username}

    def _connection_use_fallback(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        """Swap `host` and `fallback_host`, because a person asked.

        A swap rather than a one-way move, so the same command undoes it. §3e
        wanted the recorded address used automatically on a resolution failure;
        building it showed why it must not be — a DHCP lease can be reassigned,
        and failing over silently would send the stored credentials to whatever
        now answers on that address.
        """
        ref = _require_str(request.params, "ref")
        previous = self.store.load()
        connection = _find_connection(previous, ref)
        fallback = connection.get("fallback_host")
        if not fallback:
            raise InvalidParams(
                f"connection {connection['id']!r} has no recorded fallback address",
                detail="Add one with --fallback, or edit the host directly.",
            )
        swapped = {
            **connection,
            "host": fallback,
            "fallback_host": connection["host"],
        }
        updated = {
            **previous,
            "connections": [
                swapped if c["id"] == connection["id"] else c
                for c in previous["connections"]
            ],
        }
        self._commit(previous, updated)
        _audit(peer, "connection.use_fallback", connection["id"])
        return swapped

    def _connection_watch(
        self, _request: Request, _peer: PeerCredentials
    ) -> list[dict[str, Any]]:
        """The current state of every connection, as the monitor sees it.

        A client calls this once to prime itself and then listens for
        `state.changed` events rather than calling it in a loop.
        """
        if self.monitor is None:
            raise SmbpalError("this daemon is not watching connection state")
        return [state.to_wire() for state in self.monitor.snapshot()]

    def _connection_connect(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        connection, mount_name = self._unit_for(request)
        # Clear any latched failure first, or this "connect" is a promise we
        # cannot keep: systemd refuses a start-limited unit without running the
        # mount at all, and returns the same failure as before.
        systemd.reset_failed(mount_name, runner=self._runner())
        systemd.start(mount_name, runner=self._runner())
        _audit(peer, "connection.connect", connection["id"])
        return {"id": connection["id"], "unit": mount_name}

    def _connection_disconnect(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        connection, mount_name = self._unit_for(request)
        systemd.stop(mount_name, runner=self._runner())
        _audit(peer, "connection.disconnect", connection["id"])
        return {"id": connection["id"], "unit": mount_name}

    def _unit_for(self, request: Request) -> tuple[dict[str, Any], str]:
        if self.mounter is None:
            raise SmbpalError("this daemon was started with --no-apply")
        connection = _find_connection(
            self.store.load(), _require_str(request.params, "ref")
        )
        mount_name, _ = units.unit_names(connection["mountpoint"])
        return connection, mount_name

    def _runner(self) -> Any:
        return self.mounter.runner if self.mounter else None

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


def _owner_from(peer: PeerCredentials) -> str | None:
    """Default a connection's owner to whoever asked for it.

    The person adding a connection is the person who will use it, and the
    kernel already told us who they are. Root is not defaulted: a CLI run under
    `sudo` arrives as uid 0, and mounting a NAS as root-owned is almost never
    what was meant — the CLI passes the real user instead.
    """
    if peer.uid == 0:
        return None
    try:
        return pwd.getpwuid(peer.uid).pw_name
    except KeyError:
        return None


def _find_connection(config: dict[str, Any], ref: str) -> dict[str, Any]:
    for connection in config.get("connections", []):
        if connection.get("id") == ref or connection.get("mountpoint") == ref:
            return connection
    raise NotFound(f"no connection called {ref!r}")


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
    "apply": Dispatcher._apply,
    "share.make_writable": Dispatcher._share_make_writable,
    "credential.list": Dispatcher._credential_list,
    "credential.set": Dispatcher._credential_set,
    "credential.remove": Dispatcher._credential_remove,
    "connection.list": Dispatcher._connection_list,
    "connection.add": Dispatcher._connection_add,
    "connection.remove": Dispatcher._connection_remove,
    "connection.set_credentials": Dispatcher._connection_set_credentials,
    "connection.connect": Dispatcher._connection_connect,
    "connection.disconnect": Dispatcher._connection_disconnect,
    "connection.use_fallback": Dispatcher._connection_use_fallback,
    "connection.live": Dispatcher._connection_live,
    "connection.watch": Dispatcher._connection_watch,
    "browse": Dispatcher._browse,
}
