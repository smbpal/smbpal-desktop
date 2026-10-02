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
from urllib.parse import quote

from smbpal import PROTOCOL_VERSION, __version__
from smbpal.agent.client import AgentClients
from smbpal.config import ConfigStore
from smbpal.config import operations as ops
from smbpal.discovery import discover
from smbpal.discovery.identity import Identity, identify
from smbpal.errors import (
    AlreadyExists,
    InvalidParams,
    NotFound,
    NotPermitted,
    SmbpalError,
    UnknownMethod,
)
from smbpal.daemon import polkit
from smbpal.mounts import inventory, systemd, units
from smbpal.mounts.apply import Mounter
from smbpal.samba import control, passwd
from smbpal.samba.apply import Applier
from smbpal.shares import ownership
from smbpal.system import selinux as selinux_module
from smbpal.state.monitor import StateMonitor, fallback_hint
from smbpal.ipc.peer import PeerCredentials
from smbpal.ipc.protocol import Request, encode_failure, encode_success, parse_request
from smbpal.ipc.transport import Connection

log = logging.getLogger(__name__)
audit = logging.getLogger("smbpal.audit")

Method = Callable[["Dispatcher", Request, PeerCredentials], Any]

# The vocabulary `status` uses for a share. Public and named because a client
# has to say something sensible about each of them, and a client cannot notice
# a state it has never been told exists: a GUI that fell through to printing
# the raw token would explain a share by repeating its state back. Pinned by a
# test in tests/test_gui_model.py, so adding one here fails there.
SHARE_SERVING = "serving"
SHARE_READ_ONLY = "read-only"
SHARE_NOT_SERVED = "not served"
SHARE_DISABLED = "disabled"
SHARE_UNKNOWN = "unknown"
SHARE_UNMANAGED = "unmanaged"

# Both lists carry this one: it is a property of the daemon, not of the record.
NOT_APPLIED = "not applied"

SHARE_STATES = (
    SHARE_SERVING,
    SHARE_READ_ONLY,
    SHARE_NOT_SERVED,
    SHARE_DISABLED,
    SHARE_UNKNOWN,
    SHARE_UNMANAGED,
    NOT_APPLIED,
)


class Authoriser:
    """Decides *may act*, which the socket's group guard does not answer (D4).

    The socket's `0660 root:smbpal` mode answers *may talk*. It cannot answer
    *may act*, because everyone it lets through looks identical to it — and
    from M2 until 30 August 2026 the daemon did not answer it either: any peer
    past the guard could do anything. This class is where that stopped.

    **Three policies, and only one of them is for production.** `polkit` is the
    default and what the package ships. `root` and `group` exist because the
    daemon has to be runnable where polkit is not — a development machine, a
    container, macOS — and the honest way to do that is a flag that says which
    rules are in force and gets logged at startup, rather than a silent
    fallback that makes the weakest policy the one nobody chose.

    **An unmapped mutating method is refused.** The method table is the list of
    things that can be asked for; `ACTIONS` is the list of things that have
    been thought about. A new method appears in the first and not the second by
    forgetting, and the useful direction to fail in is the one that makes the
    author notice. A test asserts the two agree, so the refusal is a backstop
    and not the plan.
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

    # Every mutating method, and the action a user is prompted for when they
    # ask for it. Credentials split across two actions rather than getting a
    # third: an SMB account password is part of sharing a folder, and a
    # connection's password is part of that connection. Neither is a thing on
    # its own that someone would sensibly hold a separate opinion about.
    ACTIONS = {
        "share.add": polkit.MANAGE_SHARES,
        "share.remove": polkit.MANAGE_SHARES,
        "share.make_writable": polkit.MANAGE_SHARES,
        "apply": polkit.MANAGE_SHARES,
        "teardown": polkit.MANAGE_SHARES,
        "credential.set": polkit.MANAGE_SHARES,
        "credential.remove": polkit.MANAGE_SHARES,
        "connection.add": polkit.MANAGE_CONNECTIONS,
        "connection.remove": polkit.MANAGE_CONNECTIONS,
        "connection.set_credentials": polkit.MANAGE_CONNECTIONS,
        "connection.use_fallback": polkit.MANAGE_CONNECTIONS,
        "connection.connect": polkit.USE_CONNECTIONS,
        "connection.disconnect": polkit.USE_CONNECTIONS,
    }

    POLICIES = ("polkit", "root", "group")

    def __init__(
        self,
        *,
        policy: str = "polkit",
        checker: Any | None = None,
    ) -> None:
        if policy not in self.POLICIES:
            raise ValueError(f"unknown authorisation policy: {policy}")
        self.policy = policy
        self.checker = checker if checker is not None else polkit.Polkit()

    def policy_note(self) -> str:
        if self.policy == "polkit":
            where = self.checker.executable() if hasattr(self.checker, "executable") else None
            found = where or "NOT FOUND — every mutation will be refused"
            return f"authorisation: polkit, via {found}"
        if self.policy == "root":
            return "authorisation: mutations require uid 0; polkit is not being asked"
        return (
            "authorisation: INSECURE — any peer past the socket's group guard may "
            "mutate. Development only; polkit is not being asked"
        )

    def check(self, peer: PeerCredentials, method: str) -> None:
        if method in self.READ_ONLY:
            return
        # root can already do all of this with an editor, and the package's own
        # prerm calls `smbpal teardown` as root while dpkg holds the machine.
        # A prompt there would be a removal that hangs waiting for a dialog
        # nobody is looking at.
        if peer.uid == 0:
            return
        if self.policy == "group":
            return
        if self.policy == "root":
            raise self._refusal(peer, method)
        action = self.ACTIONS.get(method)
        if action is None:
            log.error(
                "%s mutates and has no polkit action; refusing it. Add it to "
                "Authoriser.ACTIONS.",
                method,
            )
            raise self._refusal(peer, method)
        if self.checker.check(peer, action):
            return
        raise self._refusal(peer, method, action=action)

    def _refusal(
        self, peer: PeerCredentials, method: str, *, action: str | None = None
    ) -> NotPermitted:
        detail = f"peer {peer.describe()} is not permitted to perform this action"
        if action is not None:
            detail += f" ({action})"
        return NotPermitted(f"{method} requires authorisation", detail=detail)


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
        agents: AgentClients | None = None,
        identity: Callable[[], Identity] = identify,
    ) -> None:
        self.store = store
        # How this machine is reached from others. Injected so tests do not
        # depend on the host's Avahi or its network interfaces.
        self.identity = identity
        self.authoriser = authoriser or Authoriser()
        # None means config-only: useful on a development machine with no
        # Samba, and the reason --no-apply exists.
        self.applier = applier
        self.mounter = mounter
        self.monitor = monitor
        # Set on macOS, where mounting cannot happen here (D13). Not a second
        # mounter: it is the same two operations, performed in the session of
        # whoever asked, by the one process on that machine that is allowed to.
        self.agents = agents

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

        **The undo is not conditioned on what went wrong, and that was a
        defect.** It caught `SmbpalError` alone, which is the failure we
        anticipated; anything else fell past it to `handle`'s catch-all, which
        told the caller "the daemon hit an internal error" and left the saved
        record in place. Reported from a Pi on 20 September 2026: a connection
        added with the wrong password failed that way, and adding it again
        after correcting the password produced **two** connections, one of
        which had never worked. The unanticipated failure is exactly the one
        where least is known about what was applied, so it is the one where
        the config is least entitled to claim anything. `BaseException`
        rather than `Exception` because this is an undo that re-raises
        immediately: nothing is swallowed, and an apply stopped by anything at
        all must not leave the file describing it as done.
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
        except BaseException:
            log.warning("apply failed; rolling the config back")
            self.store.save(previous)
            try:
                if self.applier is not None:
                    self.applier.apply(previous)
                if self.mounter is not None:
                    self.mounter.apply(previous, previous=updated)
            except Exception:
                # Not BaseException here: this one does not re-raise, so
                # swallowing an interrupt would be swallowing it for good. A
                # failure to restore is logged and the original error is what
                # the caller gets, since that is what they asked about.
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
            # What another device types to reach this one (§3d: reported,
            # never set). Asked on every status: two short commands, and a DHCP
            # lease or an Avahi rename can change the answer at any time.
            "host": self.identity().to_wire(),
            "shares": self._share_states(config),
            # Whether anything is actually serving those shares. A share can be
            # in Samba's effective configuration on a machine where Samba is
            # stopped, and every earlier row hid that by running a distribution
            # whose package starts it (see control.service_state).
            "samba": self._samba_state(),
            # Per share, because the answer is about a path rather than about
            # the machine: one share can be serveable and the next not.
            "selinux": [
                problem
                for problem in (
                    selinux_module.unserveable(s["path"])
                    for s in config.get("shares", [])
                    if s.get("path")
                )
                if problem is not None
            ],
            "connections": self._connection_states(config),
            # Reported without being asked for. The case this exists for is one
            # nobody would think to ask about: a connection removed from the
            # config whose automount is still enabled and still mounting.
            "unaccounted": self._unaccounted(config),
        }

    def _samba_state(self) -> dict[str, object]:
        if self.applier is None:
            return {"unit": None, "active": False, "installed": False}
        try:
            return control.service_state(runner=self.applier.runner)
        except SmbpalError:
            # Asking failed, which is not the same as stopped. Saying nothing is
            # better than saying something untrue about somebody's server.
            return {"unit": None, "active": True, "installed": True}

    def _smb_accounts(self) -> set[str] | None:
        """Who has an SMB password here, or None when Samba cannot be asked.

        Plain `pdbedit -L`, names only (see `passwd.list_users`): no hash ever
        leaves Samba to answer this.
        """
        runner = self.applier.runner if self.applier else None
        try:
            return set(passwd.list_users(runner=runner))
        except SmbpalError as exc:
            log.debug("could not list SMB accounts: %s", exc.message)
            return None

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
                {**conn, "state": NOT_APPLIED}
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
            return [{**s, "state": NOT_APPLIED} for s in config.get("shares", [])]

        # Ask Samba what it is actually serving rather than assuming our own
        # writes took (M0 §1a: testparm's verdict proves nothing about our file).
        try:
            effective = control.effective_shares(runner=self.applier.runner)
        except SmbpalError:
            effective = None
        serving = None if effective is None else set(effective)
        accounts = self._smb_accounts()

        rows = []
        for planned in self.applier.plan(config):
            row = planned.to_wire()
            row["can_sign_in"] = _can_sign_in(planned.share, accounts)
            if not planned.share.get("enabled", True):
                row["state"] = SHARE_DISABLED
            elif serving is None:
                row["state"] = SHARE_UNKNOWN
            elif planned.share["name"] in serving:
                row["state"] = SHARE_READ_ONLY if planned.read_only else SHARE_SERVING
            else:
                row["state"] = SHARE_NOT_SERVED
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
                        "state": SHARE_UNMANAGED,
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
        described = self._describe(share, report)
        # SELinux, asked at the one moment the path is in front of somebody.
        # None on every machine without it, which is most of them.
        selinux = selinux_module.unserveable(share["path"])
        # Carried on the response so the CLI and the window can say it at the
        # one moment somebody is watching the share being made. A share that
        # nothing is serving is not an error — Samba may be started next — but
        # it is not the success the caller would otherwise read.
        return {**described, "samba": self._samba_state(), "selinux": selinux}

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

    def _teardown(self, _request: Request, peer: PeerCredentials) -> dict[str, Any]:
        """Undo everything SMBPal put outside the config. §6's claim, reachable.

        **Both teardowns existed and nothing called them.** They were written
        for §6 — `Applier.teardown` removes the include as a *block*, precisely
        because M0's line-based removal left a blank line behind and the diff
        blamed it — and until 27 August 2026 there was no IPC method, no CLI
        verb and no shutdown path that reached either. The reversibility claim
        was implemented, unit-tested and unreachable, so it had never run
        against a real `smb.conf`. M7's `prerm` would have found the same hole.

        **The config is deliberately kept.** This undoes side effects, not
        intent: a later `apply` puts everything back. Removing the record of
        what someone configured is a different act and should be a different
        command.
        """
        if self.applier is None and self.mounter is None:
            raise SmbpalError("this daemon was started with --no-apply")
        samba = self.applier.teardown() if self.applier is not None else {}
        units_removed = self.mounter.teardown() if self.mounter is not None else []
        _audit(peer, "teardown", f"{len(units_removed)} unit(s)")
        return {**samba, "units_removed": units_removed}

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
        if self.monitor is not None:
            # An id is derived from host and share, so this one may be the id of
            # a connection that was removed a moment ago and primed before that.
            # See StateMonitor.forget.
            self.monitor.forget(connection["id"])
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
        # **Only an item SMBPal created.** `replaced` means the person had
        # already stored that password themselves — through Finder, most
        # likely — and removing a connection must not remove their credential
        # for the same server (§10.6, and §6.6's reason for owning our own).
        if (
            self.agents is not None
            and connection.get("keychain_credential") == "created"
            and connection.get("credential_account")
        ):
            self.agents.for_uid(peer.uid).credential_forget(
                str(connection["host"]), str(connection["credential_account"])
            )
        if self.monitor is not None:
            self.monitor.forget(connection["id"])
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
        ref = _require_str(request.params, "ref")
        username = _require_str(request.params, "username")
        password = request.params.get("password")
        if not isinstance(password, str) or not password:
            raise InvalidParams("'password' is required and must be a non-empty string")
        if self.agents is not None:
            return self._set_credentials_in_keychain(ref, username, password, peer)
        if self.mounter is None:
            raise SmbpalError("this daemon was started with --no-apply")

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
        if self.monitor is not None:
            # Credentials are new information about a connection the monitor
            # may already have given up on. `connection add --user` prompts for
            # the password *after* the connection exists, so a poll in between
            # primes it without credentials, the mount is refused, and priming
            # stops — correctly, since a refused credential must not be retried.
            # This is the thing that makes the refusal out of date. Fedora,
            # 27 September 2026.
            self.monitor.forget(connection["id"])
        _audit(peer, "connection.set_credentials", connection["id"])
        return {"id": connection["id"], "username": username}

    def _set_credentials_in_keychain(
        self, ref: str, username: str, password: str, peer: PeerCredentials
    ) -> dict[str, Any]:
        """The macOS half of `connection.set_credentials` (D13).

        **There is no file.** On Linux the password goes into a 0600 root-owned
        file because `mount.cifs` reads it from there. On macOS the reader is
        NetAuthAgent, inside the session, and the store is the login Keychain —
        which root cannot read, which is half of why the agent exists. So this
        hands the password to the agent and keeps nothing.

        **The outcome is recorded because it is a promise about uninstall.**
        One Keychain item per server and account, so storing a password for a
        share the person has already connected to in Finder *replaces their
        item*. §10.6 says SMBPal removes what it created; the item carries no
        mark of ours, so `keychain_credential` is the only place that can know.
        """
        previous = self.store.load()
        connection = _find_connection(previous, ref)
        agent = self.agents.for_uid(peer.uid)
        outcome = agent.credential_set(str(connection["host"]), username, password)

        # **`credential_ref` is not set here, and the first version of this set
        # it to the connection id.** That reference names a file in
        # `/etc/smbpal/credentials`, and on macOS there is no file: the item is
        # found by server *and account*. So the account is what gets recorded —
        # under its own key, because `credential_ref`'s charset is a filename's
        # and a remote account is whatever the server calls it. The bug was not
        # subtle once it ran: `connection remove` asked the Keychain to forget
        # an account called `nas-example-media`, which does not exist, and the
        # real item survived a removal that reported success.
        updated = {
            **previous,
            "connections": [
                {
                    **candidate,
                    "credential_account": username,
                    "keychain_credential": outcome,
                }
                if candidate["id"] == connection["id"]
                else candidate
                for candidate in previous["connections"]
            ],
        }
        self.store.save(updated)
        if self.monitor is not None:
            self.monitor.forget(connection["id"])
        _audit(peer, "connection.set_credentials", connection["id"])
        return {
            "id": connection["id"],
            "username": username,
            "keychain": outcome,
            "note": (
                "Stored in your login Keychain."
                if outcome == "created"
                else "Replaced the login Keychain item that was already there "
                "for that server and account, which SMBPal will leave behind "
                "if you uninstall it."
            ),
        }

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
        if self.agents is not None:
            return self._connect_via_agent(request, peer)
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
        if self.agents is not None:
            return self._disconnect_via_agent(request, peer)
        connection, mount_name = self._unit_for(request)
        systemd.stop(mount_name, runner=self._runner())
        _audit(peer, "connection.disconnect", connection["id"])
        # D14. The unmount is real and the automount stays armed, so anything
        # that touches the path puts it straight back -- on a desktop whose
        # file manager watches the mountpoint that is immediate, and the
        # button looks broken. Found on COSMIC, 30 September 2026; M0 §4 saw
        # the same re-trigger 80 seconds after boot and it read as a
        # curiosity. The CLI has always said this. The window said nothing,
        # and a control whose effect cannot be observed is indistinguishable
        # from one that does not work.
        return {
            "id": connection["id"],
            "unit": mount_name,
            "note": "Unmounted. It will mount again as soon as anything opens "
            "the folder, which on some desktops is immediately.",
        }

    # --- mounting through a per-user agent (macOS, D13) --------------------

    def _connect_via_agent(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        """Mount in the session of whoever asked, not in this process.

        **`peer.uid` is the whole reason this is safe to do.** The daemon acts
        for everyone, so "which session" is not a question it may guess at: the
        answer is the uid the kernel reported for this connection, the same one
        polkit was asked about a moment ago. A mount for somebody else is not
        something the protocol can even express.
        """
        connection = self._connection_for(request)
        agent = self.agents.for_uid(peer.uid)
        url = _smb_url(connection)
        landed = agent.mount(url, user=self._username_for(connection))
        _audit(peer, "connection.connect", connection["id"])
        return {
            "id": connection["id"],
            "url": url,
            "mountpoint": landed,
            **self._record_where_it_landed(connection, landed),
        }

    def _record_where_it_landed(
        self, connection: dict[str, Any], landed: str
    ) -> dict[str, Any]:
        """**macOS chooses the mountpoint, so the record has to learn it.**

        `NetFSMountURLSync` is given no mountpath, by design: the directory has
        to exist and `/Volumes` is `root:wheel`, so an unprivileged agent cannot
        prepare the one place every Mac application looks. Measured 2 October
        2026. Letting macOS choose always works; passing a path would work only
        for a path inside the person's own home, which is the wrong place for a
        network volume on that platform.

        The consequence is a stored `mountpoint` that can be wrong, and
        **`connection.disconnect` unmounts the stored one.** `/Volumes/Media`
        is the derived default and is usually right, but a caller may name
        anything, and two connections to a share of the same name disambiguate
        differently here (`Media on rivendell`) from there (`Media-1`). So
        prediction is unreliable in general and the only reliable source is the
        mount itself.

        Found by reading on 2 October 2026 rather than by running: the
        disconnect test passed because nothing had been mounted, which is
        exactly the case that hides it. Left alone, a share would stay mounted
        after a disconnect that reported success.
        """
        if landed == connection.get("mountpoint"):
            return {}
        previous = self.store.load()
        self.store.save(
            {
                **previous,
                "connections": [
                    {**candidate, "mountpoint": landed}
                    if candidate["id"] == connection["id"]
                    else candidate
                    for candidate in previous.get("connections", [])
                ],
            }
        )
        log.info(
            "%s mounted at %s, not %s; the record now says so",
            connection["id"],
            landed,
            connection.get("mountpoint"),
        )
        return {
            "asked_for": connection.get("mountpoint"),
            "note": (
                f"macOS mounted this at {landed} rather than "
                f"{connection.get('mountpoint')} — it chooses the location, and "
                "SMBPal has recorded where it went so that disconnecting finds it."
            ),
        }

    def _disconnect_via_agent(
        self, request: Request, peer: PeerCredentials
    ) -> dict[str, Any]:
        connection = self._connection_for(request)
        agent = self.agents.for_uid(peer.uid)
        unmounted = agent.unmount(connection["mountpoint"])
        _audit(peer, "connection.disconnect", connection["id"])
        # **The Linux note is false here and must not be repeated.** There it
        # warns that the automount is still armed, so the share comes back the
        # moment anything opens the folder. macOS has no automount: §6.8
        # measured it refusing to reconnect a lost mount at all, which is the
        # reason D13's agent exists. Saying "it will mount again" on a platform
        # where it will not is the D14 defect with the sign reversed.
        return {
            "id": connection["id"],
            "mountpoint": connection["mountpoint"],
            "unmounted": unmounted,
            "note": (
                "Unmounted. macOS will not mount it again by itself — "
                "`smbpal connection connect` does."
                if unmounted
                else "Nothing was mounted there, so nothing changed."
            ),
        }

    def _connection_for(self, request: Request) -> dict[str, Any]:
        """The connection, with no opinion about how it gets mounted.

        `_unit_for` cannot serve here: it names a systemd unit, and it refuses
        when `--no-apply` left the daemon without a mounter — which is the
        normal state of a macOS daemon, since there is no Samba for it to
        apply to and no systemd to apply with.
        """
        return _find_connection(
            self.store.load(), _require_str(request.params, "ref")
        )

    def _username_for(self, connection: dict[str, Any]) -> str | None:
        """The username, and never the password.

        `CredentialsStore` has `username_for` and deliberately has no
        `password_for`: that file is written for `mount.cifs` to read, and the
        daemon reading it back would make root a party to every credential it
        stores. On macOS it does not have to be — the credential belongs to the
        session, in the login Keychain the agent can read and root cannot
        (D13). So this hands over a name and lets the session supply the rest.
        """
        if self.agents is not None:
            # No file to read it out of, so it is in the record. Returning None
            # here instead -- which the first version did, because it went
            # looking for a credentials file that cannot exist -- means mounting
            # as a guest with a credential sitting in the Keychain unused.
            account = connection.get("credential_account")
            return str(account) if account else None
        ref = connection.get("credential_ref")
        if not ref or self.mounter is None:
            return None
        return self.mounter.credentials.username_for(str(ref))

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


def _can_sign_in(share: dict[str, Any], accounts: set[str] | None) -> bool | None:
    """Whether anybody can open this share from another machine at all.

    Found on Ubuntu, 19 September 2026: a folder shared from the window was
    served correctly and nobody could open it. Samba's passwords are its own,
    separate from the login password (§3b), our shares say `guest ok = no`,
    and on a fresh machine nobody has one. `smb.conf` was right and the share
    was useless, which only this can say.

    A share served as one account needs that account to have an SMB password.
    A share with no account named takes any account that has one, so it needs
    at least one. None when Samba could not be asked, which is not the same as
    no.
    """
    if accounts is None:
        return None
    user = share.get("credential_ref")
    if user:
        return user in accounts
    return bool(accounts)


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


def _smb_url(connection: dict[str, Any]) -> str:
    """`smb://host/share`, and nothing else in it.

    **No username and no password, deliberately.** `mount_smbfs` takes the
    credential in the URL, which is the reason §3.2 ruled it out: a URL is the
    kind of string that ends up in an argv, a log line and a mount table.
    `NetFSMountURLSync` takes both as separate arguments (D13), so the URL here
    carries only what it has to.

    The share name is percent-encoded because it is allowed to contain a space
    — `netfs.mount` refuses a string CoreFoundation cannot parse as a URL, and
    does it before touching the network, so this would fail as *not a URL*
    rather than as anything to do with the share. An IPv6 literal is bracketed
    for the same reason.
    """
    host = str(connection["host"])
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    share = quote(str(connection["share"]), safe="")
    return f"smb://{host}/{share}"


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
    "teardown": Dispatcher._teardown,
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
