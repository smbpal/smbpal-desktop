"""Turning config into published sharepoints, and back again.

The macOS counterpart of `samba/apply.py`, with the same contract to the
dispatcher -- `plan`, `apply`, `teardown` -- so D12's save-then-apply-or-roll-
back in `Dispatcher._commit` works unchanged. The order is the Samba one with
Samba's steps swapped for the helper's:

    inspect through the helper -> refuse what §13 refuses -> unpublish ours
    that should go -> publish what is missing -> **verify by presence**

Verify by presence for the same reason as on Linux: `sharing` reported nothing
when given a directory that did not exist (account spike), so the exit status
is not evidence. A share is either in `sharing -l` at the path we meant or it
is not.

**What this does not do yet, and says so rather than pretending.**

- *Read-only shares.* `sharing -l` reports an `smb_read_only` field, so there is
  probably a way; nothing has measured it, and serving writable a share
  somebody marked read-only is the one failure here that would be a lie in the
  dangerous direction. Refused until it is measured.
- *Creating accounts or setting their SMB password* (`SMB-NT`, the account
  spike's steps 1-4). Decided 12 October 2026: shares are served to accounts
  that already exist. On macOS the SMB password is the login password, so the
  person turns SMB sign-in on for their account in System Settings; SMBPal
  reports whether they have, and `share make-writable` grants the folder with
  an ACE (step 5) rather than an ownership change.
- *Turning File Sharing on.* `launchctl enable` on an Apple-managed service is a
  trap (account spike §1), and starting `smbd` exposes every sharepoint on the
  machine, not just SMBPal's. Reported, not changed.
"""

from __future__ import annotations

import json
import logging
import socket
from typing import Any

from smbpal.errors import AlreadyExists, NeedsAuthorisation, SmbpalError
from smbpal.samba.apply import ApplyError, ApplyReport, PlannedShare
from smbpal.shares import ownership
from smbpal.system import authorization as macos_auth
from smbpal.system.helper import Helper, HelperError, PathFacts

log = logging.getLogger(__name__)

# The daemon's methods a sharepoint applier still cannot serve. Each is a
# missing piece named in the module docstring, refused by name before any
# prompt (see `Dispatcher.handle`) rather than failing into a Samba tool that
# is not there.
UNSUPPORTED_METHODS = frozenset({"credential.set", "credential.remove"})

# The helper's line between a person and a system account (§13 rule 5), which
# it applies to accounts as well as folders. Mirrored, not imported: it is a
# C constant, and a test pins the two together.
FIRST_PERSON_UID = 500


def refusal(path: str, facts: PathFacts) -> str | None:
    """Why §13 will not share `path`, in words a person can act on, or None.

    §13 asks that the message say what it means "rather than quoting a rule
    number", and each verdict has a different fix.
    """
    resolved = facts.resolved
    via = f" (it resolves to {resolved})" if resolved and resolved != path else ""
    if facts.verdict == "ok":
        return None
    if facts.verdict == "not-found":
        return (
            f"{path} does not exist. On macOS SMBPal shares a folder that is "
            "already there; create it first."
        )
    if facts.verdict == "not-directory":
        return f"{path} is not a folder{via}"
    if facts.verdict == "outside-roots":
        return (
            f"{path} is not inside /Users or /Volumes{via}. On macOS SMBPal "
            "shares folders in people's home folders and on attached disks."
        )
    if facts.verdict == "home-root":
        return (
            f"{path} is {facts.owner}'s whole home folder{via}. Share a folder "
            "inside it instead, such as Documents or Public."
        )
    if facts.verdict == "system-owned":
        return (
            f"{path} belongs to {facts.owner}, a system account{via}. SMBPal "
            "shares folders that belong to a person."
        )
    return f"{path} cannot be shared ({facts.verdict})"


class SharepointApplier:
    """Owns every sharepoint SMBPal publishes, through the helper and only it."""

    UNSUPPORTED_METHODS = UNSUPPORTED_METHODS
    # `Dispatcher._commit` re-applies on every config change, connections
    # included. On Linux that is a free rewrite of `smbpal.conf`; here any drift
    # -- a sharepoint removed by hand in System Settings -- would need a
    # manage-shares grant, and a connection edit would fail asking for one. So
    # a commit that leaves the shares alone leaves the sharepoints alone too.
    APPLY_ONLY_WHEN_SHARES_CHANGE = True
    UNSUPPORTED_DETAIL = (
        "on macOS the SMB password is the account's login password, so SMBPal "
        "does not set one. Turn on SMB sign-in for an account in System "
        "Settings > General > Sharing > File Sharing > Options, where macOS "
        "asks for that account's password."
    )

    # No command runner: nothing here runs a command. The dispatcher hands
    # `applier.runner` to Samba helpers (`pdbedit`) that fail cleanly on a Mac
    # and are then reported as unknown, which is the behaviour wanted.
    runner = None

    def __init__(self, helper: Helper | None = None) -> None:
        self.helper = helper or Helper()

    # --- planning ----------------------------------------------------------

    def _facts(self, share: dict[str, Any]) -> PathFacts:
        # The share's account goes with the question when there is one, so the
        # answer says whether an ACE lets it write -- without which an ACL
        # makes writability unknown. Only a name the helper would accept: one
        # it refuses would fail the whole inspection over a typo in a field
        # that only refines it.
        identity = _identity_for(share)
        if identity is not None and identity.uid >= FIRST_PERSON_UID:
            return self.helper.path_inspect(share["path"], user=identity.username)
        return self.helper.path_inspect(share["path"])

    def plan(self, config: dict[str, Any]) -> list[PlannedShare]:
        """How each share would be served. Reads, never writes -- and never
        prompts, because `path.inspect` needs no grant.

        **A helper that cannot be asked degrades one row, not `status`.** This
        feeds `smbpal status`, which also reports connections; a stopped helper
        failing the whole answer would hide everything that does work behind
        the one thing that does not. `apply` asks without this net, because
        there a missing answer has to stop the change.
        """
        planned = []
        for share in config.get("shares", []):
            try:
                planned.append(self._plan_one(share, self._facts(share)))
            except HelperError as exc:
                planned.append(
                    PlannedShare(
                        share=share,
                        status=ownership.DirectoryStatus(path=share["path"], exists=False),
                        read_only=bool(share.get("read_only")),
                        reason=f"cannot inspect {share['path']}: {exc.message}",
                    )
                )
        return planned

    def _plan_one(self, share: dict[str, Any], facts: PathFacts) -> PlannedShare:
        if not facts.exists:
            status = ownership.DirectoryStatus(path=share["path"], exists=False)
        else:
            status = ownership.describe(
                share["path"],
                uid=facts.uid if facts.uid is not None else -1,
                gid=facts.gid if facts.gid is not None else -1,
                # The helper has already said whether it is a directory; the
                # mode it sends is the permission bits alone.
                mode=(facts.mode or 0)
                | (0 if facts.verdict == "not-directory" else 0o040000),
                owner_name=facts.owner,
                identity=_identity_for(share),
                has_acl=facts.has_acl,
                access=facts.access,
            )
        read_only, reason = ownership.effective_read_only(
            bool(share.get("read_only")), status
        )
        refused = refusal(share["path"], facts)
        if refused is not None:
            reason = refused
        return PlannedShare(share=share, status=status, read_only=read_only, reason=reason)

    # --- applying ----------------------------------------------------------

    def apply(self, config: dict[str, Any], *, grant: bytes | None = None) -> ApplyReport:
        enabled = [s for s in config.get("shares", []) if s.get("enabled", True)]
        facts = {s["id"]: self._facts(s) for s in config.get("shares", [])}
        planned = [self._plan_one(s, facts[s["id"]]) for s in config.get("shares", [])]

        for share in enabled:
            refused = refusal(share["path"], facts[share["id"]])
            if refused is not None:
                raise ApplyError(f"cannot share {share['name']!r}", detail=refused)
            if share.get("read_only"):
                raise ApplyError(
                    f"cannot share {share['name']!r} read-only on macOS yet",
                    detail="SMBPal has not yet measured how macOS serves a "
                    "read-only share, and serving it writable would not be what "
                    "was asked. Share it without --read-only, or leave it out.",
                )

        # The resolved path is the one the helper publishes (§13 rule 1), so it
        # is the one to compare against what `sharing -l` reports.
        wanted = {s["name"]: facts[s["id"]].resolved for s in enabled}
        owned = set(self.helper.share_owned())
        current = self._sharepoints()

        stale = sorted(
            name
            for name in owned
            if name not in wanted or current.get(name, {}).get("path") != wanted[name]
        )
        missing = sorted(name for name in wanted if name not in owned or name in stale)

        for name in missing:
            if name in current and name not in owned:
                raise AlreadyExists(
                    f"this Mac already shares a folder called {name!r} that SMBPal "
                    "did not create",
                    detail=f"It is at {current[name].get('path') or 'an unrecorded path'}. "
                    "SMBPal does not adopt or replace sharepoints it did not "
                    "publish. Choose another name.",
                )

        if (stale or missing) and grant is None:
            # Every caller that reaches here with changes to make was
            # authorised by the dispatcher -- except root, which `Authoriser`
            # waves through and the helper does not. Said plainly rather than
            # left to arrive as the helper's one-word `denied`.
            raise NeedsAuthorisation(
                "changing what this Mac shares needs an administrator's "
                "authorisation, even for root",
                right=macos_auth.MANAGE_SHARES,
            )

        try:
            for name in stale:
                self.helper.share_unpublish(name, auth=grant)
                log.info("unpublished sharepoint %s", name)
            for name in missing:
                self.helper.share_publish(name, wanted[name], auth=grant)
                log.info("published sharepoint %s at %s", name, wanted[name])
        except HelperError as exc:
            raise _explain(exc) from exc

        self._verify_present(wanted)
        log.info("applied %d sharepoint(s)", len(wanted))
        return ApplyReport(shares=planned, served=sorted(wanted), advertising=False)

    def teardown(self, *, grant: bytes | None = None) -> dict[str, Any]:
        """Unpublish every sharepoint the helper recorded, and nothing else.

        §6's guarantee in its macOS form, measured in helper spike §3: every
        record SMBPal did not create is unchanged and the ones it did are
        gone. The helper refuses to remove anything not on its list, so this
        cannot reach further even if it tried.
        """
        owned = sorted(self.helper.share_owned())
        if owned and grant is None:
            raise NeedsAuthorisation(
                "removing what this Mac shares needs an administrator's "
                "authorisation, even for root",
                right=macos_auth.MANAGE_SHARES,
            )
        removed = []
        for name in owned:
            try:
                self.helper.share_unpublish(name, auth=grant)
            except HelperError as exc:
                raise _explain(exc) from exc
            removed.append(name)
        return {"sharepoints_removed": removed}

    # --- access ------------------------------------------------------------

    def make_writable(
        self, share: dict[str, Any], *, grant: bytes | None
    ) -> ownership.DirectoryStatus:
        """§3c's explicit action, macOS form: an ACE for the share's account.

        Never an ownership change, which is what it is on Linux: the folder
        stays its owner's, and the account spike measured that an appended ACE
        is enough for a client to write. Idempotent -- the helper answers OK
        without adding a second ACE when one already allows the account.
        """
        user = share.get("credential_ref")
        if not user:
            raise ApplyError(
                f"share {share['id']!r} has no user assigned",
                detail="Assign one with --user so there is an account to grant.",
            )
        if grant is None:
            raise NeedsAuthorisation(
                "changing who can write to a shared folder needs an "
                "administrator's authorisation, even for root",
                right=macos_auth.MANAGE_SHARES,
            )
        try:
            self.helper.share_grant(share["path"], user, auth=grant)
        except HelperError as exc:
            # Headed with what could not be done, not with the verb that said
            # no: "the helper refused share.grant" is plumbing.
            raise _explain(
                exc, headline=f"cannot make {share['name']!r} writable for {user}"
            ) from exc
        [planned] = self.plan({"shares": [share]})
        return planned.status

    def can_sign_in(self, share: dict[str, Any]) -> bool | None:
        """Whether anybody can open this share from another machine at all.

        For a named account, whether it has SMB sign-in turned on. For a share
        with none, unknown rather than a guess: any account with sign-in on
        could open it, and the helper is not asked to list every account.
        None, too, when the helper cannot be asked -- not the same as no.
        """
        user = share.get("credential_ref")
        if not user:
            return None
        try:
            return self.helper.account_smb(user)
        except HelperError:
            return None

    # --- what the dispatcher asks of any applier ---------------------------

    def effective_shares(self) -> dict[str, str]:
        """Every sharepoint this Mac publishes over SMB, name to path."""
        return {
            record.get("smb_name") or name: record.get("path") or ""
            for name, record in self._sharepoints().items()
            if record.get("smb_shared", True)
        }

    def unmanaged_shares(self, configured: list[str]) -> dict[str, str]:
        """Sharepoints SMBPal did not publish, which it must never touch."""
        owned = set(self.helper.share_owned())
        return {
            name: path
            for name, path in self.effective_shares().items()
            if name not in owned
        }

    def service_state(self) -> dict[str, object]:
        """Whether File Sharing is on, read as whether anything answers on 445.

        `smbd` is socket-activated, so a listener exists exactly when File
        Sharing is on, and a refused connection means it is off. Asked with a
        connection rather than `launchctl print`, which reads differently as
        root and as a role account and which §2 of the helper spike found
        misleading in the other direction.

        **Not yet measured on hardware**: whether 445 refuses promptly with
        File Sharing off, which is the reading this depends on.
        """
        state: dict[str, object] = {"unit": "com.apple.smbd", "installed": True}
        try:
            with socket.create_connection(("127.0.0.1", 445), timeout=1.0):
                state["active"] = True
        except ConnectionRefusedError:
            state["active"] = False
        except OSError:
            # Asking failed, which is not the same as off -- the convention
            # `Dispatcher._samba_state` already follows.
            state["active"] = True
        return state

    # --- pieces ------------------------------------------------------------

    def _sharepoints(self) -> dict[str, dict[str, Any]]:
        """`sharing -l -f json`, keyed by record name -- the key removal needs
        (helper spike §3), which is why it is read back rather than assumed."""
        try:
            parsed = json.loads(self.helper.share_list() or b"{}")
        except ValueError as exc:
            raise ApplyError("could not read this Mac's sharepoints", detail=str(exc)) from exc
        if not isinstance(parsed, dict):
            raise ApplyError("could not read this Mac's sharepoints", detail="not a JSON object")
        return {str(k): v for k, v in parsed.items() if isinstance(v, dict)}

    def _verify_present(self, wanted: dict[str, str | None]) -> None:
        current = self._sharepoints()
        wrong = sorted(
            name for name, path in wanted.items() if current.get(name, {}).get("path") != path
        )
        if wrong:
            raise ApplyError(
                "macOS did not publish " + ", ".join(repr(n) for n in wrong),
                detail="`sharing` accepted the request but the sharepoint is not "
                "in `sharing -l` at the folder asked for.",
            )


def _identity_for(share: dict[str, Any]) -> ownership.ServingIdentity | None:
    user = share.get("credential_ref")
    if not user:
        return None
    try:
        return ownership.serving_identity(user)
    except SmbpalError:
        return None


# The helper's refusals, in words. Its tokens are a fixed vocabulary and never
# an echo of the request, so they can be matched exactly.
_HELPER_REFUSALS = {
    "denied": "the authorisation was not accepted -- it may have expired; try again",
    "exists": "a sharepoint with that name already exists and SMBPal did not create it",
    "published": "SMBPal already published that sharepoint; run `smbpal apply`",
    "not-ours": "that sharepoint was not published by SMBPal, so SMBPal will not remove it",
    "account": "that is not an existing person's account on this Mac -- SMBPal "
    "grants access to people, not to system or role accounts",
    "deny-ace": "an access entry on the folder denies that account; somebody set it "
    "on purpose, so SMBPal leaves it alone",
    "chmod": "macOS's `chmod` did not add the access entry",
    "sharing": "macOS's `sharing` tool did not make the change",
    "ledger": "the helper could not update its record of what SMBPal published",
}


def _explain(exc: HelperError, *, headline: str | None = None) -> SmbpalError:
    detail = _HELPER_REFUSALS.get(exc.token or "")
    if detail is None and exc.token:
        # A §13 verdict: the helper re-checked the folder and refused it, after
        # `apply` had already found it acceptable. Rare (the folder changed in
        # between), and exactly the TOCTOU window §13 records.
        detail = f"the helper refused the folder: {exc.token}"
    return ApplyError(headline or exc.message, detail=detail or exc.detail)
