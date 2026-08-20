"""Turning config into a serving Samba, and back again.

The order matters and comes straight out of M0 §1:

    write our file -> ensure the include -> reload, never restart -> **verify by
    presence** -> reconcile the mDNS record

The verify step is the one that would be easy to leave out and wrong to. M0
found `testparm` reporting `Loaded services file OK.` both when the included
file was malformed and when it was missing, so nothing in Samba will tell us we
got it wrong. A share either appears in the effective configuration or it does
not, and a typo yields a share that silently does not exist.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from smbpal.discovery.advertise import Advertiser
from smbpal.errors import SmbpalError
from smbpal.samba import conf, control, include
from smbpal.shares import ownership
from smbpal.system import atomic
from smbpal.system.run import CommandRunner

log = logging.getLogger(__name__)

DEFAULT_SMB_CONF = Path("/etc/samba/smb.conf")
DEFAULT_SMBPAL_CONF = Path(include.SMBPAL_CONF)


class ApplyError(SmbpalError):
    code = "apply_failed"


@dataclass(frozen=True)
class PlannedShare:
    """One share as it will actually be served, which is not always as configured."""

    share: dict[str, Any]
    status: ownership.DirectoryStatus
    read_only: bool
    reason: str | None

    def to_wire(self) -> dict[str, Any]:
        return {
            **self.share,
            "effective_read_only": self.read_only,
            # §3c: the UI must distinguish "you chose read-only" from
            # "read-only because SMBPal cannot write here". Only the second has
            # a fix attached, and this is that distinction on the wire.
            "read_only_reason": self.reason,
            "directory": self.status.to_wire(),
        }


@dataclass
class ApplyReport:
    shares: list[PlannedShare] = field(default_factory=list)
    served: list[str] = field(default_factory=list)
    advertising: bool = False

    def to_wire(self) -> dict[str, Any]:
        return {
            "shares": [s.to_wire() for s in self.shares],
            "served": self.served,
            "advertising": self.advertising,
        }


class Applier:
    """Owns every file outside the config that SMBPal writes."""

    def __init__(
        self,
        *,
        smb_conf: Path | str = DEFAULT_SMB_CONF,
        smbpal_conf: Path | str = DEFAULT_SMBPAL_CONF,
        advertiser: Advertiser | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.smb_conf = Path(smb_conf)
        self.smbpal_conf = Path(smbpal_conf)
        self.advertiser = advertiser or Advertiser()
        self.runner = runner
        # Derived, never assumed: the include line has to name the file we
        # actually write, or the two drift apart the moment either path moves.
        self.include_line = f"include = {self.smbpal_conf}"

    # --- planning ----------------------------------------------------------

    def plan(self, config: dict[str, Any]) -> list[PlannedShare]:
        """Work out how each share would actually be served. Reads, never writes.

        `status` uses this too, so what the user is told matches what would
        happen — rather than being a second opinion that can drift.
        """
        planned: list[PlannedShare] = []
        for share in config.get("shares", []):
            identity = self._identity_for(share)
            status = ownership.inspect_directory(share["path"], identity)
            read_only, reason = ownership.effective_read_only(
                bool(share.get("read_only")), status
            )
            if not status.exists:
                reason = (
                    f"{share['path']} does not exist yet — it will be created when "
                    "the share is applied"
                )
            planned.append(
                PlannedShare(
                    share=share, status=status, read_only=read_only, reason=reason
                )
            )
        return planned

    @staticmethod
    def _identity_for(share: dict[str, Any]) -> ownership.ServingIdentity | None:
        # Without a user assigned there is no single serving identity —
        # whoever authenticates is served as themselves, so writability cannot
        # be computed in advance. Reporting "unknown" is honest; reporting
        # "writable" would be a guess (§3c).
        user = share.get("credential_ref")
        if not user:
            return None
        try:
            return ownership.serving_identity(user)
        except SmbpalError:
            return None

    # --- applying ----------------------------------------------------------

    def apply(self, config: dict[str, Any]) -> ApplyReport:
        planned = self.plan(config)
        self._create_missing_directories(planned)
        planned = self.plan(config)  # re-read: creation changed the answers

        enabled = [p for p in planned if p.share.get("enabled", True)]
        rendered = conf.render(
            [{**p.share, "read_only": p.read_only} for p in enabled]
        )
        self._write(self.smbpal_conf, rendered, mode=0o644)

        self._ensure_include()
        control.reload_config(runner=self.runner)

        expected = {p.share["name"] for p in enabled}
        control.verify_present(expected, runner=self.runner)

        advertising = self.advertiser.reconcile(len(enabled))
        report = ApplyReport(
            shares=planned, served=sorted(expected), advertising=advertising
        )
        log.info(
            "applied %d share(s); advertising=%s", len(expected), advertising
        )
        return report

    def teardown(self) -> None:
        """Undo everything outside the config. §6's reversibility claim.

        `smb.conf` comes back byte-identical because the block is removed as a
        block — M0's line-based removal left a blank line behind and the diff
        blamed it.
        """
        try:
            original = self.smb_conf.read_text(encoding="utf-8")
        except FileNotFoundError:
            original = None
        if original is not None:
            stripped = include.remove_include(original, include_line=self.include_line)
            if stripped != original:
                self._write(self.smb_conf, stripped, mode=self._mode_of(self.smb_conf))
        self.smbpal_conf.unlink(missing_ok=True)
        self.advertiser.withdraw()
        try:
            control.reload_config(runner=self.runner)
        except SmbpalError as exc:
            # Nothing left to serve either way; a Samba that will not reload is
            # worth reporting but not worth failing an uninstall over.
            log.warning("could not reload Samba after teardown: %s", exc.message)

    # --- pieces ------------------------------------------------------------

    def _create_missing_directories(self, planned: list[PlannedShare]) -> None:
        for item in planned:
            if item.status.exists or not item.share.get("enabled", True):
                continue
            identity = self._identity_for(item.share)
            if identity is None:
                # No serving user, so no defensible owner to give it. Samba will
                # fail to serve the path and say so, which beats creating a
                # directory owned by root that nothing can write.
                log.warning(
                    "share %s has no user assigned; not creating %s",
                    item.share["id"],
                    item.share["path"],
                )
                continue
            # §3c's uncomplicated case: SMBPal made the directory, so SMBPal
            # sets the ownership. Nothing of the user's is touched.
            ownership.create_directory(item.share["path"], identity)
            log.info("created %s for share %s", item.share["path"], item.share["id"])

    def _ensure_include(self) -> None:
        try:
            original = self.smb_conf.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise ApplyError(
                f"{self.smb_conf} does not exist",
                detail="Samba does not appear to be installed.",
            ) from exc
        except OSError as exc:
            raise ApplyError(f"cannot read {self.smb_conf}", detail=str(exc)) from exc

        updated = include.insert_include(original, include_line=self.include_line)
        if updated == original:
            return  # Already there. Idempotent by construction (M0 §1).
        self._write(self.smb_conf, updated, mode=self._mode_of(self.smb_conf))
        log.info("added the SMBPal include block to %s", self.smb_conf)

    def _write(self, path: Path, text: str, *, mode: int) -> None:
        try:
            atomic.write_text(path, text, mode=mode)
        except OSError as exc:
            raise ApplyError(f"cannot write {path}", detail=str(exc)) from exc

    @staticmethod
    def _mode_of(path: Path, default: int = 0o644) -> int:
        # Preserve whatever the distribution chose for smb.conf rather than
        # imposing ours on a file we do not own.
        try:
            return path.stat().st_mode & 0o777
        except OSError:
            return default
