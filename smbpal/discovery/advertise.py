"""§3f: advertise `_smbpal._tcp`, but only while sharing.

Decided 20 August 2026. The record exists so §3e can tell a machine running
SMBPal from any other SMB host — and it exists *only while at least one share
is active*, because advertising is not free. It publishes that this machine runs
SMBPal to everyone on the segment, on every network it joins, and if a
vulnerability is ever found in SMBPal that record is a targeting list. Gated on
share count, the only machines announcing are ones already visible via
`_smb._tcp`, and **a laptop used purely as a client stays silent on hotel Wi-Fi**.

Port 445 because that is what a peer can actually connect to: SMBPal has no
listening service of its own (D4 is a Unix socket, §11.1 rules out a network
API), and publishing a port nothing listens on is a lie that turns into a
support case.

`v=1` is a *protocol* version, not the application version. Publishing
`ver=0.1.0` hands an attacker the version-matching step for free, and a `caps=`
list designed before the feature it serves is a legacy field waiting to happen.
TXT is extensible, so nothing is foreclosed.
"""

from __future__ import annotations

import logging
from pathlib import Path

from smbpal.errors import SmbpalError
from smbpal.system import atomic

log = logging.getLogger(__name__)

DEFAULT_SERVICE_FILE = Path("/etc/avahi/services/smbpal.service")

# `%h` with replace-wildcards is Avahi's hostname. §3d: SMBPal reports the
# machine's name, it does not set it.
SERVICE_XML = """\
<?xml version="1.0" standalone='no'?><!--*-nxml-*-->
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<!-- Written by SMBPal while at least one share is active. Removed when none is. -->
<service-group>
  <name replace-wildcards="yes">%h</name>
  <service>
    <type>_smbpal._tcp</type>
    <port>445</port>
    <txt-record>v=1</txt-record>
  </service>
</service-group>
"""


class AdvertiseError(SmbpalError):
    code = "advertise"


class Advertiser:
    """Owns the Avahi service file. Avahi watches the directory, so writing and
    removing the file is the whole mechanism — no D-Bus, no reload."""

    def __init__(self, path: Path | str = DEFAULT_SERVICE_FILE) -> None:
        self.path = Path(path)

    def reconcile(self, share_count: int) -> bool:
        """Make the file match reality. Returns True if the record is published.

        Called on every share change **and at startup**. A daemon that died with
        shares active leaves the file behind, and a stale record advertises a
        machine that may no longer be sharing — so the state on disk is never
        trusted, only overwritten.
        """
        return self.publish() if share_count > 0 else self.withdraw()

    def publish(self) -> bool:
        if self.path.exists() and self._current() == SERVICE_XML:
            return True
        # Atomic, like every other file the daemon owns: Avahi watches this
        # directory and would happily read a half-written one.
        try:
            atomic.write_text(self.path, SERVICE_XML, mode=0o644)
        except OSError as exc:
            raise AdvertiseError(f"cannot write {self.path}", detail=str(exc)) from exc
        log.info("advertising _smbpal._tcp via %s", self.path)
        return True

    def withdraw(self) -> bool:
        if self.path.exists():
            try:
                self.path.unlink()
            except OSError as exc:
                raise AdvertiseError(
                    f"cannot remove {self.path}", detail=str(exc)
                ) from exc
            log.info("withdrew _smbpal._tcp (%s removed)", self.path)
        return False

    def _current(self) -> str | None:
        try:
            return self.path.read_text(encoding="utf-8")
        except OSError:
            return None
