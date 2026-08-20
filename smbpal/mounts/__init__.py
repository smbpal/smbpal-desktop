"""Mounting remote shares: systemd units, credentials, and asking whether a
mountpoint is alive without ever blocking on it.

The last of those is the requirement M0 §4 produced, and the one most likely to
decide whether SMBPal feels broken. With the remote absent, a plain `ls` on a
cifs mountpoint blocked for a protracted period before `soft` let it fail. It
does not hang forever — that is the important half. The other half is that
"eventually" is long enough to be indistinguishable from a hang to whoever is
watching, and a GUI that freezes when the NAS is off is the single most likely
way for this to feel broken.
"""

from smbpal.mounts.units import (
    automount_unit,
    escape_path,
    mount_unit,
    unit_names,
)

__all__ = ["automount_unit", "escape_path", "mount_unit", "unit_names"]
