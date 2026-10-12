"""Serving folders on macOS, where there is no Samba to configure.

macOS publishes a folder as a *sharepoint* record, created with `sharing` and
needing root. The daemon is unprivileged there (helper spike §9), so everything
in this package goes through the privileged helper -- including looking at the
folder, which the daemon cannot do inside a home directory (§15).
"""

from smbpal.sharepoints.apply import SharepointApplier

__all__ = ["SharepointApplier"]
