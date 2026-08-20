"""Connection state: what is actually happening, in words a person can act on."""

from smbpal.state.machine import (
    AUTH_FAILED,
    CONNECTED,
    CONNECTING,
    DISABLED,
    FAILED,
    IDLE,
    RECONNECTING,
    UNREACHABLE,
    UNRESOLVED,
    UNKNOWN,
    ConnectionState,
    derive,
)
from smbpal.state.translate import Cause, translate_journal

__all__ = [
    "AUTH_FAILED",
    "CONNECTED",
    "CONNECTING",
    "DISABLED",
    "FAILED",
    "IDLE",
    "RECONNECTING",
    "UNKNOWN",
    "UNREACHABLE",
    "UNRESOLVED",
    "Cause",
    "ConnectionState",
    "derive",
    "translate_journal",
]
