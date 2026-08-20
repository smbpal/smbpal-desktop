"""IPC: the boundary between the daemon and its clients.

D4 keeps the transport behind an interface from day one so that remote
administration stays possible without a redesign. `transport.py` is that
interface; `server.py` is the only implementation Phase 1 ships.
"""

from smbpal.ipc.peer import PeerCredentials, peer_credentials
from smbpal.ipc.protocol import (
    MAX_FRAME_BYTES,
    Request,
    encode_event,
    encode_failure,
    encode_success,
    parse_request,
)
from smbpal.ipc.transport import Connection, Transport

__all__ = [
    "MAX_FRAME_BYTES",
    "Connection",
    "PeerCredentials",
    "Request",
    "Transport",
    "encode_event",
    "encode_failure",
    "encode_success",
    "parse_request",
    "peer_credentials",
]
