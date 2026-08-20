"""Who is on the other end of the socket.

D4: identity comes from the kernel, never from anything in the message. A
client that could name itself could name someone else.

Linux answers with SO_PEERCRED, which carries pid, uid and gid. macOS has no
equivalent for pid; `getpeereid(2)` gives uid and gid only. Phase 1 ships Linux,
but development happens on a Mac, so both are implemented and `pid` is optional
rather than a lie.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import socket
import struct
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class PeerCredentials:
    uid: int
    gid: int
    pid: int | None = None

    def describe(self) -> str:
        who = f"uid={self.uid} gid={self.gid}"
        return f"{who} pid={self.pid}" if self.pid is not None else who


def peer_credentials(sock: socket.socket) -> PeerCredentials:
    """Return the credentials the kernel reports for the connected peer."""
    if sys.platform.startswith("linux"):
        return _linux_peercred(sock)
    if sys.platform == "darwin":
        return _darwin_peereid(sock)
    raise OSError(
        f"peer credentials are not implemented on {sys.platform}; "
        "the daemon is a Linux service and this is the development fallback"
    )


def _linux_peercred(sock: socket.socket) -> PeerCredentials:
    # struct ucred { pid_t pid; uid_t uid; gid_t gid; } — three 32-bit ints.
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return PeerCredentials(uid=uid, gid=gid, pid=pid)


def _darwin_peereid(sock: socket.socket) -> PeerCredentials:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    uid = ctypes.c_uint32()
    gid = ctypes.c_uint32()
    if libc.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise OSError(ctypes.get_errno(), "getpeereid failed")
    return PeerCredentials(uid=uid.value, gid=gid.value, pid=None)
