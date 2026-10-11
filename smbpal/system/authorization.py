"""Authorization Services, which is how *may act* is answered on macOS.

**polkit cannot be ported here, and the reason is not effort.** `daemon/polkit.py`
builds its subject from `(pid, start-time, uid)`, and on macOS `getpeereid` gives
uid and gid and **no pid** — so no subject exists to ask about. The information is
not on the channel, and nothing that identifies a *caller* can put it there.

Authorization Services inverts that: **the authorisation travels with the request
instead of being looked up from an identity.** The client prompts, serialises the
grant it was given, and the privileged side asks the system whether that grant
covers the right. Nobody has to work out who is calling.

**This module is the client half only, and it prompts.** The verifying half is
`helper/smbpal-helper.c`, in C, and §10 is emphatic about why it is not the
daemon: §9 established that `smbpald` is admin-writable code, so a helper that
trusted the daemon's verdict would be a root-escalation service with a socket on
it. An admin who replaced the daemon could simply not verify. The helper
verifying survives a replaced daemon, because a forged external form either
fails to import or imports to a reference holding no rights.

**A grant is replayable for as long as the right stays authorised**, so the
`timeout` on each right in `helper/smbpal-helper.c` is a security parameter
SMBPal chose rather than inherited. It is not a flaw in the scheme; it is the
dial the scheme exposes.

**Root does not prompt here, and that is the daemon's rule rather than a
property of the scheme.** `handlers.py` lets uid 0 past before any checker is
consulted — root can already do all of this with an editor — so a client running
under `sudo` has nothing to ask the dialog for.

It does not follow that root can mutate on a headless machine. The *helper* is
the authority, and it sees the daemon's uid on its socket and never the
client's, so it cannot exempt root. Making `sudo` work with no window server
needs `allow-root` on the right, and that waits on a measurement — the rule in
`helper/smbpal-helper.c` says why.

**There is no headless path, and §11 measured that rather than assuming it.**
A tty is not what decides: `Aqua` with a tty prompted and succeeded, `System`
with none and `Background` over `ssh` *with* a tty both returned
`InteractionNotAllowed` (-60007). The Aqua session is the discriminator. So over
`ssh` this fails fast and the answer is `sudo`, not a terminal prompt — unlike
Linux, where `cli/agent.py`'s `TtyAgent` lets polkit ask on a terminal.
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from typing import Any

from smbpal.errors import SmbpalError

log = logging.getLogger(__name__)

SECURITY_PATH = "/System/Library/Frameworks/Security.framework/Security"

# `kAuthorizationExternalFormLength`, read from `Authorization.h` on this
# machine rather than remembered. The helper asserts the same number against
# the struct the system defines for it, so the two cannot drift silently.
EXTERNAL_FORM_LENGTH = 32

# The rights. Named `app.smbpal.*` to match the LaunchDaemon labels, where the
# Linux actions are `org.smbpal.*` to match the polkit policy -- the prefixes
# differ because the namespaces do, and pretending otherwise would make one of
# them wrong.
#
# **Three rights, mirroring the three polkit actions**, and the policy file
# explains the split better than a second copy of the argument would: the line
# that earns a separate right is *configuring the machine* against *using what
# is already configured*. A test pins these against the helper's C, which is
# where the rules that go with them live.
MANAGE_SHARES = "app.smbpal.manage-shares"
MANAGE_CONNECTIONS = "app.smbpal.manage-connections"
USE_CONNECTIONS = "app.smbpal.use-connections"

# **Two rights are registered, not three**, and the third is the interesting one.
# `use-connections` is `allow_active yes` on Linux, for a reason that holds here
# and is argued in packaging/polkit/org.smbpal.policy: a configured connection
# is already reachable without a prompt, so putting one on the button that does
# the same thing protects nothing and teaches the person that SMBPal's prompts
# are noise. On macOS the mount is performed by the user's own agent as
# themselves (D13), so there is no privilege to ask for either.
#
# So nothing ever verifies it -- and a right registered in the system's
# authorization database that no component checks is dead policy that reads like
# live policy. It is left unregistered instead, which also keeps §10.6's promise
# to remove what it created down to what it actually created.
RIGHTS = (MANAGE_SHARES, MANAGE_CONNECTIONS)

UNPROMPTED = frozenset({USE_CONNECTIONS})

_FLAG_INTERACTION_ALLOWED = 1 << 0
_FLAG_EXTEND_RIGHTS = 1 << 1

_SUCCESS = 0
# Measured in §11, and distinguished from a denial because they are different
# things to tell someone: -60007 means nothing could have asked.
_INTERACTION_NOT_ALLOWED = -60007
_CANCELED = -60006
_DENIED = -60005

_MESSAGES = {
    _DENIED: "authorisation was refused",
    _CANCELED: "the authorisation dialog was dismissed",
    _INTERACTION_NOT_ALLOWED: (
        "there is no window server session to ask in; on a headless macOS or "
        "over ssh, run the command with sudo instead"
    ),
}

_loaded: dict[str, Any] = {}


class AuthorizationError(SmbpalError):
    """Nothing was authorised. The caller's only correct response is to stop."""


class _AuthorizationItem(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("valueLength", ctypes.c_size_t),
        ("value", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
    ]


class _AuthorizationRights(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("items", ctypes.POINTER(_AuthorizationItem)),
    ]


class _ExternalForm(ctypes.Structure):
    _fields_ = [("bytes", ctypes.c_char * EXTERNAL_FORM_LENGTH)]


def available() -> bool:
    return sys.platform == "darwin"


def _security() -> Any:
    if not available():
        raise AuthorizationError(
            "Authorization Services is macOS only",
            detail=f"this is {sys.platform}, where polkit answers this question",
        )
    if _loaded:
        return _loaded["sec"]
    sec = ctypes.CDLL(SECURITY_PATH)

    sec.AuthorizationCreate.restype = ctypes.c_int32
    sec.AuthorizationCreate.argtypes = [
        ctypes.POINTER(_AuthorizationRights),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    sec.AuthorizationCopyRights.restype = ctypes.c_int32
    sec.AuthorizationCopyRights.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_AuthorizationRights),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.POINTER(_AuthorizationRights)),
    ]
    sec.AuthorizationMakeExternalForm.restype = ctypes.c_int32
    sec.AuthorizationMakeExternalForm.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_ExternalForm),
    ]
    sec.AuthorizationFree.restype = ctypes.c_int32
    sec.AuthorizationFree.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

    _loaded["sec"] = sec
    return sec


def _message(status: int) -> str:
    return _MESSAGES.get(status, f"Authorization Services returned {status}")


def grant(right: str, *, interaction: bool = True) -> bytes:
    """Prompt for `right` and return the external form, `EXTERNAL_FORM_LENGTH` bytes.

    The reference is freed before returning and the bytes outlive it on purpose:
    an `AuthorizationExternalForm` is what the grant is *for*, and holding the
    reference open would keep a live authorisation in a process that has already
    finished asking for one.
    """
    if right not in RIGHTS:
        # Not a lookup failure to pass on to the system. A right this module has
        # never heard of cannot have been registered by our install, so asking
        # about it would get an answer about nothing.
        raise AuthorizationError(
            f"unknown right: {right}",
            detail=f"the rights SMBPal registers are {', '.join(RIGHTS)}",
        )
    sec = _security()

    name = right.encode()
    item = _AuthorizationItem(name=name, valueLength=0, value=None, flags=0)
    rights = _AuthorizationRights(count=1, items=ctypes.pointer(item))

    ref = ctypes.c_void_p()
    status = sec.AuthorizationCreate(None, None, 0, ctypes.byref(ref))
    if status != _SUCCESS:
        raise AuthorizationError(
            "could not create an authorisation reference", detail=_message(status)
        )
    try:
        flags = _FLAG_EXTEND_RIGHTS
        if interaction:
            flags |= _FLAG_INTERACTION_ALLOWED
        status = sec.AuthorizationCopyRights(
            ref, ctypes.byref(rights), None, flags, None
        )
        if status != _SUCCESS:
            raise AuthorizationError(f"not authorised for {right}", detail=_message(status))

        form = _ExternalForm()
        status = sec.AuthorizationMakeExternalForm(ref, ctypes.byref(form))
        if status != _SUCCESS:
            raise AuthorizationError(
                f"the grant for {right} could not be serialised", detail=_message(status)
            )
        # Read by address and length, not through `.bytes`: that is a
        # fixed-size char array, and ctypes truncates one at the first NUL. The
        # form is binary and a NUL in it is an ordinary byte.
        return ctypes.string_at(ctypes.byref(form), EXTERNAL_FORM_LENGTH)
    finally:
        # Not `kAuthorizationFlagDestroyRights`: the grant has to survive this
        # process for the helper to verify it, and destroying the rights here
        # would hand over 32 bytes that import to nothing.
        sec.AuthorizationFree(ref, 0)


def grant_for(right: str) -> bytes | None:
    """`grant`, except that root gets `None` and prompts for nothing.

    `handlers.py` lets uid 0 past before a checker is consulted, so a client
    under `sudo` has nothing to ask for and a dialog there would be a question
    with no consequence attached to either answer.
    """
    if right in UNPROMPTED:
        return None
    if os.geteuid() == 0:
        log.debug("uid 0 needs no grant for %s", right)
        return None
    return grant(right)
