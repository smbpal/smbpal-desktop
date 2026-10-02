"""Mounting SMB on macOS, through NetFS.

**D13.** The Linux side asks `mount.cifs` for a mount and hands it a
credentials file; macOS has no equivalent. `mount_smbfs` takes the password
*in the URL* — `//user:password@server/share` — which M0 §9 forbids outright,
and its only alternative reads a per-user file that `nsmb.conf(5)` does not
document. So the command-line route is excluded by rule rather than by
preference, and the supported one is an API:

    NetFSMountURLSync(url, mountpath, user, passwd, open_options,
                      mount_options, &mountpoints)

`user` and `passwd` are arguments to a C function. They never become a command
line, never a file, and never a journal — which is the whole reason this module
exists and the only reason it is written in `ctypes` rather than shelled out.

**No PyObjC.** `ipc/peer.py` reaches `getpeereid(2)` the same way and says why:
the dependency is not worth one call. Everything here is CoreFoundation and one
framework, and §3.2's budgets are the reason that matters.

**This module does not decide where it runs.** D13 puts macOS mounting in a
per-user agent, because the login Keychain is unreadable from root and because
an unprivileged `mount_smbfs` reaches the network — measured, not assumed. That
is an architecture question and this is the mechanism underneath it.

**It must import on Linux.** The test suite runs on `ubuntu-latest`, so the
frameworks are loaded at first call and not at import, and everything that
needs them says so when it is not macOS.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno as _errno
import logging
import sys
from typing import Any

from smbpal.errors import SmbpalError

log = logging.getLogger(__name__)

CF_PATH = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
NETFS_PATH = "/System/Library/Frameworks/NetFS.framework/NetFS"

_UTF8 = 0x08000100

# NetFS.h. `NoUI` is not a nicety: D13's agent reconnects in front of an empty
# chair, and a password dialog there is worse than a failure. Proven on
# 30 September 2026 — an authentication failure with nothing cached raised no
# dialog, which is the behaviour the reconnect design rests on.
UI_OPTION_KEY = "UIOption"
UI_OPTION_NO_UI = "NoUI"
# `kNetFSForceNewSessionKey`, an open-session option beside `UIOption`.
FORCE_NEW_SESSION_KEY = "ForceNewSession"


class NetFSError(SmbpalError):
    code = "netfs"


# --- the platform's numbers -------------------------------------------------

def _status(name: str) -> int | None:
    """`errno.EAUTH` does not exist on Linux, and this table is written there.

    `EAUTH` and `ENEEDAUTH` are BSD extensions with no Linux equivalent, so the
    macOS table cannot be built by naming constants and hoping. It is also why
    `state/translate.py`'s table could not simply be re-keyed by symbol:
    the mapping is not one-to-one between the platforms (D14, and
    `phase-2-porting-surface.md` §6.9).
    """
    return getattr(_errno, name, None)


# Deliberately the same sentences as `state/translate.py`'s Linux table where
# the cause is the same. The *numbers* differ per platform -- ECONNREFUSED is
# 111 on Linux and 61 here -- and the *words* must not, because a person who
# reads them on two machines is reading about one thing. `test_netfs` asserts
# the two agree, so drift is a failing test rather than a discovery.
_STATUS: dict[int | None, tuple[str, str, bool]] = {
    _status("EAUTH"): (
        "auth_failed",
        "the username or password was refused by the server",
        False,
    ),
    _status("ENEEDAUTH"): (
        "auth_failed",
        "the server wants a username and password",
        False,
    ),
    _status("EACCES"): (
        "auth_failed",
        "the username or password was refused by the server",
        False,
    ),
    _status("ENOENT"): ("failed", "the server has no share by that name", False),
    _status("ETIMEDOUT"): ("unreachable", "the server did not answer in time", True),
    _status("ECONNREFUSED"): (
        "unreachable",
        "the server refused the connection: either SMBPal's sharing is "
        "stopped there, or a firewall is blocking it. `smbpal status` on that "
        "machine says which",
        True,
    ),
    _status("EHOSTDOWN"): (
        "unreachable",
        "the server is switched off or unreachable",
        True,
    ),
    _status("EHOSTUNREACH"): ("unreachable", "there is no route to the server", True),
    _status("ENETUNREACH"): ("unreachable", "the network is unreachable", True),
    _status("EEXIST"): (
        "failed",
        "that share is already mounted, or another mount is using the same "
        "name",
        False,
    ),
}
_STATUS.pop(None, None)


def describe(status: int) -> tuple[str, str, bool]:
    """`(state, message, retryable)` for what `NetFSMountURLSync` returned.

    NetFS documents negative `OSStatus` values and `kNetAuthError` codes, and
    says nothing about positive ones -- but an unresolvable host returns **65**,
    which is `EHOSTUNREACH`. So the ordinary failures arrive as POSIX errno and
    the approach `state/translate.py` takes transfers intact. A negative number
    is an `OSStatus` and is reported as itself rather than guessed at.
    """
    known = _STATUS.get(status)
    if known is not None:
        return known
    if status < 0:
        return ("failed", f"the mount failed with macOS status {status}", True)
    return ("failed", f"the mount failed with error {status}", True)


# --- the frameworks ---------------------------------------------------------

_loaded: dict[str, Any] = {}


def available() -> bool:
    return sys.platform == "darwin"


def _frameworks() -> dict[str, Any]:
    if not available():
        raise NetFSError(
            "NetFS is macOS only",
            detail=f"this is {sys.platform}; Linux mounts go through mount.cifs",
        )
    if _loaded:
        return _loaded

    cf = ctypes.CDLL(CF_PATH)
    netfs = ctypes.CDLL(NETFS_PATH)
    ref = ctypes.c_void_p

    cf.CFStringCreateWithCString.restype = ref
    cf.CFStringCreateWithCString.argtypes = [ref, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFStringGetCString.argtypes = [ref, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
    cf.CFURLCreateWithString.restype = ref
    cf.CFURLCreateWithString.argtypes = [ref, ref, ref]
    cf.CFURLGetString.restype = ref
    cf.CFURLGetString.argtypes = [ref]
    cf.CFDictionaryCreateMutable.restype = ref
    cf.CFDictionaryCreateMutable.argtypes = [ref, ctypes.c_long, ref, ref]
    cf.CFDictionarySetValue.restype = None
    cf.CFDictionarySetValue.argtypes = [ref, ref, ref]
    cf.CFArrayGetCount.restype = ctypes.c_long
    cf.CFArrayGetCount.argtypes = [ref]
    cf.CFArrayGetValueAtIndex.restype = ref
    cf.CFArrayGetValueAtIndex.argtypes = [ref, ctypes.c_long]
    cf.CFRelease.restype = None
    cf.CFRelease.argtypes = [ref]

    netfs.NetFSMountURLSync.restype = ctypes.c_int
    netfs.NetFSMountURLSync.argtypes = [
        ref, ref, ref, ref, ref, ref, ctypes.POINTER(ref)
    ]
    netfs.NetFSCopyURLForRemountingVolume.restype = ref
    netfs.NetFSCopyURLForRemountingVolume.argtypes = [ref]

    # unmount(2), not `umount` the command. There is no credential involved in
    # taking a mount away, so shelling out would be allowed -- but it would
    # mean parsing somebody's error text to find out what happened, and libc
    # hands back an errno that `describe` already knows how to read.
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.unmount.restype = ctypes.c_int
    libc.unmount.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _loaded["libc"] = libc

    _loaded.update(
        cf=cf,
        netfs=netfs,
        # Exported as structs; the dictionary constructor wants their
        # addresses, not their first pointer-sized word. Getting this wrong
        # produces a dictionary that silently holds nothing.
        key_cb=ctypes.addressof(ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryKeyCallBacks")),
        val_cb=ctypes.addressof(ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryValueCallBacks")),
        # `ForceNewSession` takes a boolean, not the string "true" -- these are
        # CFTypeRefs, so their *value* is the ref, where the callback structs
        # above want their address. The same confusion, one line apart.
        true=ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue").value,
        false=ctypes.c_void_p.in_dll(cf, "kCFBooleanFalse").value,
    )
    return _loaded


# --- CoreFoundation, kept local ---------------------------------------------

class _Refs:
    """Everything created here is released here, in reverse, whatever happens.

    CoreFoundation has no garbage collector and `ctypes` will not help. A leak
    is invisible and an over-release is a crash in a long-lived agent, so the
    lifetime is a `with` block rather than a discipline.
    """

    def __init__(self, cf: Any) -> None:
        self._cf = cf
        self._refs: list[Any] = []

    def keep(self, ref: Any) -> Any:
        if ref:
            self._refs.append(ref)
        return ref

    def __enter__(self) -> "_Refs":
        return self

    def __exit__(self, *_exc: Any) -> None:
        for ref in reversed(self._refs):
            self._cf.CFRelease(ref)
        self._refs.clear()


def _string(cf: Any, text: str) -> Any:
    return cf.CFStringCreateWithCString(None, text.encode(), _UTF8)


def _text(cf: Any, ref: Any) -> str:
    buffer = ctypes.create_string_buffer(4096)
    if not cf.CFStringGetCString(ref, buffer, len(buffer), _UTF8):
        return ""
    return buffer.value.decode()


def _options(cf: Any, refs: _Refs, pairs: dict[str, str | bool]) -> Any:
    """A CFDictionary of NetFS options. A `bool` becomes a CFBoolean.

    `UIOption` is a string and `ForceNewSession` is a boolean, so this cannot
    be a string-to-string helper. Passing the string "true" for a boolean key
    is accepted by the dictionary and ignored by NetFS, which is the silent
    failure this signature exists to prevent.
    """
    loaded = _frameworks()
    table = refs.keep(
        cf.CFDictionaryCreateMutable(None, 0, loaded["key_cb"], loaded["val_cb"])
    )
    for key, value in pairs.items():
        if isinstance(value, bool):
            cell = loaded["true"] if value else loaded["false"]
        else:
            cell = refs.keep(_string(cf, value))
        cf.CFDictionarySetValue(table, refs.keep(_string(cf, key)), cell)
    return table


# --- what the rest of the daemon calls ---------------------------------------

def mount(
    url: str,
    *,
    user: str | None = None,
    password: str | None = None,
    allow_ui: bool = False,
    force_new_session: bool = True,
) -> str:
    """Mount `smb://host/share` and return where it landed.

    `password` is a `CFString` for the length of this call and nothing else. It
    is never logged, never interpolated into a message, and never reaches a
    process argument — which is the point of the module.

    The mountpoint is macOS's choice, under `/Volumes` and named for the share,
    which is where Finder puts it too: an agent can predict it and find its own
    mounts again without storing a path it may later be denied.
    """
    loaded = _frameworks()
    cf, netfs = loaded["cf"], loaded["netfs"]

    with _Refs(cf) as refs:
        text = refs.keep(_string(cf, url))
        target = refs.keep(cf.CFURLCreateWithString(None, text, None))
        if not target:
            raise NetFSError(
                "that is not a URL SMBPal can mount",
                detail=f"{url!r} could not be parsed as one",
            )

        options: dict[str, str | bool] = {}
        if not allow_ui:
            options[UI_OPTION_KEY] = UI_OPTION_NO_UI
        if force_new_session:
            # **Default on, and it cost an evening to learn why.** macOS keeps
            # the credential for a server after the last unmount, below
            # NetAuthAgent -- which is SIP-protected and cannot be restarted --
            # so a second mount succeeds on the strength of the first. On
            # 2 October 2026 that produced a mount with the Keychain item
            # deleted, with a deliberately wrong item, and addressed by IP, and
            # it took a reboot to get an honest answer. A stale session also
            # masks a credential that has since changed, which is the case a
            # person meets after fixing a password.
            options[FORCE_NEW_SESSION_KEY] = True
        opens = _options(cf, refs, options)
        mounts = _options(cf, refs, {})

        out = ctypes.c_void_p()
        status = netfs.NetFSMountURLSync(
            target,
            None,
            refs.keep(_string(cf, user)) if user else None,
            refs.keep(_string(cf, password)) if password else None,
            opens,
            mounts,
            ctypes.byref(out),
        )

        if status != 0:
            _state, message, _retryable = describe(status)
            raise NetFSError(message, detail=f"NetFSMountURLSync returned {status}")

        if not out or cf.CFArrayGetCount(out) < 1:
            raise NetFSError(
                "the mount reported success without saying where",
                detail="NetFSMountURLSync returned 0 and no mountpoint",
            )
        where = _text(cf, cf.CFArrayGetValueAtIndex(out, 0))
        cf.CFRelease(out)
        return where


# `MNT_FORCE` from sys/mount.h. Not the default: forcing an unmount while
# something is writing is how a half-written file happens, and a mount that
# will not go away is information rather than an obstacle.
MNT_FORCE = 0x00080000


# `unmount(2)` returns these when the path is not a mount point, which is the
# state a caller asking for an unmount wanted to reach. Found on 2 October 2026
# by disconnecting a connection that had never mounted: `ENOENT` went through
# the mount table and came back as *the server has no share by that name*, which
# is what that number means for a **mount** and has nothing to do with this one.
# Two operations, one errno, two causes -- D14, and the message named the wrong
# one. Taking them as success also makes disconnect idempotent, which is what
# `systemd.stop` on a stopped unit already does on Linux.
_ALREADY_UNMOUNTED = frozenset(
    code for code in (_status("ENOENT"), _status("EINVAL")) if code is not None
)


def unmount(mountpoint: str, *, force: bool = False) -> bool:
    """Take a mount away. False if there was nothing there to take.

    The automount, if any, may put it straight back. That is not this
    function's business and it is the finding pop-os.md §5 recorded: on a
    desktop whose file manager watches the mountpoint, an unmount is undone
    before the screen redraws. Saying so is the caller's job -- macOS has no
    automount at all, so the two platforms owe a person different sentences.
    """
    loaded = _frameworks()
    libc = loaded["libc"]
    ctypes.set_errno(0)
    if libc.unmount(mountpoint.encode(), MNT_FORCE if force else 0) == 0:
        return True
    code = ctypes.get_errno()
    if code in _ALREADY_UNMOUNTED:
        log.info("nothing was mounted at %s", mountpoint)
        return False
    _state, message, _retryable = describe(code)
    raise NetFSError(
        message if code in _STATUS else f"could not unmount {mountpoint}",
        detail=f"unmount(2) failed with errno {code}",
    )


def remount_url(mountpoint: str) -> str | None:
    """The URL that would mount this path again, or None.

    §9's health-check loop has to put a lost mount back, and macOS supplies the
    primitive rather than making us reconstruct it from stored state — which
    matters because the stored state is what would be wrong after a rename.
    Nothing here is credentialled: the URL carries no password.
    """
    loaded = _frameworks()
    cf, netfs = loaded["cf"], loaded["netfs"]

    with _Refs(cf) as refs:
        path = refs.keep(_string(cf, mountpoint))
        local = refs.keep(cf.CFURLCreateWithString(None, path, None))
        if not local:
            return None
        found = netfs.NetFSCopyURLForRemountingVolume(local)
        if not found:
            return None
        refs.keep(found)
        return _text(cf, cf.CFURLGetString(found)) or None
