"""The login Keychain, which is why the agent exists at all.

D13 put mounting in a per-user agent for two measured reasons, and this is the
second of them: **the login Keychain is unreadable from root**. So the
credential for a mount has to be stored, and found, inside the session — by
this process, for this person, and by nothing else.

**What goes in is an internet password, in the shape the system looks for.**
`kSecClassInternetPassword`, `kSecAttrProtocol` of `kSecAttrProtocolSMB`
(`'smb '`), the server and the account. That is not a choice: NetAuthAgent is
what consults the Keychain when `NetFSMountURLSync` is given no password, and it
looks for the item the system's own Finder would have written. An item of our
own shape, under our own service name, would be ours and invisible.

**There is a `get`, and there was deliberately not one until a measurement
forced it.** The original rule was `set`, `present`, `forget` and no read — the
same shape that gives `CredentialsStore` a `username_for` and no
`password_for`, on the grounds that the store exists so something *else* can
read it: `mount.cifs` there, NetAuthAgent here.

**NetAuthAgent turned out not to read it when asked not to show UI.** Measured
on 2 October 2026 against a real server: with the correct item in the Keychain,
`NetFSMountURLSync` under `kNAUIOptionNoUI` was refused with `EAUTH`, and the
same password passed as an argument mounted the share. The NetFS header has no
"use the Keychain" option to turn on — the lookup belongs to NetAuthAgent's UI
path, and a launchd agent must not raise a dialog. So the agent reads the
password itself and passes it.

**D13's property is unchanged, and that is the test of whether this is a
retreat.** The credential still never leaves the session and root still cannot
see it; what changed is which process inside the session reads it. The daemon
has no `get` and no way to ask for one.

**The item's key is the item, and that bounds what uninstall may do.**
`SecItemAdd` of a second item with the same server, account and protocol returns
`errSecDuplicateItem` (-25299) — measured, not read. So SMBPal cannot keep its
own copy beside the one Finder may already hold for the same share: there is
one item, and writing is *create or replace*. **Which means deleting one is not
this module's decision.** `forget` does what it is told; whether SMBPal put that
item there is knowledge that lives in SMBPal's config, and §10.6's promise to
remove what it created must not become a promise to remove what it found.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from typing import Any

from smbpal.errors import SmbpalError

log = logging.getLogger(__name__)

SECURITY_PATH = "/System/Library/Frameworks/Security.framework/Security"
CF_PATH = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

_UTF8 = 0x08000100

# Measured, because the headers disagree with the documentation about the sign.
ERR_SUCCESS = 0
ERR_DUPLICATE_ITEM = -25299
ERR_ITEM_NOT_FOUND = -25300

_loaded: dict[str, Any] = {}


class KeychainError(SmbpalError):
    code = "keychain"


def available() -> bool:
    return sys.platform == "darwin"


def _frameworks() -> dict[str, Any]:
    """Loaded at first use, not at import, so the suite collects on Linux."""
    if not available():
        raise KeychainError(
            "the login Keychain is macOS only",
            detail=(
                f"this is {sys.platform}, where a mount credential goes in a "
                "root-owned file for mount.cifs to read"
            ),
        )
    if _loaded:
        return _loaded

    cf = ctypes.CDLL(CF_PATH)
    sec = ctypes.CDLL(SECURITY_PATH)
    ref = ctypes.c_void_p

    cf.CFStringCreateWithCString.restype = ref
    cf.CFStringCreateWithCString.argtypes = [ref, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFStringGetCString.argtypes = [ref, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
    cf.CFDataCreate.restype = ref
    cf.CFDataCreate.argtypes = [ref, ctypes.c_char_p, ctypes.c_long]
    # **Both of these, or `get_password` segfaults.** Without a declared
    # `restype`, ctypes assumes `int` and truncates the returned pointer to 32
    # bits, so `string_at` reads from an address that was never allocated. The
    # first run of the new test exited 139 rather than failing an assertion,
    # which is the whole reason this module declares every signature it uses.
    cf.CFDataGetLength.restype = ctypes.c_long
    cf.CFDataGetLength.argtypes = [ref]
    cf.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_char)
    cf.CFDataGetBytePtr.argtypes = [ref]
    cf.CFDictionaryCreateMutable.restype = ref
    cf.CFDictionaryCreateMutable.argtypes = [ref, ctypes.c_long, ref, ref]
    cf.CFDictionarySetValue.restype = None
    cf.CFDictionarySetValue.argtypes = [ref, ref, ref]
    cf.CFRelease.restype = None
    cf.CFRelease.argtypes = [ref]

    for name in ("SecItemAdd", "SecItemCopyMatching"):
        # (query, out) — the second argument is where the result is written.
        function = getattr(sec, name)
        function.restype = ctypes.c_int32
        function.argtypes = [ref, ctypes.POINTER(ref)]
    # **Not the same signature**, which `ctypes` caught and a C compiler would
    # have: `SecItemUpdate` takes two dictionaries — what to find and what to
    # change — and no out-parameter.
    sec.SecItemUpdate.restype = ctypes.c_int32
    sec.SecItemUpdate.argtypes = [ref, ref]
    sec.SecItemDelete.restype = ctypes.c_int32
    sec.SecItemDelete.argtypes = [ref]
    sec.SecCopyErrorMessageString.restype = ref
    sec.SecCopyErrorMessageString.argtypes = [ctypes.c_int32, ref]

    _loaded.update(
        cf=cf,
        sec=sec,
        # Structs, so the dictionary constructor wants their addresses. The
        # `kSec*` constants below are CFStringRefs — pointers — and want their
        # value instead. Getting the two confused produces a dictionary that
        # silently holds nothing, which is the `netfs.py` lesson restated.
        key_cb=ctypes.addressof(ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryKeyCallBacks")),
        val_cb=ctypes.addressof(ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryValueCallBacks")),
        true=ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue").value,
    )
    return _loaded


class _Refs:
    """Created here, released here, in reverse, whatever happens.

    The same discipline `netfs.py` keeps and for the same reason: an
    over-release is a crash in a long-lived agent and a leak is invisible.
    """

    def __init__(self, cf: Any) -> None:
        self._cf = cf
        self._refs: list[Any] = []

    def keep(self, created: Any) -> Any:
        if created:
            self._refs.append(created)
        return created

    def __enter__(self) -> "_Refs":
        return self

    def __exit__(self, *_exc: Any) -> None:
        for created in reversed(self._refs):
            self._cf.CFRelease(created)
        self._refs.clear()


def _constant(name: str) -> Any:
    return ctypes.c_void_p.in_dll(_frameworks()["sec"], name).value


def _string(refs: _Refs, text: str) -> Any:
    cf = _frameworks()["cf"]
    return refs.keep(cf.CFStringCreateWithCString(None, text.encode(), _UTF8))


def _message(status: int) -> str:
    """The system's own words for an OSStatus, rather than ours for a number."""
    loaded = _frameworks()
    with _Refs(loaded["cf"]) as refs:
        described = refs.keep(loaded["sec"].SecCopyErrorMessageString(status, None))
        if not described:
            return f"OSStatus {status}"
        buffer = ctypes.create_string_buffer(2048)
        if not loaded["cf"].CFStringGetCString(described, buffer, len(buffer), _UTF8):
            return f"OSStatus {status}"
        return buffer.value.decode()


def _query(refs: _Refs, host: str, account: str, **extra: Any) -> Any:
    """The three attributes that identify one SMB credential, plus any extras.

    Server, account and protocol: measured to be the unique key, so these three
    are what every call here agrees on. A query that leaves one out would match
    more than it meant to, and `SecItemDelete` matches *everything* a query
    matches.
    """
    loaded = _frameworks()
    cf = loaded["cf"]
    table = refs.keep(
        cf.CFDictionaryCreateMutable(None, 0, loaded["key_cb"], loaded["val_cb"])
    )
    pairs = {
        "kSecClass": _constant("kSecClassInternetPassword"),
        "kSecAttrServer": _string(refs, host),
        "kSecAttrAccount": _string(refs, account),
        "kSecAttrProtocol": _constant("kSecAttrProtocolSMB"),
    }
    pairs.update(extra)
    for key, value in pairs.items():
        cf.CFDictionarySetValue(table, _constant(key), value)
    return table


def set_password(host: str, account: str, password: str) -> str:
    """Store the credential for one server and account. "created" or "replaced".

    The caller is told which, because it is the only moment anybody can know:
    *created* means SMBPal put this item there and may remove it later;
    *replaced* means something else did — Finder, most likely — and uninstall
    must leave it alone. See the module docstring.
    """
    if not host or not account:
        raise KeychainError("a Keychain item needs both a server and an account")
    if not password:
        raise KeychainError("the password must not be empty")

    loaded = _frameworks()
    cf = loaded["cf"]
    encoded = password.encode()
    with _Refs(cf) as refs:
        data = refs.keep(cf.CFDataCreate(None, encoded, len(encoded)))
        # The label is what Keychain Access shows in its list, so it is the
        # server rather than anything of ours: somebody auditing their own
        # Keychain should see the machine they connected to.
        query = _query(
            refs,
            host,
            account,
            kSecAttrLabel=_string(refs, host),
            kSecValueData=data,
        )
        status = loaded["sec"].SecItemAdd(query, None)
        if status == ERR_SUCCESS:
            log.info("stored a Keychain credential for %s on %s", account, host)
            return "created"
        if status != ERR_DUPLICATE_ITEM:
            raise KeychainError(
                f"could not store the credential for {account} on {host}",
                detail=_message(status),
            )

        # One item per server, account and protocol, so this is a replacement
        # rather than a second item. `SecItemUpdate` takes the identifying
        # query and a dictionary of what to change — the data only.
        changes = refs.keep(
            cf.CFDictionaryCreateMutable(None, 0, loaded["key_cb"], loaded["val_cb"])
        )
        cf.CFDictionarySetValue(changes, _constant("kSecValueData"), data)
        status = loaded["sec"].SecItemUpdate(_query(refs, host, account), changes)
        if status != ERR_SUCCESS:
            raise KeychainError(
                f"there is already a Keychain item for {account} on {host} "
                "and it could not be updated",
                detail=_message(status),
            )
        log.info("replaced the Keychain credential for %s on %s", account, host)
        return "replaced"


def present(host: str, account: str) -> bool:
    """Whether a credential exists. Attributes only, so the password is untouched.

    Measured on 2 October 2026: an attributes-only lookup answers with no
    prompt, from a process that did not create the item. Asking for the data
    would be the call that can block an agent on a dialog.
    """
    loaded = _frameworks()
    with _Refs(loaded["cf"]) as refs:
        found = ctypes.c_void_p()
        query = _query(
            refs,
            host,
            account,
            kSecReturnAttributes=loaded["true"],
            kSecMatchLimit=_constant("kSecMatchLimitOne"),
        )
        status = loaded["sec"].SecItemCopyMatching(query, ctypes.byref(found))
    if status == ERR_SUCCESS:
        if found:
            loaded["cf"].CFRelease(found)
        return True
    if status == ERR_ITEM_NOT_FOUND:
        return False
    raise KeychainError(
        f"could not look for a credential for {account} on {host}",
        detail=_message(status),
    )


def get_password(host: str, account: str) -> str | None:
    """The password, or None if there is no item. **Session-only, by design.**

    The one function here that handles a secret, and the one that can raise a
    Keychain dialog: reading the *data* needs the item's ACL, where `present`
    asks only for attributes and needs nothing. Measured on 2 October 2026 —
    a process that did not create the item read it back with no prompt, because
    the ACL trusts the interpreter rather than the process. **A `brew upgrade
    python@3.14` changes that interpreter's code identity**, so the first read
    afterwards may prompt. In the agent that dialog appears in the person's own
    session, which is survivable, and `smbpal-agent --status` is where somebody
    would go looking.

    The returned string is held for the length of one `netfs.mount` call and is
    never logged, stored, or returned over the daemon's socket.
    """
    loaded = _frameworks()
    found = ctypes.c_void_p()
    with _Refs(loaded["cf"]) as refs:
        query = _query(
            refs,
            host,
            account,
            kSecReturnData=loaded["true"],
            kSecMatchLimit=_constant("kSecMatchLimitOne"),
        )
        status = loaded["sec"].SecItemCopyMatching(query, ctypes.byref(found))
    if status == ERR_ITEM_NOT_FOUND:
        return None
    if status != ERR_SUCCESS:
        raise KeychainError(
            f"could not read the credential for {account} on {host}",
            detail=_message(status),
        )
    cf = loaded["cf"]
    try:
        length = cf.CFDataGetLength(found)
        pointer = cf.CFDataGetBytePtr(found)
        return ctypes.string_at(pointer, length).decode("utf-8")
    finally:
        cf.CFRelease(found)


def forget(host: str, account: str) -> bool:
    """Remove it. False if there was nothing there, which is not a failure.

    The same shape as `netfs.unmount` and `launchd.bootout`: a caller asking
    for something to be gone has got what it asked for.

    **It does not ask whether SMBPal put the item there.** It cannot: the item
    carries no mark of ours, because it has to be the item the system looks
    for. Only SMBPal's config knows, and the caller is where that knowledge is.
    """
    loaded = _frameworks()
    with _Refs(loaded["cf"]) as refs:
        status = loaded["sec"].SecItemDelete(_query(refs, host, account))
    if status == ERR_SUCCESS:
        log.info("removed the Keychain credential for %s on %s", account, host)
        return True
    if status == ERR_ITEM_NOT_FOUND:
        return False
    raise KeychainError(
        f"could not remove the credential for {account} on {host}",
        detail=_message(status),
    )
