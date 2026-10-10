"""List the shares a server offers, through `libsmbclient` rather than a CLI.

**Why this exists.** Browsing a real Mac on 10 October 2026 (docs §6.19) found
that nothing in SMBPal can answer *"what is this server called it?"*. The share
was `Luke H's Public Folder`; the obvious guess was `Public`; the failure read
*the server has no share by that name* with no suggestion of what the names
were. On macOS they are unguessable — apostrophes, spaces, and a `Public
Folder` suffix nobody would predict from a folder called `Public`.

**Why the library and not `smbclient -L`.** M0 §9. `smbclient` takes the
password with `--password` (argv, which `ps` shows) or `-A <file>`, which means
writing a credential to disk for a read-only listing. `libsmbclient` asks for
it through a callback, so it never leaves this process's memory. It is also
268 KiB against `smbclient`'s 2419 KiB (measured on Pi OS, 10 October 2026),
and it is the same shape as D13's NetFS adapter on macOS — a ctypes binding to
the platform's own library — so both halves of the port are solved the same way
instead of one shelling out and one not.

**Everything above `_libsmbclient_lister` is pure** and tested against captured
entries, the way `browse.py` separates its rules from `avahi-browse`.
"""

from __future__ import annotations

import ctypes
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from smbpal.errors import Unavailable

SONAME = "libsmbclient.so.0"

# `smbc_type` in `struct smbc_dirent`. Only the share kinds matter here: a
# listing of `smb://host` returns shares, never files.
SMBC_WORKGROUP = 1
SMBC_SERVER = 2
SMBC_FILE_SHARE = 3
SMBC_PRINTER_SHARE = 4
SMBC_COMMS_SHARE = 5
SMBC_IPC_SHARE = 6

_KINDS = {
    SMBC_FILE_SHARE: "disk",
    SMBC_PRINTER_SHARE: "printer",
    SMBC_COMMS_SHARE: "comms",
    SMBC_IPC_SHARE: "ipc",
    SMBC_WORKGROUP: "workgroup",
    SMBC_SERVER: "server",
}

DEFAULT_TIMEOUT = 5.0

# Each listing owns its context, so there is no global state to share — but
# Samba's library-wide initialisation (talloc, loadparm) is process-global and
# is not documented as thread-safe. The daemon answers requests on one thread
# today, and this makes that not something to remember.
_LOCK = threading.Lock()


@dataclass(frozen=True)
class Share:
    """One entry from a listing of `smb://host`."""

    name: str
    kind: str
    comment: str = ""

    def to_wire(self) -> dict[str, str]:
        return {"name": self.name, "kind": self.kind, "comment": self.comment}


#: A lister takes (host, username, password) and returns raw
#: (smbc_type, name, comment) triples. Injectable so every rule below is
#: tested without a server, and so the ctypes layer has exactly one caller.
Lister = Callable[[str, str, str], Sequence[tuple[int, str, str]]]


def classify(smbc_type: int) -> str:
    return _KINDS.get(smbc_type, "other")


def interpret(entries: Iterable[tuple[int, str, str]]) -> list[Share]:
    """Turn raw entries into `Share` rows, sorted the way a person reads them.

    Sorted case-insensitively by name, with disk shares first: a listing exists
    to be scanned by eye for the thing you meant to type, and `IPC$` is never
    that. Nothing is dropped — the CLI shows every row and says what kind it
    is, because a printer share that is missing is a question and a printer
    share that is labelled is an answer.
    """
    shares = [
        Share(name=name, kind=classify(smbc_type), comment=comment)
        for smbc_type, name, comment in entries
        if name not in (".", "..")
    ]
    return sorted(shares, key=lambda s: (s.kind != "disk", s.name.casefold()))


def mountable(shares: Iterable[Share]) -> list[str]:
    """The names worth offering as *"did you mean"* — disk shares only."""
    return [s.name for s in shares if s.kind == "disk"]


def list_shares(
    host: str,
    *,
    username: str = "",
    password: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    lister: Lister | None = None,
) -> list[Share]:
    """List `host`'s shares. Anonymous unless a username is given."""
    if not host or any(c in host for c in "/\\ \t\r\n\x00"):
        raise Unavailable(f"not a host this can list: {host!r}")
    run = lister or _libsmbclient_lister(timeout)
    return interpret(run(host, username, password))


# --- the ctypes layer, which is the only part that needs the library -------
#
# **This mirrors D13's NetFS adapter** (§6.4, §6.9): bind the platform's own
# library rather than wrap its CLI. Everything goes through one context that
# this call owns — created, configured, used and freed — and the directory
# functions are taken off it rather than called through libsmbclient's legacy
# wrappers, for the measured reason recorded below.
#
# The timeout is why the context is configured rather than defaulted: without
# one, listing a host that is switched off blocks the daemon's handler for as
# long as SMB's own retries take, which is the failure mode `browse.py`
# already guards against with `subprocess(timeout=...)`.


class SmbcDirent(ctypes.Structure):
    """`struct smbc_dirent` from `libsmbclient.h`.

    `name` is a flexible array member, so it is declared as one byte and read
    from its offset for `namelen` bytes. **The field order matters and is not
    guessable** — `commentlen` precedes `comment`, and `namelen` follows it —
    so `probe_layout` below exists to prove it against the installed library
    rather than trusting this declaration.
    """

    _fields_ = [
        ("smbc_type", ctypes.c_uint),
        ("dirlen", ctypes.c_uint),
        ("commentlen", ctypes.c_uint),
        ("comment", ctypes.c_char_p),
        ("namelen", ctypes.c_uint),
        ("name", ctypes.c_char * 1),
    ]


# **The out-parameters are `POINTER(c_char)`, not `c_char_p`.** ctypes marshals
# a `c_char_p` argument into a Python `bytes` — a copy — so a callback declared
# that way receives an immutable object, the pointer is lost, and writing into
# it is at best useless. Only the two genuinely-input strings are `c_char_p`.
# The directory calls are taken off the context rather than used through the
# legacy `smbc_opendir` wrappers. **Measured 10 October 2026:** the wrappers
# returned `EINVAL` for every URL, anonymous or authenticated, against a Mac
# that `smbclient -L` listed fine from the same machine seconds later. The
# compat layer keeps its own initialisation and file-descriptor table that only
# `smbc_init()` sets up, and `smbc_new_context` + `smbc_set_context` does not
# stand in for it. Going through the context has no global state to get wrong.
_OPENDIR_FN = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p)
_READDIR_FN = ctypes.CFUNCTYPE(
    ctypes.POINTER(SmbcDirent), ctypes.c_void_p, ctypes.c_void_p
)
_CLOSEDIR_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)

_CHAR_OUT = ctypes.POINTER(ctypes.c_char)
_AUTH_FN = ctypes.CFUNCTYPE(
    None,
    ctypes.c_char_p,  # server, in
    ctypes.c_char_p,  # share, in
    _CHAR_OUT,  # workgroup, written in place
    ctypes.c_int,
    _CHAR_OUT,  # username, written in place
    ctypes.c_int,
    _CHAR_OUT,  # password, written in place
    ctypes.c_int,
)


def _load() -> ctypes.CDLL:
    try:
        lib = ctypes.CDLL(SONAME, use_errno=True)
    except OSError as exc:
        raise Unavailable(
            "listing a server's shares needs libsmbclient, which is not loadable",
            detail=_why_not_loadable(exc),
        ) from exc

    lib.smbc_new_context.restype = ctypes.c_void_p
    lib.smbc_init_context.argtypes = [ctypes.c_void_p]
    lib.smbc_init_context.restype = ctypes.c_void_p
    lib.smbc_free_context.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.smbc_free_context.restype = ctypes.c_int
    lib.smbc_setTimeout.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.smbc_setTimeout.restype = None
    lib.smbc_setDebug.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.smbc_setDebug.restype = None
    lib.smbc_setFunctionAuthData.argtypes = [ctypes.c_void_p, _AUTH_FN]
    lib.smbc_setFunctionAuthData.restype = None
    lib.smbc_getFunctionOpendir.argtypes = [ctypes.c_void_p]
    lib.smbc_getFunctionOpendir.restype = _OPENDIR_FN
    lib.smbc_getFunctionReaddir.argtypes = [ctypes.c_void_p]
    lib.smbc_getFunctionReaddir.restype = _READDIR_FN
    lib.smbc_getFunctionClosedir.argtypes = [ctypes.c_void_p]
    lib.smbc_getFunctionClosedir.restype = _CLOSEDIR_FN
    return lib


def _why_not_loadable(exc: OSError) -> str:
    """Say the true reason, which is not the same one on both platforms.

    On Linux `libsmbclient` is a declared dependency, so absence is a broken
    install. **macOS does not ship Samba at all**, and saying "partial
    install" there would send someone looking for a problem they do not have.
    The macOS daemon is a real configuration (D4), so this message gets read.
    """
    if sys.platform == "darwin":
        return (
            f"{SONAME}: {exc}. macOS does not ship Samba, so there is no "
            "libsmbclient unless one was installed by hand. `smbutil view "
            "//user@host` lists a server's shares with Apple's own tooling."
        )
    return (
        f"{SONAME}: {exc}. It is a dependency of this package, so this "
        "normally means a partial install."
    )


def available() -> bool:
    """Whether a listing can be attempted at all, for a caller that degrades."""
    try:
        _load()
    except Unavailable:
        return False
    return True


def _entry(pointer: "ctypes._Pointer[SmbcDirent]") -> tuple[int, str, str]:
    """Read one dirent, refusing to trust a record that cannot be right.

    A wrong struct layout does not announce itself: it reads a plausible
    integer out of the wrong offset and then copies that many bytes from
    somewhere. So `namelen` is checked against the record's own `dirlen`
    before anything is read, and a mismatch is reported as a layout problem
    rather than returned as a share called whatever happened to be in memory.
    """
    dirent = pointer.contents
    namelen, dirlen = dirent.namelen, dirent.dirlen
    offset = SmbcDirent.name.offset
    if not 0 < namelen <= 255 or dirlen < offset + namelen:
        raise Unavailable(
            "libsmbclient returned a directory entry this cannot read",
            detail=f"namelen={namelen} dirlen={dirlen} name offset={offset}. "
            "That is a struct smbc_dirent layout mismatch, not a server "
            "problem — run smbpal.discovery.shares.probe_layout to confirm.",
        )
    name = ctypes.string_at(ctypes.addressof(dirent) + offset, namelen)
    comment = b""
    if dirent.comment and dirent.commentlen:
        comment = ctypes.string_at(dirent.comment, dirent.commentlen)
    return (
        int(dirent.smbc_type),
        name.decode("utf-8", errors="replace"),
        comment.decode("utf-8", errors="replace"),
    )


def _libsmbclient_lister(timeout: float) -> Lister:
    def run(host: str, username: str, password: str) -> list[tuple[int, str, str]]:
        lib = _load()

        def auth(
            _server: bytes | None,
            _share: bytes | None,
            workgroup: object,
            _wglen: int,
            user: object,
            userlen: int,
            passwd: object,
            pwlen: int,
        ) -> None:
            # The buffers are the library's, and it says how long they are.
            # M0 §9's whole point is that the password is never anywhere
            # another process can read: it arrives as an argument and is
            # copied straight into them.
            _write_into(user, userlen, username)
            _write_into(passwd, pwlen, password)
            _ = workgroup  # left as the library set it

        callback = _AUTH_FN(auth)
        with _LOCK:
            context = lib.smbc_new_context()
            if not context:
                raise Unavailable("libsmbclient would not create a context")
            try:
                lib.smbc_setDebug(context, 0)
                lib.smbc_setTimeout(context, int(max(1.0, timeout) * 1000))
                lib.smbc_setFunctionAuthData(context, callback)
                if not lib.smbc_init_context(context):
                    raise Unavailable(
                        "libsmbclient would not initialise",
                        detail=_strerror(ctypes.get_errno()),
                    )
                opendir = lib.smbc_getFunctionOpendir(context)
                readdir = lib.smbc_getFunctionReaddir(context)
                closedir = lib.smbc_getFunctionClosedir(context)
                ctypes.set_errno(0)
                handle = opendir(context, f"smb://{host}".encode())
                if not handle:
                    raise Unavailable(
                        f"cannot list shares on {host}",
                        detail=_refusal(ctypes.get_errno(), bool(username)),
                    )
                try:
                    entries = []
                    while True:
                        # readdir returning NULL is both "no more entries" and
                        # "it failed", told apart only by errno, so it is
                        # cleared before each call rather than once.
                        ctypes.set_errno(0)
                        pointer = readdir(context, handle)
                        if not pointer:
                            errno = ctypes.get_errno()
                            if errno:
                                raise Unavailable(
                                    f"listing {host} stopped part way through",
                                    detail=_strerror(errno),
                                )
                            break
                        entries.append(_entry(pointer))
                    return entries
                finally:
                    closedir(context, handle)
            finally:
                lib.smbc_free_context(context, 1)

    return run


def _write_into(buffer: object, size: int, value: str) -> None:
    """Copy `value` into a library-owned char buffer, NUL-terminated.

    The buffer and its length are the library's; this never decides either.
    A NULL pointer or a zero length is a refusal to be honoured rather than
    worked around — writing anyway is a segfault in a daemon.
    """
    if buffer is None or not buffer or size <= 0:
        return
    encoded = value.encode("utf-8")[: size - 1] + b"\0"
    ctypes.memmove(buffer, encoded, len(encoded))


def _strerror(errno: int) -> str:
    import os

    return f"errno {errno}: {os.strerror(errno)}" if errno else "no errno reported"


def _refusal(errno: int, authenticated: bool) -> str:
    """Why a listing would not open, and what to try when nothing says.

    **Measured 10 October 2026.** An anonymous listing of a Mac fails with the
    handle NULL and `errno` left at 0 — no reason reported at all — while the
    same listing with a username returns all five shares. macOS refuses
    anonymous enumeration whether or not guest access is enabled on a share,
    so "no reason given" has one overwhelmingly likely cause and the message
    says so rather than shrugging.
    """
    if errno:
        return _strerror(errno)
    if authenticated:
        return (
            "the server closed the listing without giving a reason. The "
            "credential may be refused for enumeration even where it works "
            "for a mount."
        )
    return (
        "the server gave no reason, which is what an anonymous listing looks "
        "like when it is refused — macOS always refuses one, guest access or "
        "not. Try again with --user."
    )


def probe_layout() -> dict[str, int]:
    """What this *believes* `struct smbc_dirent` looks like.

    **This is not a verification.** The numbers are computed by ctypes from
    the declaration above, so they agree with it by construction. They are
    worth printing only to compare against the installed
    `samba-4.0/libsmbclient.h`, or against a listing that comes back with
    names a person recognises. A wrong offset reads memory rather than
    failing, so the only honest check is one of those two.
    """
    return {
        "sizeof": ctypes.sizeof(SmbcDirent),
        **{name: getattr(SmbcDirent, name).offset for name, _ in SmbcDirent._fields_},
    }


if __name__ == "__main__":  # pragma: no cover - a diagnostic, not a code path
    import getpass
    import json

    print(json.dumps(probe_layout(), indent=2))
    print(f"{SONAME} loadable: {available()}\n")
    if len(sys.argv) > 1:
        user = sys.argv[2] if len(sys.argv) > 2 else ""
        secret = getpass.getpass(f"Password for {user}: ") if user else ""
        try:
            shares = list_shares(sys.argv[1], username=user, password=secret)
        except Unavailable as exc:
            # The detail is the errno, which is the whole point of running
            # this by hand. `Unavailable.__str__` is the one-line form.
            print(f"FAILED: {exc}")
            print(f"detail: {getattr(exc, 'detail', None)}")
            raise SystemExit(1) from None
        for share in shares:
            print(f"{share.kind:10} {share.name}  {share.comment}")
