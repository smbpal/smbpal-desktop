"""What the agent will answer, and what it refuses to become.

**Seven methods, in two groups.** Mount, unmount, the URL that would remount
something, and a ping; then the three that put a credential in the login
Keychain, look for one, and take one away. It holds no configuration, writes no
files and makes no decisions: the daemon decides what should be mounted and
this does the mounting, because on macOS the mounting is the part that cannot
be done from root — and the credential is the other half of the same fact,
since the Keychain it has to come from is unreadable there.

**Authorisation is one line, and it is not a simplification.** The daemon has
polkit, a group-guarded socket and an `Authoriser`, because it acts for
everyone and must decide whether this caller may. The agent acts for exactly
one person — the one whose Keychain it can read and whose session it runs in —
so the only question is whether the peer is that person. `ipc/peer.py` answers
it from the kernel, and it already implements macOS: `getpeereid(2)` gives uid
and gid, and its docstring says why `pid` is optional rather than a lie.

**And root, which is the caller this exists for.** The daemon asks on behalf of
whoever asked it (`agent/client.py`), so it arrives as uid 0. Admitting root is
not a hole: root can `launchctl asuser` into this session and run anything at
all in it, including something that reads the Keychain, so refusing it here
would protect nothing and would leave the daemon unable to mount. Every other
uid stays refused, which is the question the kernel's answer actually settles.

**A credential never lands here.** `mount` takes a password and hands it
straight to `netfs.mount`, which makes it a `CFString` for the length of one
call. It is not stored, not logged, and not echoed in an error — the detail on
a failure is the status number, never the request.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Callable
from urllib.parse import urlsplit

from smbpal.errors import SmbpalError
from smbpal.ipc.protocol import Request, encode_failure, encode_success, parse_request
from smbpal.ipc.transport import Connection
from smbpal.agent import keychain as keychain_module
from smbpal.agent.ledger import MountLedger
from smbpal.mounts import netfs, volumes

log = logging.getLogger(__name__)


class NotYours(SmbpalError):
    code = "not_yours"


class UnknownMethod(SmbpalError):
    code = "unknown_method"


def _require_str(params: dict[str, Any], name: str) -> str:
    value = params.get(name)
    if not isinstance(value, str) or not value:
        raise SmbpalError(f"{name} is required and must be a string")
    return value


class AgentDispatcher:
    """One user's mounting, behind the same protocol the daemon speaks."""

    def __init__(
        self,
        *,
        uid: int | None = None,
        mounter: Any = netfs,
        keychain: Any = keychain_module,
        mounts: Callable[[], list[volumes.SmbMount]] = volumes.smb_mounts,
        ledger: Any = None,
    ) -> None:
        # Injected so the suite can run on Linux, where neither NetFS nor the
        # Keychain exists and where CI runs. The defaults are the real things.
        self.uid = os.getuid() if uid is None else uid
        self.mounter = mounter
        self.keychain = keychain
        self.mounts = mounts
        # Which mounts SMBPal made (`agent/ledger.py`). In memory unless `main`
        # gives it a file, so the suite never writes into a home directory.
        self.ledger = ledger if ledger is not None else MountLedger(mounts=mounts)
        # One mount at a time. The reconnect loop and a `connect` from the
        # daemon can otherwise both find a share unmounted and both mount it,
        # and macOS answers the second with `/Volumes/Code-1`.
        self._mount_lock = threading.Lock()
        # Set by `main` when the reconnect loop runs, so a connect or
        # disconnect asked for through SMBPal reaches it: the loop must not
        # mount back what somebody disconnected on purpose.
        self.reconnector: Any = None

    # --- the methods -------------------------------------------------------

    def _ping(self, _request: Request) -> dict[str, Any]:
        return {"ok": True, "uid": self.uid, "platform_supported": netfs.available()}

    def _mount(self, request: Request) -> dict[str, Any]:
        """Mount, with the password fetched from the Keychain if none was sent.

        **The daemon never sends one.** It fetches it here because NetFS will
        not: under `kNAUIOptionNoUI` the Keychain is not consulted, measured
        against a real server on 2 October 2026, and there is no option to turn
        the lookup on without permitting a dialog this process must not raise.
        So the credential is read inside the session, by the one process that
        can, and handed straight to `netfs.mount`.

        `host` comes from the daemon rather than from the URL, because the
        daemon is what stored the item and the lookup key has to be the string
        it stored under. Falling back to the URL's hostname keeps a direct
        caller working, at the cost of its lowercasing.
        """
        url = _require_str(request.params, "url")
        result = self.mount_url(
            url,
            user=request.params.get("user") or None,
            password=request.params.get("password") or None,
            host=request.params.get("host") or None,
        )
        if self.reconnector is not None:
            self.reconnector.connected(url, result["mountpoint"])
        return result

    def mount_url(
        self,
        url: str,
        *,
        user: str | None = None,
        password: str | None = None,
        host: str | None = None,
    ) -> dict[str, Any]:
        """The mount itself, shared by `agent.mount` and the reconnect loop.

        **A share already mounted by this user is answered, not mounted
        again.** Found on 15 October 2026: the loop had mounted Code at
        `/Volumes/Code` a moment before `connection connect` arrived, and NetFS
        mounted a second copy at `/Volumes/Code-1`. The table is read without
        blocking (`mounts/volumes.py`), under the same lock as the mount.
        """
        with self._mount_lock:
            key = volumes.key_for_url(url)
            for existing in self.mounts():
                if existing.owner_uid == self.uid and existing.key == key:
                    log.info("%s is already mounted at %s", url, existing.mountpoint)
                    return {
                        "url": url,
                        "mountpoint": existing.mountpoint,
                        "used_keychain": False,
                        "already": True,
                    }
            return self._mount_now(url, user=user, password=password, host=host)

    def _mount_now(
        self,
        url: str,
        *,
        user: str | None,
        password: str | None,
        host: str | None,
    ) -> dict[str, Any]:
        looked_up = False
        if password is None and user:
            host = host or urlsplit(url).hostname
            if host:
                password = self.keychain.get_password(str(host), user)
                looked_up = password is not None
        where = self.mounter.mount(url, user=user, password=password)
        self._remember(url, where)
        # The URL is safe to log and the password was never in the message we
        # keep: `request.params` is not logged anywhere, and this line names
        # only what a mount table would show anyway. Whether a credential was
        # found is worth saying; what it was is not.
        log.info(
            "mounted %s at %s%s",
            url,
            where,
            " (credential from the Keychain)" if looked_up else "",
        )
        return {"url": url, "mountpoint": where, "used_keychain": looked_up}

    def _remember(self, url: str, where: str) -> None:
        """Write the mount just made into the ledger, by its filesystem id."""
        key = volumes.key_for_url(url)
        for mount in self.mounts():
            if mount.owner_uid == self.uid and mount.key == key and mount.mountpoint == where:
                self.ledger.record(mount)
                return
        log.warning("mounted %s at %s but cannot find it in the mount table", url, where)

    def _release(self, request: Request) -> dict[str, Any]:
        """Unmount what SMBPal mounted for a share, and say what was left.

        For `connection remove`. Unlike a disconnect, which unmounts the share
        wherever it is because a person asked for exactly that, removal only
        undoes SMBPal's own work: a mount the ledger does not hold is left
        alone and reported, and so is one macOS will not unmount because it is
        in use.
        """
        url = _require_str(request.params, "url")
        key = volumes.key_for_url(url)
        unmounted: list[str] = []
        left: list[dict[str, str]] = []
        for mount in self.mounts():
            if mount.owner_uid != self.uid or mount.key != key:
                continue
            if not self.ledger.owns(mount):
                left.append({"mountpoint": mount.mountpoint, "reason": "not-ours"})
                continue
            try:
                self.mounter.unmount(mount.mountpoint)
            except SmbpalError as exc:
                left.append(
                    {"mountpoint": mount.mountpoint, "reason": "busy", "detail": exc.message}
                )
                continue
            self.ledger.forget(mount)
            unmounted.append(mount.mountpoint)
        if unmounted:
            log.info("released %s: unmounted %s", url, ", ".join(unmounted))
        return {"url": url, "unmounted": unmounted, "left": left}

    def _unmount(self, request: Request) -> dict[str, Any]:
        """Unmount, by the share when the caller names it.

        **A recorded mountpoint goes stale**, and the record is all the daemon
        has: macOS chooses where a mount lands, and Finder, an eject or a
        duplicate can move it after the daemon wrote it down. Found on
        15 October 2026: the record said `/Volumes/Code-1`, Code was mounted
        at `/Volumes/Code`, and `disconnect` reported "nothing was mounted"
        while the share stayed mounted. So with a `url` the mount table is
        asked which of this user's mounts are that share, and every one of
        them is unmounted: a disconnect means none, not one fewer. The
        `mountpoint` is still tried when the table has nothing, which keeps a
        caller that sends no URL working as before.
        """
        mountpoint = _require_str(request.params, "mountpoint")
        url = request.params.get("url")
        targets: list[str] = []
        if isinstance(url, str) and url:
            key = volumes.key_for_url(url)
            targets = [
                m.mountpoint
                for m in self.mounts()
                if m.owner_uid == self.uid and m.key == key
            ]
        if not targets:
            targets = [mountpoint]
        # `unmount` is idempotent and says which it was, so the caller can tell
        # a person "unmounted" from "there was nothing mounted there" rather
        # than reporting the first for both.
        unmounted = [where for where in targets if self.mounter.unmount(where)]
        for mount in self.mounts():
            if mount.mountpoint in unmounted:
                self.ledger.forget(mount)
        if self.reconnector is not None:
            # Held whether or not anything was mounted there: "disconnect" is
            # the state the person asked for, and a mount that had already
            # dropped is exactly the one the loop would otherwise put back.
            for where in {mountpoint, *targets}:
                self.reconnector.released(where)
        return {
            "mountpoint": unmounted[0] if unmounted else mountpoint,
            "unmounted": bool(unmounted),
            "mountpoints": unmounted,
        }

    def _remount_url(self, request: Request) -> dict[str, Any]:
        mountpoint = _require_str(request.params, "mountpoint")
        return {
            "mountpoint": mountpoint,
            "url": self.mounter.remount_url(mountpoint),
        }

    # --- the credential, which is the reason this process exists -----------

    def _credential_set(self, request: Request) -> dict[str, Any]:
        """Put the password where NetFS will find it, and nowhere else.

        **The password is in this process for the length of one call.** It
        arrives on the socket, goes into a `CFData`, and is released with the
        rest of the CoreFoundation objects. It is not written to a file, not
        kept in an attribute, and not logged — `handle` logs a method name and
        an error code, and these params are the reason that rule exists.

        The reply says *created* or *replaced*, because the daemon has to
        record which: one Keychain item per server and account, so a password
        for a share Finder already knows about overwrites the person's own
        item, and §10.6 must not then delete it on uninstall.
        """
        host = _require_str(request.params, "host")
        account = _require_str(request.params, "account")
        password = _require_str(request.params, "password")
        return {
            "host": host,
            "account": account,
            "outcome": self.keychain.set_password(host, account, password),
        }

    def _credential_present(self, request: Request) -> dict[str, Any]:
        host = _require_str(request.params, "host")
        account = _require_str(request.params, "account")
        return {
            "host": host,
            "account": account,
            "present": self.keychain.present(host, account),
        }

    def _credential_forget(self, request: Request) -> dict[str, Any]:
        """Remove it. Whether SMBPal may is the caller's question, not ours."""
        host = _require_str(request.params, "host")
        account = _require_str(request.params, "account")
        return {
            "host": host,
            "account": account,
            "removed": self.keychain.forget(host, account),
        }

    def perform(self, method: str, params: dict[str, Any]) -> Any:
        """Run one method for a request that came down the daemon link.

        The socket's ownership check does not apply, and nothing is skipped by
        that: the link only exists once `agent/link.py` has confirmed the
        listener is the daemon, which is the caller `_may` admits anyway.
        """
        handler = self._methods().get(method)
        if handler is None:
            raise UnknownMethod(f"no such method: {method}")
        return handler(Request(id="link", method=method, params=params))

    # --- who may ask -------------------------------------------------------

    def _may(self, uid: int) -> bool:
        """The owner, and root. Nobody else, which is the real question.

        See the module docstring for why root is not a loophole. Kept as a
        method rather than inlined so that the one-line rule has one place to
        be read, and so a test can state it as a rule rather than as a case.
        """
        return uid in (self.uid, 0)

    # --- the wire ----------------------------------------------------------

    def handle(self, connection: Connection, frame: bytes) -> bytes | None:
        request: Request | None = None
        try:
            request = parse_request(frame)
            # Existence before ownership, for the reason the daemon gives:
            # answering "not yours" for a method that does not exist sends
            # somebody hunting a permission problem they do not have.
            method = self._methods().get(request.method)
            if method is None:
                raise UnknownMethod(f"no such method: {request.method}")
            if not self._may(connection.peer.uid):
                raise NotYours(
                    "this agent serves one person and you are not them",
                    detail=(
                        f"the socket belongs to uid {self.uid} and the caller "
                        f"is uid {connection.peer.uid}"
                    ),
                )
            return encode_success(request.id, method(request))
        except SmbpalError as exc:
            # **The agent's stderr is a log file**, which is the whole point of
            # the plist's `StandardErrorPath` — and until now a refused mount
            # wrote nothing to it. The only record of why was the reply, which
            # goes to the daemon and is gone. Found on 2 October 2026, by
            # reading an empty log after a mount that failed. The method and the
            # code; never the params, one of which can be a password.
            log.info(
                "%s -> %s: %s",
                request.method if request else "<unparsed>",
                exc.code,
                exc.message,
            )
            return encode_failure(request.id if request else None, exc)
        except Exception as exc:  # pragma: no cover - the last resort
            log.exception("agent failed to handle a request")
            return encode_failure(
                request.id if request else None,
                SmbpalError("the agent could not do that", detail=str(exc)),
            )

    def _methods(self) -> dict[str, Callable[[Request], dict[str, Any]]]:
        return {
            "agent.ping": self._ping,
            "agent.mount": self._mount,
            "agent.unmount": self._unmount,
            "agent.release": self._release,
            "agent.remount_url": self._remount_url,
            "agent.credential_set": self._credential_set,
            "agent.credential_present": self._credential_present,
            "agent.credential_forget": self._credential_forget,
        }
