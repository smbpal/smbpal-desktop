"""§3e: find SMB servers over mDNS and report every address each answers to.

`avahi-browse -rptk <type>`, four flags each of which earns its place:

    -r  resolve, so we get hostname, address and port rather than just a name
    -p  parsable — semicolon-separated fields instead of aligned columns
    -t  terminate once the cache is exhausted, rather than watching forever
    -k  **no service-type lookup**

`-k` is the one worth explaining. `-p` alone does *not* give a raw service type:
M0's own capture came back with `Microsoft Windows Network` in the type column
even in parsable mode, because avahi resolves the type against its description
database unless told not to. The plan's §3e note that `-p` is what makes the
type raw is half right — `-p` fixes the field separation, `-k` fixes the type.
We browse one type at a time so we do not depend on the column, but a parser
that silently accepts a prose type is a parser waiting to match the wrong thing.

Everything here except `discover()` is pure, so the rules in `merge()` are
tested against captured output rather than against a live network.
"""

from __future__ import annotations

import os
import re
import selectors
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable

from smbpal.errors import Unavailable

SMB_SERVICE = "_smb._tcp"
SMBPAL_SERVICE = "_smbpal._tcp"

AVAHI_BROWSE = "avahi-browse"
DEFAULT_TIMEOUT = 5.0
# macOS: Apple's own client for mDNSResponder. Not Python's resolver: the Local
# Network privacy gate refuses Homebrew's interpreter a `.local` lookup
# (`probe.can_probe`), and Apple's binary is let through.
DNS_SD = "/usr/bin/dns-sd"

# One pass over `\ddd` (avahi's decimal form for anything non-printable) and
# `\X` (everything else it escapes, including ';' '.' and '\\' itself). A single
# regex rather than chained str.replace calls, so an unescaped result cannot be
# fed back in and unescaped a second time.
_ESCAPE = re.compile(r"\\(\d{3}|.)", re.DOTALL)
_LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1"})


@dataclass(frozen=True)
class Service:
    """One resolved `=` line."""

    interface: str
    protocol: str
    name: str
    type: str
    domain: str
    hostname: str
    address: str
    port: int
    txt: str = ""


@dataclass
class Machine:
    """One machine, however many records it published."""

    name: str
    hostname: str
    addresses: list[str] = field(default_factory=list)
    port: int = 445
    running_smbpal: bool = False

    def to_wire(self) -> dict[str, object]:
        return {
            "name": self.name,
            "hostname": self.hostname,
            "addresses": self.addresses,
            "port": self.port,
            "running_smbpal": self.running_smbpal,
        }


# --- parsing ---------------------------------------------------------------


def parse(text: str) -> list[Service]:
    """Parse the resolved lines out of `avahi-browse -p` output."""
    services: list[Service] = []
    for line in text.splitlines():
        if not line.startswith("="):
            # '+' is an unresolved announcement and '-' a withdrawal. Neither
            # carries an address, and -r means a '=' follows for anything real.
            continue
        fields = _split_escaped(line, limit=10)
        if len(fields) < 9:
            continue
        try:
            port = int(fields[8])
        except ValueError:
            continue
        services.append(
            Service(
                interface=fields[1],
                protocol=fields[2],
                name=_unescape(fields[3]),
                type=fields[4],
                domain=fields[5],
                hostname=_unescape(fields[6]),
                address=fields[7],
                port=port,
                txt=fields[9] if len(fields) > 9 else "",
            )
        )
    return services


def _split_escaped(line: str, *, limit: int) -> list[str]:
    """Split on ';' while honouring backslash escapes.

    A service name may legitimately contain a semicolon, and avahi escapes it
    rather than quoting the field. `str.split(';')` would tear such a name in
    half and shift every field after it.
    """
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append("\\")
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ";" and len(fields) < limit - 1:
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def _unescape(value: str) -> str:
    """Undo avahi's escaping, decoding `\\ddd` runs as **bytes**.

    avahi escapes each non-printable *byte*, so one character outside ASCII
    arrives as several escapes: `Luke\\226\\128\\153s` is a single U+2019. The
    first version of this mapped each escape to a codepoint of its own with
    `chr(int(body))`, which turned every such name into mojibake —
    `Lukeâ€™s MacBook Air`. **macOS names a machine
    `<Name>’s MacBook Air` with a curly apostrophe by default**, so that was
    nearly every Mac discovered from a Linux client. Found by browsing a real
    Mac, 10 October 2026; docs §6.19.

    The whole string goes through a byte buffer rather than only the escapes,
    because a multi-byte character may be split across escaped and unescaped
    runs and only one decode can see both halves. `errors="replace"` because a
    truncated sequence is a name to render imperfectly, never a reason to drop
    a machine off the list.
    """
    out = bytearray()
    # `re.split` on a pattern with one group alternates literal, body, literal.
    for index, part in enumerate(_ESCAPE.split(value)):
        if index % 2 == 0:
            out += part.encode("utf-8")
        elif part.isascii() and part.isdigit() and len(part) == 3 and int(part) < 256:
            # `\\d` matches non-ASCII digits too, and `\\999` is not a byte, so
            # neither is taken on trust just because the regex matched.
            out.append(int(part))
        else:
            out += part.encode("utf-8")
    return out.decode("utf-8", errors="replace")


# --- the §3e rules ---------------------------------------------------------


def merge(
    smb: Iterable[Service], smbpal: Iterable[Service] = ()
) -> list[Machine]:
    """Collapse records into one row per machine, applying §3e's three rules."""
    machines: dict[str, Machine] = {}

    for service in smb:
        if _is_uninteresting(service):
            continue
        # Key on hostname rather than instance name. §3e asks for dedup by
        # instance name, and this subsumes it: one machine has one .local name,
        # and the hostname is also the join key below and the thing you would
        # actually connect to.
        key = service.hostname.lower()
        machine = machines.get(key)
        if machine is None:
            machine = Machine(
                name=service.name, hostname=service.hostname, port=service.port
            )
            machines[key] = machine
        if service.address not in machine.addresses:
            machine.addresses.append(service.address)

    # §3f: join on hostname, never on instance name. Samba's instance is the
    # NetBIOS name uppercased (RASPBERRYPI) while ours follows Avahi's hostname
    # (raspberrypi) — matching on the instance would silently never join, and
    # every machine would render as "not running SMBPal".
    for service in smbpal:
        machine = machines.get(service.hostname.lower())
        if machine is not None:
            machine.running_smbpal = True

    for machine in machines.values():
        machine.addresses.sort(key=_address_sort_key)
    return sorted(machines.values(), key=lambda m: m.name.lower())


def _is_uninteresting(service: Service) -> bool:
    # `lo` is Linux's loopback and `lo0` macOS's.
    if service.interface in ("lo", "lo0") or service.address in _LOOPBACK_ADDRESSES:
        # This machine advertising to itself. Offering to mount your own share
        # as a remote is nonsense.
        return True
    if service.address.lower().startswith("fe80:"):
        # Link-local IPv6 is unusable without a scope id and means nothing to
        # a person reading a list.
        return True
    return not service.hostname


def _address_sort_key(address: str) -> tuple[int, str]:
    # IPv4 first: it is the one a person recognises.
    return (1, address) if ":" in address else (0, address)


# --- running it ------------------------------------------------------------

Runner = Callable[[str, float], str]


# `(args, window, until)`: run `dns-sd` for at most `window` seconds, stopping
# early once `until` says the output so far holds the answer.
DnsSd = Callable[[list[str], float, Callable[[str], bool] | None], str]


def discover(
    *,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner | None = None,
    platform: str | None = None,
    dns_sd: DnsSd | None = None,
) -> list[Machine]:
    """Browse the network and return one row per machine."""
    if runner is None and (platform or _platform()) == "darwin":
        # Both types at once: each spends most of its time waiting.
        with ThreadPoolExecutor(max_workers=2) as pool:
            smb, smbpal = pool.map(
                lambda kind: discover_dns_sd(kind, timeout, dns_sd),
                (SMB_SERVICE, SMBPAL_SERVICE),
            )
        return merge(smb, smbpal)
    run = runner or _run_avahi_browse
    return merge(
        parse(run(SMB_SERVICE, timeout)), parse(run(SMBPAL_SERVICE, timeout))
    )


def _platform() -> str:
    """The platform, asked at call time and only by this module.

    A function rather than `sys.platform` read in place, so a test can choose
    the Linux route without telling the whole process it is on Linux -- which
    sent the CLI looking for Linux sockets and polkit, and stalled it.
    """
    return sys.platform


# --- macOS: dns-sd ---------------------------------------------------------
#
# Found on 15 October 2026: `smbpal browse` and the window's "Browse servers"
# had never worked on a Mac -- both asked for `avahi-browse`, which macOS does
# not have, and the Homebrew caveats said browsing worked. `dns-sd` is three
# steps where avahi's `-r` is one: browse for instance names, resolve each to a
# host and port, then look the host up. None of them exits on its own, so each
# runs for a window and is stopped, and the second and third run in parallel.

_RESOLVED = re.compile(
    r"can be reached at (?P<host>.+?):(?P<port>\d+) \(interface (?P<index>\d+)\)"
)


def parse_dns_sd_browse(text: str) -> list[tuple[int, str]]:
    """`(interface index, instance name)` from `dns-sd -B` output.

    Columns are `Timestamp A/R Flags if Domain Type Name`, and the name is the
    rest of the line, because it may contain spaces.
    """
    found: list[tuple[int, str]] = []
    for line in text.splitlines():
        fields = line.split(None, 6)
        if len(fields) < 7 or fields[1] != "Add":
            continue
        try:
            found.append((int(fields[3]), fields[6].strip()))
        except ValueError:
            continue
    return found


def parse_dns_sd_resolve(text: str) -> tuple[str, int, int] | None:
    """`(hostname, port, interface index)` from `dns-sd -L` output."""
    match = _RESOLVED.search(text)
    if match is None:
        return None
    return (
        match.group("host").rstrip("."),
        int(match.group("port")),
        int(match.group("index")),
    )


def parse_dns_sd_addresses(text: str) -> list[tuple[int, str]]:
    """`(interface index, address)` from `dns-sd -G v4v6` output."""
    found: list[tuple[int, str]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[1] != "Add":
            continue
        try:
            found.append((int(fields[3]), fields[5]))
        except ValueError:
            continue
    return found


def discover_dns_sd(
    service_type: str, timeout: float, run: DnsSd | None = None
) -> list[Service]:
    """Every instance of `service_type`, resolved, as avahi's `Service` rows."""
    execute = run or _run_dns_sd
    # Browsing has no last answer, so it gets most of the budget; a resolve or
    # a lookup stops at its first answer and keeps the rest only in reserve.
    browse_window = max(1.0, timeout * 0.6)
    window = max(1.0, timeout * 0.2)
    names = sorted({name for _index, name in parse_dns_sd_browse(
        execute(["-B", service_type, "local."], browse_window, None)
    )})
    if not names:
        return []
    with ThreadPoolExecutor(max_workers=min(16, len(names))) as pool:
        resolved = dict(zip(names, pool.map(
            lambda name: parse_dns_sd_resolve(
                execute(["-L", name, service_type, "local."], window, _has_resolve)
            ),
            names,
        )))
        hosts = sorted({r[0] for r in resolved.values() if r is not None})
        addresses = dict(zip(hosts, pool.map(
            lambda host: parse_dns_sd_addresses(
                execute(["-G", "v4v6", host + "."], window, _has_last_address)
            ),
            hosts,
        )))
    services: list[Service] = []
    for name in names:
        found = resolved.get(name)
        if found is None:
            continue
        host, port, _index = found
        for index, address in addresses.get(host, []):
            services.append(
                Service(
                    interface=_interface_name(index),
                    protocol="IPv6" if ":" in address else "IPv4",
                    name=name,
                    type=service_type,
                    domain="local",
                    hostname=host,
                    address=address,
                    port=port,
                )
            )
    return services


def _has_resolve(text: str) -> bool:
    return _RESOLVED.search(text) is not None


def _has_last_address(text: str) -> bool:
    """An `Add` without mDNSResponder's more-coming bit (0x1) is the last."""
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[1] == "Add":
            try:
                if not int(fields[2], 16) & 0x1:
                    return True
            except ValueError:
                continue
    return False


def _interface_name(index: int) -> str:
    try:
        return socket.if_indextoname(index)
    except OSError:
        return str(index)


def _run_dns_sd(
    args: list[str], window: float, until: Callable[[str], bool] | None = None
) -> str:
    """Run `dns-sd` for up to `window` seconds and return what it printed.

    It never exits by itself, so being stopped is the normal end, not an
    error; with `until`, it is stopped as soon as the output answers the
    question. A missing binary is an error, and says so.
    """
    try:
        process = subprocess.Popen(
            [DNS_SD, *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
    except OSError as exc:
        raise Unavailable(f"cannot run {DNS_SD}", detail=str(exc)) from exc
    assert process.stdout is not None
    out = bytearray()
    deadline = time.monotonic() + window
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while (left := deadline - time.monotonic()) > 0:
            if not selector.select(left):
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            out += chunk
            if until is not None and until(out.decode("utf-8", errors="replace")):
                break
    process.terminate()
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    process.stdout.close()
    return out.decode("utf-8", errors="replace")


def _run_avahi_browse(service_type: str, timeout: float) -> str:
    if shutil.which(AVAHI_BROWSE) is None:
        raise Unavailable(
            "network discovery needs avahi-browse, which is not installed",
            detail="It lives in the avahi-utils package, which avahi-daemon does "
            "not pull in. Until then, connect by typing a hostname or address.",
        )
    try:
        completed = subprocess.run(
            [AVAHI_BROWSE, "-rptk", service_type],
            capture_output=True,
            text=True,
            timeout=timeout + 2.0,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise Unavailable(
            f"{AVAHI_BROWSE} did not finish within {timeout + 2:g}s"
        ) from None
    except OSError as exc:
        raise Unavailable(f"cannot run {AVAHI_BROWSE}", detail=str(exc)) from exc

    if completed.returncode != 0 and not completed.stdout:
        raise Unavailable(
            f"{AVAHI_BROWSE} failed",
            detail=(completed.stderr or "").strip() or f"exit {completed.returncode}",
        )
    return completed.stdout
