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

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Iterable

from smbpal.errors import Unavailable

SMB_SERVICE = "_smb._tcp"
SMBPAL_SERVICE = "_smbpal._tcp"

AVAHI_BROWSE = "avahi-browse"
DEFAULT_TIMEOUT = 5.0

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
    def replace(match: re.Match[str]) -> str:
        body = match.group(1)
        return chr(int(body)) if len(body) == 3 and body.isdigit() else body

    return _ESCAPE.sub(replace, value)


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
    if service.interface == "lo" or service.address in _LOOPBACK_ADDRESSES:
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


def discover(
    *, timeout: float = DEFAULT_TIMEOUT, runner: Runner | None = None
) -> list[Machine]:
    """Browse the network and return one row per machine."""
    run = runner or _run_avahi_browse
    return merge(
        parse(run(SMB_SERVICE, timeout)), parse(run(SMBPAL_SERVICE, timeout))
    )


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
