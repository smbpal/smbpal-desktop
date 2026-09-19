"""This machine's name and addresses, as another device on the network would use them.

§3d: SMBPal **reports** the machine's name, it does not set it. §3e taught the
browse list to show every identity a remote machine answers to; this is the
same courtesy turned round, so a person standing at this machine can see what to
type on their phone or their Mac to reach it.

**The `.local` name is asked of Avahi, not built from the hostname.** They are
usually the same, and the case where they are not is exactly the one that
matters: a second machine on the network with the same hostname makes Avahi
rename this one (`raspberrypi-2.local`), and a name derived from
`gethostname()` would then point at the other machine. When Avahi is not
running there is no `.local` name at all, and saying so is more useful than
printing one that will not resolve.

**Addresses are IPv4 on links that are actually up**, loopback excluded. A
Docker bridge with nothing on it, or a Wi-Fi adapter that is switched off, holds
an address nobody can reach, and listing it invites someone to type the one that
does not work.

Everything except `identify()` is pure, so the rules are tested against
captured output.
"""

from __future__ import annotations

import json
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Any

from smbpal.errors import SmbpalError
from smbpal.system.run import CommandRunner, run

log = logging.getLogger(__name__)

BUSCTL = "busctl"
IP = "ip"
_TIMEOUT = 3.0

AVAHI_CALL = (
    BUSCTL,
    "--system",
    "call",
    "org.freedesktop.Avahi",
    "/",
    "org.freedesktop.Avahi.Server",
    "GetHostNameFqdn",
)
IP_ADDRESSES = (IP, "-j", "-4", "addr", "show")

# busctl prints a D-Bus string reply as `s "name"`.
_BUSCTL_STRING = re.compile(r'^s\s+"(.*)"\s*$')


@dataclass(frozen=True)
class Identity:
    hostname: str
    mdns: str | None
    addresses: list[str] = field(default_factory=list)

    def to_wire(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "mdns": self.mdns,
            "addresses": list(self.addresses),
        }


def parse_busctl_string(output: str) -> str | None:
    match = _BUSCTL_STRING.match(output.strip())
    if not match or not match.group(1):
        return None
    return match.group(1)


def parse_ip_addresses(output: str) -> list[str]:
    """IPv4 addresses from `ip -j -4 addr show`, on links that are up."""
    try:
        links = json.loads(output or "[]")
    except json.JSONDecodeError:
        return []
    found: list[str] = []
    for link in links:
        flags = link.get("flags") or []
        # LOWER_UP is the carrier: UP alone is only "an administrator enabled
        # it", which a Wi-Fi adapter with no network still is.
        if "LOOPBACK" in flags or "LOWER_UP" not in flags:
            continue
        for info in link.get("addr_info") or []:
            address = info.get("local")
            if info.get("family") != "inet" or not address:
                continue
            if info.get("scope") not in (None, "global"):
                continue
            if address not in found:
                found.append(address)
    return found


def describe(host: dict[str, Any] | None) -> str:
    """What to type on another device to reach this one: name, then addresses.

    Takes the wire form, so the window and the CLI say it the same way. The
    `.local` name first, because it survives a DHCP change and an address does
    not (§3e's reason for storing names, from the other side). Every address
    follows, since a machine on Ethernet and Wi-Fi at once really has two.
    Empty when nothing is known.
    """
    if not host:
        return ""
    parts = [host["mdns"]] if host.get("mdns") else []
    parts.extend(host.get("addresses") or [])
    return " · ".join(parts)


def identify(*, runner: CommandRunner | None = None) -> Identity:
    """Ask the system. Never raises: a part that cannot be read is left empty."""
    execute = runner or run
    mdns = None
    try:
        result = execute(list(AVAHI_CALL), timeout=_TIMEOUT)
        if result.ok:
            mdns = parse_busctl_string(result.stdout)
    except (SmbpalError, OSError) as exc:
        log.debug("could not ask Avahi for this machine's name: %s", exc)

    addresses: list[str] = []
    try:
        result = execute(list(IP_ADDRESSES), timeout=_TIMEOUT)
        if result.ok:
            addresses = parse_ip_addresses(result.stdout)
    except (SmbpalError, OSError) as exc:
        log.debug("could not list this machine's addresses: %s", exc)

    return Identity(hostname=socket.gethostname(), mdns=mdns, addresses=addresses)
