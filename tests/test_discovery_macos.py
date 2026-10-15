"""macOS discovery through `dns-sd`, from captured output.

Captured on a Mac on 15 October 2026 and rewritten with placeholder names and
documentation addresses (RFC 5737, RFC 3849), which the hygiene test requires.
Found the same day: `smbpal browse` and the window's "Browse servers" asked
for `avahi-browse` on a Mac, which has none.
"""

from __future__ import annotations

import unittest
from typing import Callable

from smbpal.discovery.browse import (
    SMB_SERVICE,
    SMBPAL_SERVICE,
    _has_last_address,
    discover,
    parse_dns_sd_addresses,
    parse_dns_sd_browse,
    parse_dns_sd_resolve,
)

BROWSE_SMB = """Browsing for _smb._tcp.local.
DATE: ---Thu 15 Oct 2026---
21:48:42.190  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
21:48:42.190  Add        3  12 local.               _smb._tcp.           NAS
21:48:42.190  Add        3  12 local.               _smb._tcp.           Someone’s MacBook Air
21:48:42.190  Add        2   1 local.               _smb._tcp.           Someone’s MacBook Air
21:48:43.001  Rmv        0  12 local.               _smb._tcp.           Gone Away
"""

BROWSE_SMBPAL = """Browsing for _smbpal._tcp.local.
DATE: ---Thu 15 Oct 2026---
21:49:36.099  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
21:49:36.100  Add        2  12 local.               _smbpal._tcp.        nas
"""

RESOLVE = {
    "NAS": "21:49:28.078  NAS._smb._tcp.local. can be reached at nas.local.:445 (interface 12)\n",
    "Someone’s MacBook Air": (
        "21:49:30.085  Someone’s\\032MacBook\\032Air._smb._tcp.local. can be reached at "
        "Someones-MacBook-Air.local.:445 (interface 1) Flags: 1\n"
    ),
}

ADDRESSES = {
    "nas.local.": (
        "Timestamp     A/R  Flags         IF  Hostname          Address          TTL\n"
        "21:49:34.096  Add  40000003      12  nas.local.        192.0.2.10       120\n"
        "21:49:34.096  Add  40000002      12  nas.local.        2001:db8::10     120\n"
    ),
    "Someones-MacBook-Air.local.": (
        "21:49:34.096  Add  40000002       1  Someones-MacBook-Air.local.  127.0.0.1  120\n"
    ),
}


def fake_dns_sd() -> Callable[..., str]:
    def run(args: list[str], window: float, until: object = None) -> str:
        if args[0] == "-B":
            return BROWSE_SMB if args[1] == SMB_SERVICE else BROWSE_SMBPAL
        if args[0] == "-L":
            if args[2] == SMBPAL_SERVICE:
                return "x nas._smbpal._tcp.local. can be reached at nas.local.:445 (interface 12)\n"
            return RESOLVE.get(args[1], "")
        if args[0] == "-G":
            return ADDRESSES.get(args[2], "")
        raise AssertionError(args)

    return run


class Parsing(unittest.TestCase):
    def test_browse_keeps_names_with_spaces_and_drops_removals(self) -> None:
        self.assertEqual(
            parse_dns_sd_browse(BROWSE_SMB),
            [(12, "NAS"), (12, "Someone’s MacBook Air"), (1, "Someone’s MacBook Air")],
        )

    def test_resolve_strips_the_trailing_dot(self) -> None:
        self.assertEqual(parse_dns_sd_resolve(RESOLVE["NAS"]), ("nas.local", 445, 12))

    def test_resolve_without_an_answer_is_none(self) -> None:
        self.assertIsNone(parse_dns_sd_resolve("Lookup NAS._smb._tcp.local.\n"))

    def test_addresses_v4_and_v6(self) -> None:
        self.assertEqual(
            parse_dns_sd_addresses(ADDRESSES["nas.local."]),
            [(12, "192.0.2.10"), (12, "2001:db8::10")],
        )

    def test_the_last_address_is_the_one_without_more_coming(self) -> None:
        first = ADDRESSES["nas.local."].splitlines()[:2]
        self.assertFalse(_has_last_address("\n".join(first)))
        self.assertTrue(_has_last_address(ADDRESSES["nas.local."]))


class Discover(unittest.TestCase):
    def test_a_mac_browses_with_dns_sd_and_merges_as_on_linux(self) -> None:
        machines = discover(platform="darwin", dns_sd=fake_dns_sd())
        self.assertEqual([m.hostname for m in machines], ["nas.local"])
        nas = machines[0]
        self.assertEqual(nas.addresses, ["192.0.2.10", "2001:db8::10"])
        self.assertTrue(nas.running_smbpal)

    def test_the_mac_itself_over_loopback_is_left_out(self) -> None:
        machines = discover(platform="darwin", dns_sd=fake_dns_sd())
        self.assertNotIn("Someones-MacBook-Air.local", [m.hostname for m in machines])

    def test_linux_still_asks_avahi(self) -> None:
        seen: list[str] = []

        def avahi(kind: str, timeout: float) -> str:
            seen.append(kind)
            return ""

        discover(platform="linux", runner=avahi)
        self.assertEqual(seen, [SMB_SERVICE, SMBPAL_SERVICE])


if __name__ == "__main__":
    unittest.main()
