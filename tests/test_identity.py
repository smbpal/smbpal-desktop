"""This machine's name and addresses, read from captured output."""

from __future__ import annotations

import json
import unittest

from smbpal.discovery import identity
from smbpal.discovery.identity import Identity
from smbpal.errors import SmbpalError
from smbpal.system.run import CommandFailed, CommandResult

# The shape of `ip -j -4 addr show` on a Pi with Ethernet up and Wi-Fi off,
# a Docker bridge nothing is attached to, and a link-local address.
IP_JSON = json.dumps(
    [
        {
            "ifname": "lo",
            "flags": ["LOOPBACK", "UP", "LOWER_UP"],
            "addr_info": [{"family": "inet", "local": "127.0.0.1", "scope": "host"}],
        },
        {
            "ifname": "eth0",
            "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "addr_info": [
                {"family": "inet", "local": "192.0.2.10", "scope": "global"},
                {"family": "inet", "local": "169.254.3.4", "scope": "link"},
            ],
        },
        {
            "ifname": "wlan0",
            "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"],
            "addr_info": [
                {"family": "inet", "local": "198.51.100.7", "scope": "global"}
            ],
        },
        {
            "ifname": "docker0",
            "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"],
            "addr_info": [
                {"family": "inet", "local": "198.51.100.9", "scope": "global"}
            ],
        },
        {
            "ifname": "eth1",
            "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "addr_info": [
                {"family": "inet", "local": "203.0.113.5", "scope": "global"}
            ],
        },
    ]
)


class TestReadingAvahi(unittest.TestCase):
    def test_the_name_avahi_answers_to(self) -> None:
        self.assertEqual(identity.parse_busctl_string('s "nas.local"\n'), "nas.local")

    def test_a_renamed_host_is_reported_as_renamed(self) -> None:
        """The reason this asks Avahi rather than building it from the hostname."""
        self.assertEqual(
            identity.parse_busctl_string('s "raspberrypi-2.local"'),
            "raspberrypi-2.local",
        )

    def test_nothing_useful_is_none(self) -> None:
        for output in ("", 's ""', "garbage"):
            with self.subTest(output=output):
                self.assertIsNone(identity.parse_busctl_string(output))


class TestReadingAddresses(unittest.TestCase):
    def test_only_live_links_and_never_loopback_or_link_local(self) -> None:
        self.assertEqual(
            identity.parse_ip_addresses(IP_JSON), ["192.0.2.10", "203.0.113.5"]
        )

    def test_output_that_is_not_json_is_no_addresses(self) -> None:
        self.assertEqual(identity.parse_ip_addresses("inet 192.0.2.10/24"), [])
        self.assertEqual(identity.parse_ip_addresses(""), [])


class FakeRunner:
    def __init__(self, avahi: CommandResult | Exception, ip: CommandResult | Exception):
        self.answers = {"busctl": avahi, "ip": ip}

    def __call__(self, argv, **_kwargs):
        answer = self.answers[argv[0]]
        if isinstance(answer, Exception):
            raise answer
        return answer


def ok(argv: str, stdout: str) -> CommandResult:
    return CommandResult((argv,), 0, stdout, "")


class TestIdentify(unittest.TestCase):
    def test_both_answers_are_used(self) -> None:
        found = identity.identify(
            runner=FakeRunner(ok("busctl", 's "nas.local"'), ok("ip", IP_JSON))
        )
        self.assertEqual(found.mdns, "nas.local")
        self.assertEqual(found.addresses, ["192.0.2.10", "203.0.113.5"])
        self.assertTrue(found.hostname)

    def test_no_avahi_means_no_local_name_rather_than_a_guessed_one(self) -> None:
        refused = CommandResult(("busctl",), 1, "", "The name is not activatable")
        found = identity.identify(runner=FakeRunner(refused, ok("ip", IP_JSON)))
        self.assertIsNone(found.mdns)
        self.assertEqual(found.addresses, ["192.0.2.10", "203.0.113.5"])

    def test_missing_tools_never_raise(self) -> None:
        missing = CommandFailed("busctl is not installed")
        found = identity.identify(
            runner=FakeRunner(missing, CommandFailed("ip is not installed"))
        )
        self.assertEqual((found.mdns, found.addresses), (None, []))
        self.assertIsInstance(missing, SmbpalError)


class TestDescribe(unittest.TestCase):
    def test_name_first_then_every_address(self) -> None:
        host = Identity("nas", "nas.local", ["192.0.2.10", "203.0.113.5"]).to_wire()
        self.assertEqual(
            identity.describe(host), "nas.local · 192.0.2.10 · 203.0.113.5"
        )

    def test_addresses_alone_when_there_is_no_local_name(self) -> None:
        host = Identity("nas", None, ["192.0.2.10"]).to_wire()
        self.assertEqual(identity.describe(host), "192.0.2.10")

    def test_nothing_known_is_empty(self) -> None:
        self.assertEqual(identity.describe(None), "")
        self.assertEqual(identity.describe(Identity("nas", None, []).to_wire()), "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
