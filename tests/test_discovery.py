"""§3e's rules, tested against captured avahi output rather than a live network."""

from __future__ import annotations

import unittest

from smbpal.discovery import SMB_SERVICE, Machine, discover, merge, parse
from smbpal.errors import Unavailable

# Verbatim from M0's avahi-smb-service.txt, the capture that closed §5.
M0_CAPTURE = """\
+;wlan0;IPv4;RIVENDELL;Microsoft Windows Network;local
=;wlan0;IPv4;RIVENDELL;Microsoft Windows Network;local;RIVENDELL.local;192.168.0.52;445;
+;wlan0;IPv6;RASPBERRYPI;Microsoft Windows Network;local
+;wlan0;IPv4;RASPBERRYPI;Microsoft Windows Network;local
+;lo;IPv4;RASPBERRYPI;Microsoft Windows Network;local
=;wlan0;IPv6;RASPBERRYPI;Microsoft Windows Network;local;raspberrypi.local;fe80::1edb:1129:123b:6c0;445;
=;wlan0;IPv4;RASPBERRYPI;Microsoft Windows Network;local;raspberrypi.local;192.168.0.210;445;
=;lo;IPv4;RASPBERRYPI;Microsoft Windows Network;local;raspberrypi.local;127.0.0.1;445;
"""


class TestParse(unittest.TestCase):
    def test_only_resolved_lines_are_parsed(self) -> None:
        services = parse(M0_CAPTURE)
        self.assertEqual(len(services), 4)
        self.assertTrue(all(s.port == 445 for s in services))

    def test_fields_land_in_the_right_places(self) -> None:
        service = parse(M0_CAPTURE)[0]
        self.assertEqual(service.name, "RIVENDELL")
        self.assertEqual(service.hostname, "RIVENDELL.local")
        self.assertEqual(service.address, "192.168.0.52")

    def test_a_semicolon_in_a_name_does_not_shift_every_later_field(self) -> None:
        # avahi escapes rather than quotes, so a naive split(';') would tear the
        # name in half and misread the address as the domain.
        line = r"=;wlan0;IPv4;we\;ird;_smb._tcp;local;host.local;10.0.0.5;445;"
        service = parse(line)[0]
        self.assertEqual(service.name, "we;ird")
        self.assertEqual(service.address, "10.0.0.5")

    def test_decimal_escapes_are_decoded(self) -> None:
        line = "=;en0;IPv4;Luke\\039s\\032Mac;_smb._tcp;local;mac.local;10.0.0.6;445;"
        self.assertEqual(parse(line)[0].name, "Luke's Mac")

    def test_a_malformed_line_is_skipped_not_fatal(self) -> None:
        self.assertEqual(parse("=;too;few;fields\n=;a;b;c;d;e;f;g;notaport;"), [])


class TestMergeRules(unittest.TestCase):
    def setUp(self) -> None:
        self.machines = merge(parse(M0_CAPTURE))

    def test_one_row_per_machine(self) -> None:
        self.assertEqual([m.name for m in self.machines], ["RASPBERRYPI", "RIVENDELL"])

    def test_loopback_is_dropped(self) -> None:
        # Offering to mount your own share as a remote is nonsense.
        addresses = [a for m in self.machines for a in m.addresses]
        self.assertNotIn("127.0.0.1", addresses)

    def test_link_local_ipv6_is_suppressed(self) -> None:
        addresses = [a for m in self.machines for a in m.addresses]
        self.assertFalse([a for a in addresses if a.startswith("fe80")])

    def test_the_surviving_addresses_are_the_usable_ones(self) -> None:
        pi = next(m for m in self.machines if m.name == "RASPBERRYPI")
        self.assertEqual(pi.addresses, ["192.168.0.210"])
        self.assertEqual(pi.hostname, "raspberrypi.local")

    def test_ipv4_sorts_before_ipv6(self) -> None:
        capture = (
            "=;en0;IPv6;HOST;_smb._tcp;local;h.local;2001:db8::1;445;\n"
            "=;en0;IPv4;HOST;_smb._tcp;local;h.local;10.0.0.9;445;\n"
        )
        self.assertEqual(merge(parse(capture))[0].addresses, ["10.0.0.9", "2001:db8::1"])


class TestSmbpalJoin(unittest.TestCase):
    SMB = "=;wlan0;IPv4;RASPBERRYPI;_smb._tcp;local;raspberrypi.local;192.168.0.210;445;"
    SMBPAL = "=;wlan0;IPv4;raspberrypi;_smbpal._tcp;local;raspberrypi.local;192.168.0.210;445;v=1"

    def test_the_join_is_on_hostname_not_instance_name(self) -> None:
        # §3f: Samba's instance is the NetBIOS name uppercased (RASPBERRYPI)
        # while ours follows Avahi's hostname (raspberrypi). Matching on the
        # instance would silently never join, and every machine would render as
        # "not running SMBPal" — a feature that looks like it works.
        machines = merge(parse(self.SMB), parse(self.SMBPAL))
        self.assertEqual(len(machines), 1)
        self.assertTrue(machines[0].running_smbpal)
        self.assertEqual(machines[0].name, "RASPBERRYPI")

    def test_a_machine_without_our_record_is_reported_as_such(self) -> None:
        machines = merge(parse(self.SMB), [])
        self.assertFalse(machines[0].running_smbpal)

    def test_an_smbpal_record_with_no_smb_record_adds_no_row(self) -> None:
        # We advertise only while sharing (§3f), so this should not arise — and
        # if it does, a machine offering no SMB service is not a row worth
        # showing in a list of places to connect to.
        self.assertEqual(merge([], parse(self.SMBPAL)), [])


class TestDiscover(unittest.TestCase):
    def test_discover_browses_both_service_types(self) -> None:
        asked: list[str] = []

        def runner(service_type: str, _timeout: float) -> str:
            asked.append(service_type)
            return M0_CAPTURE if service_type == SMB_SERVICE else ""

        machines = discover(runner=runner)
        self.assertEqual(len(asked), 2)
        self.assertIn(SMB_SERVICE, asked)
        self.assertEqual(len(machines), 2)

    def test_a_wire_row_carries_names_and_addresses_apart(self) -> None:
        machine = Machine(name="PI", hostname="pi.local", addresses=["10.0.0.1"])
        self.assertEqual(
            machine.to_wire(),
            {
                "name": "PI",
                "hostname": "pi.local",
                "addresses": ["10.0.0.1"],
                "port": 445,
                "running_smbpal": False,
            },
        )

    def test_a_missing_avahi_browse_is_reported_as_unavailable(self) -> None:
        import smbpal.discovery.browse as browse

        original = browse.shutil.which
        browse.shutil.which = lambda _name: None
        self.addCleanup(setattr, browse.shutil, "which", original)
        with self.assertRaises(Unavailable) as caught:
            discover()
        self.assertIn("avahi-utils", caught.exception.detail or "")


if __name__ == "__main__":
    unittest.main()
