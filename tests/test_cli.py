#!/usr/bin/env python3
import argparse
import pathlib
import platform
import shlex
import shutil
import struct
import subprocess
import tempfile
import unittest

from fixtures import ether, ipv4, ipv6, pcap, sample_packets, sll, tcp, udp

parser = argparse.ArgumentParser()
parser.add_argument("--binary", required=True)
parser.add_argument("--runner", default="")
args = parser.parse_args()
command = shlex.split(args.runner) + [str(pathlib.Path(args.binary).resolve())]
is_macos = platform.system() == "Darwin"


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pktide-test-")
        self.root = pathlib.Path(self.tmp.name)
        self.input = self.root / "input.pcap"
        self.input.write_bytes(pcap(sample_packets()))

    def tearDown(self):
        self.tmp.cleanup()

    def run_tool(self, *options, data=None, code=0):
        p = subprocess.run(command + list(map(str, options)), input=data,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(p.returncode, code, p.stderr.decode(errors="replace"))
        return p

    def test_help_version_interfaces(self):
        self.assertIn(b"Usage:", self.run_tool("--help").stdout)
        self.assertIn(b"system libSystem only" if is_macos else b"static, no libc", self.run_tool("--version").stdout)
        self.assertIn(b"lo0\n" if is_macos else b"lo\n", self.run_tool("-D").stdout)

    def test_protocols_and_filters(self):
        expected = {"": 11, "tcp": 5, "udp": 2, "icmp": 1, "icmp6": 1, "arp": 1,
                    "ip": 5, "ip6": 4, "vlan": 1, "tcp port 443": 3,
                    "src port 12345 and dst port 53": 2,
                    "host 192.0.2.10": 6, "src host 2001:db8::1": 4,
                    "dst host 2001:db8::2": 4, "dst host 192.0.2.10": 0,
                    "tcp and (port 80 or port 443)": 4,
                    "not (tcp or udp)": 4, "udp or arp and ip": 2}
        for expr, count in expected.items():
            with self.subTest(expression=expr):
                p = self.run_tool("-r", self.input, expr)
                self.assertEqual(len(p.stdout.splitlines()), count)
                self.assertIn(f"matched={count} ".encode(), p.stderr)

    def test_counter_limit_and_hex(self):
        p = self.run_tool("-r", self.input, "-c1", "-X", "tcp")
        self.assertIn(b"matched=1 ", p.stderr)
        self.assertIn(b"0000  ", p.stdout)
        self.assertIn(b"192.0.2.10:12345 > 198.51.100.20:443 TCP [S]", p.stdout)

    def test_pcap_endian_and_nanosecond(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    data = pcap([sample_packets()[0]], endian=endian, nano=nano)
                    p = self.run_tool("-r", "-", data=data)
                    self.assertTrue(p.stdout.startswith(b"1700000000.123456 IP "))

    def test_link_types_and_large_declared_snaplen(self):
        for link, frame in [(101, ipv4(tcp())), (113, sll(ipv4(tcp()))),
                            (101, ipv6(tcp()))]:
            with self.subTest(link=link):
                p = self.run_tool("-r", "-", "tcp", data=pcap([frame], link=link, snap=262144))
                self.assertIn(b"TCP", p.stdout)

    def test_bsd_loopback_link_types(self):
        for link in (0, 108):
            for endian in ("<", ">") if link == 0 else (">",):
                for family, payload in [(2, ipv4(tcp())), (24, ipv6(tcp())),
                                        (28, ipv6(tcp())), (30, ipv6(tcp()))]:
                    with self.subTest(link=link, endian=endian, family=family):
                        frame = struct.pack(endian + "I", family) + payload
                        data = pcap([frame], link=link)
                        p = self.run_tool("-r", "-", "tcp port 443", data=data)
                        self.assertIn(b"TCP", p.stdout)
                        self.assertIn(b"IP6" if family != 2 else b"IP ", p.stdout)
        self.run_tool("-r", "-", data=pcap([b"\x02"], link=0))

    @unittest.skipUnless(is_macos, "macOS-specific interface handling")
    def test_macos_any_is_explicitly_rejected(self):
        p = self.run_tool("-i", "any", "-c", "1", code=1)
        self.assertIn(b"macOS requires one interface", p.stderr)

    def test_write_read_and_snaplen(self):
        output = self.root / "output.pcap"
        p = self.run_tool("-r", self.input, "-w", output, "-q", "tcp port 443")
        self.assertEqual(p.stdout, b"")
        p = self.run_tool("-r", output)
        self.assertEqual(len(p.stdout.splitlines()), 3)
        output2 = self.root / "short.pcap"
        self.run_tool("-r", self.input, "-w", output2, "-s", "24", "-c", "1")
        data = output2.read_bytes()
        self.assertEqual(struct.unpack_from("<I", data, 16)[0], 24)
        self.assertEqual(struct.unpack_from("<II", data, 32), (24, 54))
        self.assertIn(b"truncated", self.run_tool("-r", output2).stdout)
        if shutil.which("tcpdump"):
            checked = subprocess.run(["tcpdump", "-nn", "-r", str(output)], capture_output=True, timeout=10)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(len(checked.stdout.splitlines()), 3)

    def test_stdout_binary_is_clean(self):
        p = self.run_tool("-r", self.input, "-w", "-", "-c", "1")
        self.assertEqual(p.stdout, pcap([sample_packets()[0]]))
        self.assertIn(b" TCP ", p.stderr)

    def test_no_clobber_or_symlink(self):
        before = self.input.read_bytes()
        self.run_tool("-r", self.input, "-w", self.input, code=1)
        self.assertEqual(self.input.read_bytes(), before)
        link = self.root / "alias.pcap"
        link.symlink_to(self.input)
        self.run_tool("-r", self.input, "-w", link, code=1)
        self.assertEqual(self.input.read_bytes(), before)

    def test_invalid_arguments(self):
        for argv in [("-c", "0"), ("-s", "65536"), ("-B", "-1"), ("-i",),
                     ("--unknown",), ("-c", "4294967296"), ("-r", "")]:
            with self.subTest(argv=argv):
                self.run_tool(*argv, code=2)
        for expr in ["port 65536", "host invalid", "tcp and", "src tcp", "(udp", "udp)",
                     "host 1:2:3:4:5:6:7:8::", "host 1:::2", "host 1.2.3.999",
                     "(" * 40 + "tcp" + ")" * 40, " or ".join(["tcp"] * 129), "x" * 100]:
            with self.subTest(filter=expr):
                self.run_tool("-r", self.input, expr, code=2)

    def test_invalid_pcaps(self):
        good = pcap([sample_packets()[0]])
        invalid = [b"", b"x" * 24, good[:23], good[:-1], good[:30],
                   pcap([], link=276), pcap([], snap=0)]
        for offset, value in [(16, 0), (32, 65536), (36, 1), (28, 1000000)]:
            b = bytearray(good)
            struct.pack_into("<I", b, offset, value)
            invalid.append(bytes(b))
        for data in invalid:
            with self.subTest(data=data[:40]):
                self.run_tool("-r", "-", data=data, code=1)

    def test_truncation_fragments_and_bad_lengths(self):
        full = sample_packets()[0]
        for size in range(len(full)):
            self.run_tool("-r", "-", data=pcap([(full[:size], len(full))]))
        # IPv4/IPv6 noninitial fragments must never expose payload as ports.
        frag6 = bytes([6, 0, 0, 8]) + b"\0" * 4 + tcp()
        for packet in [ether(ipv4(tcp(), frag=1)), ether(ipv6(frag6, 44), 0x86DD)]:
            p = self.run_tool("-r", "-", "port 443", data=pcap([packet]))
            self.assertEqual(p.stdout, b"")
        bad = bytearray(full)
        bad[46] = 0x10  # TCP data offset < 20 bytes
        self.assertIn(b"malformed", self.run_tool("-r", "-", data=pcap([bad])).stdout)

    def test_ipv6_address_forms(self):
        for host in ["::", "::1", "2001:db8::1", "::ffff:192.0.2.10", "1:2:3:4:5:6:7:8"]:
            self.run_tool("-r", self.input, "host " + host)


unittest.main(argv=[__file__], verbosity=2)
