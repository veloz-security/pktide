#!/usr/bin/env python3
"""Capture test-generated traffic on a Linux or macOS loopback interface."""
import argparse
import os
import pathlib
import platform
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("--binary", required=True)
parser.add_argument("--runner", default="")
args = parser.parse_args()
command = shlex.split(args.runner) + [str(pathlib.Path(args.binary).resolve())]
is_macos = platform.system() == "Darwin"
loopback = "lo0" if is_macos else "lo"


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pktide-live-")
        self.root = pathlib.Path(self.tmp.name)
        self.children = []

    def tearDown(self):
        for p in self.children:
            if p.poll() is None:
                p.kill()
            p.communicate(timeout=5)
        self.tmp.cleanup()

    def start(self, *options):
        p = subprocess.Popen(command + list(map(str, options)), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(p)
        deadline = time.monotonic() + 10
        ready = b""
        while time.monotonic() < deadline:
            if select.select([p.stderr], [], [], 0.1)[0]:
                chunk = os.read(p.stderr.fileno(), 4096)
                ready += chunk
                if b"Ctrl-C to stop\n" in ready:
                    return p
                if not chunk:
                    break
        self.fail(f"capture did not start: {ready!r}")

    def test_loopback_capture_and_replay(self):
        for interface, link in ([("lo0", 0)] if is_macos else [("lo", 1), ("any", 113)]):
            with self.subTest(interface=interface), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                receiver.bind(("127.0.0.1", 0))
                receiver.settimeout(5)
                port = receiver.getsockname()[1]
                path = self.root / f"{interface}.pcap"
                p = self.start("-i", interface, "-c", "1", "-w", path, "udp dst port " + str(port))
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.sendto(b"pktide local capture test", ("127.0.0.1", port))
                receiver.recv(1024)
                out, err = p.communicate(timeout=10)
                self.assertEqual(p.returncode, 0, err)
                self.assertIn(b"UDP", out)
                self.assertIn(b"matched=1 ", err)
                # QEMU user-mode may not translate SOL_PACKET getsockopt.
                if not args.runner or b"socket_drops=" in err:
                    self.assertIn(b"bpf_drops=0" if is_macos else b"socket_drops=0", err)
                data = path.read_bytes()
                self.assertEqual(struct.unpack_from("<I", data, 20)[0], link)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                replay = subprocess.run(command + ["-r", str(path), "udp"], capture_output=True, timeout=10)
                self.assertEqual(replay.returncode, 0, replay.stderr)
                self.assertEqual(len(replay.stdout.splitlines()), 1)

    def test_sigint_and_sigterm_cleanup(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig):
                path = self.root / f"signal-{sig}.pcap"
                p = self.start("-i", loopback, "-w", path, "-q", "tcp port 9")
                p.send_signal(sig)
                _, err = p.communicate(timeout=10)
                self.assertEqual(p.returncode, 0, err)
                self.assertIn(b"matched=0 ", err)
                self.assertEqual(len(path.read_bytes()), 24)

    def test_ipv6_loopback(self):
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as receiver:
            try:
                receiver.bind(("::1", 0))
            except OSError as exc:
                self.skipTest(f"IPv6 loopback unavailable: {exc}")
            receiver.settimeout(5)
            port = receiver.getsockname()[1]
            p = self.start("-i", loopback, "-c", "1", "ip6 and udp dst port " + str(port))
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sender:
                sender.sendto(b"pktide IPv6 test", ("::1", port))
            receiver.recv(1024)
            out, err = p.communicate(timeout=10)
            self.assertEqual(p.returncode, 0, err)
            self.assertIn(b"IP6", out)

    @unittest.skipUnless(os.getuid() == 0, "requires root to exercise an unprivileged uid")
    def test_no_privilege(self):
        def drop_uid():
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
        # A private home directory must not turn this into an exec permission test.
        with tempfile.TemporaryDirectory(prefix="pktide-unpriv-", dir="/tmp") as directory:
            os.chmod(directory, 0o755)
            binary = pathlib.Path(directory) / "pktide"
            shutil.copyfile(command[-1], binary)
            binary.chmod(0o755)
            p = subprocess.run(command[:-1] + [str(binary), "-i", loopback, "-c", "1"],
                               preexec_fn=drop_uid, capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 1)
        self.assertIn(b"root or read access to /dev/bpf" if is_macos else b"root or CAP_NET_RAW", p.stderr)


unittest.main(argv=[__file__], verbosity=2)
