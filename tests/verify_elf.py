#!/usr/bin/env python3
"""Verify deployable ELF properties without depending on host binutils."""
import pathlib
import struct
import sys

path, arch = pathlib.Path(sys.argv[1]), sys.argv[2]
b = path.read_bytes()
assert b[:4] == b"\x7fELF" and b[5] == 1, "must be little-endian ELF"
bits = b[4]
assert bits == (2 if arch == "x86_64" else 1), "wrong ELF class"
kind, machine = struct.unpack_from("<HH", b, 16)
assert kind == 2 and machine == (62 if arch == "x86_64" else 3), "wrong ELF type/machine"
if bits == 2:
    phoff = struct.unpack_from("<Q", b, 32)[0]
    stride, count = struct.unpack_from("<HH", b, 54)
else:
    phoff = struct.unpack_from("<I", b, 28)[0]
    stride, count = struct.unpack_from("<HH", b, 42)
stack_seen = False
for i in range(count):
    off = phoff + i * stride
    ptype = struct.unpack_from("<I", b, off)[0]
    flags = struct.unpack_from("<I", b, off + (4 if bits == 2 else 24))[0]
    assert ptype not in (2, 3), "PT_DYNAMIC/PT_INTERP dependency detected"
    if ptype == 1:
        assert flags & 3 != 3, "writable executable load segment"
    if ptype == 0x6474E551:
        stack_seen = True
        assert not flags & 1, "executable stack"
assert stack_seen, "missing GNU_STACK declaration"
assert b"GLIBC_" not in b, "glibc version dependency"
print(f"PASS {path}: {len(b):,} bytes, static {arch}, no interpreter/libc, NX stack")
