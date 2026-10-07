#!/usr/bin/env python3
"""Verify a macOS universal executable has no third-party runtime dependency."""
import pathlib
import re
import subprocess
import sys

path = pathlib.Path(sys.argv[1])
architectures = subprocess.check_output(["lipo", "-archs", str(path)], text=True).split()
assert set(architectures) == {"arm64", "x86_64"}, architectures
for arch in architectures:
    output = subprocess.check_output(["otool", "-arch", arch, "-L", str(path)], text=True)
    libraries = re.findall(r"^\s+(\S+) \(compatibility version", output, flags=re.MULTILINE)
    assert libraries == ["/usr/lib/libSystem.B.dylib"], (arch, libraries)
    headers = subprocess.check_output(["otool", "-arch", arch, "-hv", str(path)], text=True)
    assert "EXECUTE" in headers and "PIE" in headers, headers
    load_commands = subprocess.check_output(["otool", "-arch", arch, "-l", str(path)], text=True)
    assert re.search(r"\bminos 11\.0\b", load_commands), "expected macOS 11.0 deployment target"
subprocess.run(["codesign", "--verify", "--strict", "--all-architectures", str(path)], check=True)
print(f"PASS {path}: {path.stat().st_size:,} bytes, arm64 + x86_64, PIE, ad-hoc signed, system libSystem only")
