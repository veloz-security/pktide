# pktide

A lightweight C packet monitor for legacy and modern Linux and macOS. Capture live traffic, filter and summarize packets, and read or write classic PCAP files.

**One static executable per Linux CPU architecture. One Universal executable for Apple Silicon and Intel Macs.** Linux builds use system calls directly, with no glibc, musl, libpcap, libgcc, or dynamic loader. macOS builds use only the system-provided `libSystem` and capture through `/dev/bpf`. Neither requires additional runtime libraries.

```sh
# Run on a 64-bit Linux server
chmod +x pktide-x86_64
sudo ./pktide-x86_64 -i eth0 'tcp port 443'

# Save 100 matching packets to a new PCAP file
sudo ./pktide-x86_64 -i eth0 -c 100 -w capture.pcap 'tcp or udp'

# Listen on all interfaces for UDP port 53
sudo ./pktide-x86_64 -i any 'udp port 53'

# Read saved packets without root privileges
./pktide-x86_64 -r capture.pcap 'src host 192.0.2.10'
./pktide-x86_64 -r capture.pcap -X -c 5
```

Replace `eth0` with an interface listed by `-D`. Use `pktide-i386` on 32-bit Linux. Windows is not supported.

## Downloads

Choose the executable for your OS and CPU from [GitHub Releases](https://github.com/devwooops/pktide/releases):

| File | Target |
|---|---|
| `pktide-x86_64` | Linux x86_64 |
| `pktide-i386` | Linux i386 ABI on i486 or newer |
| `pktide-macos` | macOS, Apple Silicon and Intel |

Use the release's `SHA256SUMS` to verify file integrity. Grant execute permission with `chmod +x <filename>` after downloading.

**Running pktide does not require Python, Docker, a compiler, or libpcap.** Python and Docker are development and validation tools only; see [Development and testing](#development-and-testing).

## Running on macOS

```sh
# Build locally with Xcode Command Line Tools installed
make macos

# A single executable containing arm64 and x86_64 code
./dist/pktide-macos --version
./dist/pktide-macos -D
sudo ./dist/pktide-macos -i en0 -c 100 -w capture.pcap 'tcp port 443'

# Capture localhost traffic
sudo ./dist/pktide-macos -i lo0 'tcp or udp'

# Read a file without sudo
./dist/pktide-macos -r capture.pcap -X -c 5
```

The build targets macOS 11 or later. Execution has been tested on macOS 26.2 with native arm64 and Rosetta x86_64. Running `make` on a Mac selects this build. The executable uses the system `libSystem`; it is not fully static like the Linux builds.

macOS capture requires a single interface. The default is `en0`; `-i any` is not supported. Use `-D` to list interfaces. Capture requires root or read access to `/dev/bpf*`. **Actual live BPF capture remains unverified** because the test Mac lacks this access without sudo authentication. PCAP handling, filters, BPF record parsing, and permission errors have been tested. See [macOS validation](docs/VALIDATION.md#macos-build-and-validation).

## Features

- Read Ethernet, Linux cooked capture v1 (SLL), RAW IP, and BSD NULL/LOOP PCAP files.
- Summarize IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, ARP, and VLAN/QinQ.
- Check bounds when parsing IPv4 options, IPv6 extension headers, and IP fragments.
- Filter numeric IP addresses and ports with `and`, `or`, `not`, parentheses, and implicit `and`.
- Capture live traffic, read/write PCAP, limit packet counts and snaplen, and display hex/ASCII dumps.
- Read little- and big-endian PCAP with microsecond or nanosecond timestamps; write microsecond PCAP.
- Handle Ctrl-C/SIGTERM and report packet/byte counts and Linux socket or macOS BPF drop statistics.
- Perform no name resolution, avoiding DNS traffic and NSS library dependencies.
- Process packets in fixed-size buffers, with no background service.

Example output:

```text
1700000000.123456 IP 192.0.2.10:12345 > 198.51.100.20:443 TCP [S] length=54
pktide: seen=11 matched=3 matched_bytes=210
```

Timestamps use Unix epoch seconds and microseconds. TCP flags are `F S R P A U E C`. Checksums are not validated, and streams are not reassembled.

## Compatibility

| Executable | CPU / ABI | Minimum target |
|---|---|---|
| `dist/pktide-x86_64` | Baseline x86-64 / Linux LP64 | Linux 2.4.21, RHEL 3 era |
| `dist/pktide-i386` | i486 or newer / Linux i386 | Linux 2.4.21, RHEL 3 era |
| `dist/pktide-macos` | Universal Mach-O / arm64 + x86_64 | macOS 11.0 |

For a given Linux architecture, the same executable is used across distributions. Running the 32-bit executable on a 64-bit kernel requires IA32 compatibility support. Linux ARM, MIPS, POWER, s390, and IA-64 are outside the current scope. macOS uses a separate Mach-O executable.

The Linux minimum is based on capture, save/replay, and signal tests on actual CentOS 3.1 Linux 2.4.21 kernels for both architectures. Linux 2.4.0–2.4.20, 2.2, and 2.0 are untested and unsupported. Not every intermediate kernel release has been tested.

Linux requires `AF_PACKET`; live capture requires root or `CAP_NET_RAW`. Container seccomp and capability policies must also allow the required system calls. Use root on legacy systems. ABI design alone cannot guarantee every combination of RHEL release, device, and policy. See the [validation record](docs/VALIDATION.md) for tested environments and reproduction steps.

## Building

With a modern Linux x86 GCC/binutils toolchain:

```sh
make both
make verify
make ARCH=i386 verify
```

The Linux build needs no system development headers, libc, or 32-bit libc development packages. The compiler must support x86 `-m32` code generation and ELF i386 linking. Build on a development machine and copy the executable to the target; the old GCC versions shipped with RHEL 3/4 have not been tested as build toolchains. The `verify` targets require Python 3 on the development machine.

To build **Linux executables** from macOS or an ARM host with Docker:

```sh
docker build --platform linux/amd64 -t pktide-builder:local .
docker run --rm --platform linux/amd64 --network none \
  -v "$PWD:/work" -w /work pktide-builder:local make both
```

Copy only `dist/pktide-x86_64` or `dist/pktide-i386` to the target server.

## Options and filters

| Option | Meaning |
|---|---|
| `-i IFACE` | Capture interface; default: `any` on Linux, `en0` on macOS |
| `-D` | List interfaces |
| `-r FILE` | Read PCAP; `-` reads stdin |
| `-w FILE` | Write PCAP to a new file with mode 0600; `-` writes stdout |
| `-c N` | Stop after N matching packets |
| `-s N` | Output/save snaplen, 1–65535; default: 65535 |
| `-B KiB` | Requested kernel receive buffer; default: 2048 KiB, subject to kernel limits |
| `-p` | Disable promiscuous mode on the selected interface |
| `-q` | Suppress per-packet text |
| `-X` | Display captured bytes as hex and ASCII |
| `-n`, `-nn` | Compatibility options; name resolution is always disabled |

Place options before the filter expression and pass each option separately. Attached values such as `-c10` and `-ieth0` are supported. With `-w -`, packet text goes to stderr so stdout contains only PCAP. Statistics always go to stderr. Existing output files and symbolic links are never overwritten; reading and writing the same file is not allowed.

```sh
pktide-x86_64 -i eth0 '(tcp port 80 or tcp port 443) and not host 192.0.2.5'
pktide-x86_64 -i any 'ip6 and dst host 2001:db8::2'
pktide-x86_64 -r trace.pcap 'vlan and udp'
pktide-x86_64 -r trace.pcap -w - -q 'tcp' > filtered.pcap
```

Supported primitives: `tcp`, `udp`, `icmp`, `icmp6`, `arp`, `ip`, `ip6`, `vlan`, `[src|dst] port N`, and `[src|dst] host NUMERIC_IP`. Precedence is `not > and > or`. The tokens `&&`, `||`, and `!` are also accepted. Filters are limited to 4095 bytes, 128 nodes, and 32 levels of explicit nesting. IPv6 addresses may use compressed or IPv4-mapped notation.

Filters run in user space on received bytes before `-s` truncation; text and PCAP output honor the snaplen. Headers already truncated in an input file cannot be recovered. Non-initial IP fragments do not match `port`. The `host` primitive also matches parseable IPv4 ARP addresses; `ip` does not match ARP.

## Limitations

- pktide does not implement all tcpdump features or filter syntax. Kernel BPF/eBPF **filter compilation**, DNS name filters, `net`, port ranges, detailed application-protocol analysis, file rotation, and remote forwarding are not implemented. macOS BPF device capture is separate from kernel filter compilation.
- Lossless capture on high-speed links is not guaranteed. Filtering runs in user space and output is synchronous. Use `-q -w FILE` and check Linux `socket_drops` or macOS `bpf_drops`. These counters may not include hardware or driver losses.
- Linux `any` uses SLL v1 without requesting promiscuous mode. Named Linux interfaces support Ethernet/loopback only; outgoing loopback duplicates are excluded. macOS supports Ethernet/NULL/LOOP/RAW on a single interface, without `any`.
- VLAN tags removed by NIC offload and FCS are not reconstructed. GRO/GSO/TSO may change observed packet lengths or boundaries relative to wire frames. VLAN filters require tags to be present in the received bytes.
- Capture/input records are limited to 65535 bytes. IPv6 jumbograms, PCAPNG, SLL2, wireless radiotap, encrypted payload decoding, and IP/TCP reassembly are unsupported. Parsing is limited to 8 VLAN tags and 16 IPv6 extension headers.
- The legacy i386 time ABI and the 32-bit seconds field in macOS BPF headers do not support live timestamps beyond the 2038 boundary. Linux x86_64 timestamps are also constrained by the classic PCAP seconds field. Nanosecond input timestamps are truncated to microseconds.
- `seen` counts packets processed in user space. `matched` and `matched_bytes` count filter matches and their original lengths. Kernel statistics may include loopback duplicates and queued packets. Socket statistics fields are omitted when unsupported.

## Development and testing

The production code is C, with a small assembly entry point and syscall wrappers on Linux. Tests use C and Python for different purposes:

| Test layer | Language | Purpose |
|---|---|---|
| Parser and BPF record checks | C | Exercise in-process code under AddressSanitizer and UndefinedBehaviorSanitizer |
| CLI and live capture tests | Python 3, standard library | Generate PCAP fixtures, run executables, send local test traffic, and compare outputs |
| ELF/Mach-O checks | Python 3, standard library | Verify executable format and runtime dependencies; macOS checks invoke system tools |
| Legacy kernel validation | Python host runner and C guest init | Boot QEMU VMs and exercise the release executable inside an actual old kernel |

Python is used on the development host or in the test container. It is neither linked into pktide nor required on deployment targets or in the legacy test guests. There are no third-party Python package dependencies. Building pktide itself does not run the Python test suite. The VM runner requires Python 3.9 or later, QEMU, and the tools listed in `tests/vm.Dockerfile`.

```sh
make test                    # Binary checks, PCAP, filters, and error handling
make test-live               # Locally generated loopback traffic; capture privileges required
make PLATFORM=linux ARCH=i386 RUNNER=qemu-i386 test
make sanitize               # ASan + UBSan with the host C compiler
```

See the [validation record](docs/VALIDATION.md) for real 32-bit kernel testing and user-mode emulation limits. ABI decisions are documented in the [compatibility design](docs/COMPATIBILITY.md).

## License

[MIT License](LICENSE).
