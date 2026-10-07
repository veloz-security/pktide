# Validation record

Validation date: October 7, 2026. Release: pktide 0.1.0. Linux build: GCC 12.5.0 in a Debian bookworm Linux/amd64 container. macOS build: Apple Clang on macOS 26.2, targeting macOS 11.0.

## Results

| Environment | Executable | Checks | Result |
|---|---|---|---|
| CentOS 3.1, actual `2.4.21-15.0.2.EL.c0` x86_64 kernel, QEMU system TCG | x86_64 | PCAP filters, Ethernet/SLL live capture, save/replay, socket statistics, SIGINT/SIGTERM | Passed |
| CentOS 3.1, actual `2.4.21-9.0.1.EL.c0` i686 kernel, QEMU system TCG | i386 | Same as above | Passed |
| CentOS 4.0, actual `2.6.9-5.0.3.EL` x86_64 kernel, QEMU system TCG | x86_64 | PCAP filters, Ethernet/SLL live capture, save/replay, socket statistics, SIGINT/SIGTERM | Passed |
| CentOS 4.0, actual `2.6.9-5.0.3.EL` i686 kernel, QEMU system TCG | i386 | Same as above | Passed |
| Linux `7.0.14-orbstack-00380-ga7e0a2dc9535`, amd64 execution translation on an arm64 host | x86_64 | 13 CLI groups passed, 1 macOS-only group skipped; 4 live groups | Passed |
| Same modern Linux kernel, arm64-native QEMU user mode | i386 | 13 CLI groups passed, 1 macOS-only group skipped; 4 live groups | Passed |
| macOS arm64 Clang, ASan + UBSan | Shared C parser | 100,000 generated packet inputs, 10,000 filter inputs, integer/IP conversion | Passed |
| ELF structure inspection | Both Linux executables | Static ELF, architecture, no interpreter/dynamic segments, NX stack | Passed |
| macOS system tcpdump | Saved PCAP | Read a pktide-written file | Passed |
| macOS 26.2, native Apple Silicon | Universal arm64 slice | 14 CLI groups, PCAP replay/filters, interface listing | Passed |
| Same Mac, Rosetta 2 | Universal x86_64 slice | 14 CLI groups | Passed |
| macOS ASan + UBSan | BPF record handling | Batches, padding, lengths, stopping, truncated records, RAW mapping | Passed |
| Mach-O and codesign inspection | Universal executable | arm64+x86_64, PIE, macOS 11 target, libSystem only, ad-hoc signature | Passed |
| macOS `/dev/bpf*` | Actual live capture | Requires root or device read access | **Unverified: access unavailable** |

CLI groups cover protocol/address/port/boolean filters, fragments, every truncation length in the fixtures, PCAP byte order/time units/link types, invalid lengths/formats/options, output file protection, and binary stdout. Live groups use only test-generated UDP on IPv4/IPv6 loopback within the test container and also check rejection of unprivileged capture. Actual 2.4.21/2.6.9 VM live tests use IPv4 loopback; IPv6 coverage in those VMs is limited to PCAP parsing.

The pktide 0.1.0 release executables were used for Linux 2.4.21, 2.6.9, and modern-kernel validation. The shared Linux/macOS decoder reads BSD NULL/LOOP formats; tests cover both byte orders and BSD IPv6 family values.

## macOS build and validation

```sh
make macos
make test
python3 tests/test_cli.py --binary dist/pktide-macos --runner 'arch -x86_64'
make sanitize
```

`dist/pktide-macos` is one arm64/x86_64 Universal Mach-O file. `otool -L` reported only `/usr/lib/libSystem.B.dylib`, and `codesign --verify --strict --all-architectures` passed. The signature is ad-hoc, not Apple Developer ID signing or notarization. macOS 11 is a build target, not evidence of testing on each macOS version from 11 through 25.

On macOS 26.2, checks covered `-D`, PCAP handling, filters, BSD loopback decoding, and reading saved PCAP with the system tcpdump. All 14 CLI groups passed on native arm64 and Rosetta x86_64. See the [native Mac record](validation/macos-native.txt) and [Rosetta record](validation/macos-rosetta.txt).

`/dev/bpf*` was root-only (0600), and `sudo -n` required authentication. The expected permission error from `-i lo0 -c 1` was verified. Actual BPF device capture, live BPF statistics, and signals during capture remain **unverified** on this Mac. Device permissions were not changed. Synthetic BPF batch parser tests do not replace device testing.

From a local terminal with capture privileges, run:

```sh
sudo python3 tests/test_live.py --binary dist/pktide-macos
```

This tests generated IPv4/IPv6 UDP on `lo0`, PCAP save/replay, and SIGINT/SIGTERM cleanup. macOS does not support `-i any` and reports an explicit error for it.

## Coverage limits and emulation

Modern-kernel testing involved CPU execution translation. Legacy testing used **system VMs booting actual Linux 2.4.21/2.6.9 kernels**, not QEMU user mode. These results do not certify every RHEL release or physical NIC. SELinux enforcing policies on RHEL, physical NIC/offload behavior, high-speed loads, and i386 timestamps beyond the 2038 boundary are outside the passed scope.

The difference between 32-bit `rt_sigaction` and legacy `sigreturn` frames was found and corrected during VM testing. On i386, the return path must pop the signal number after the handler returns, then invoke syscall 119. SIGINT/SIGTERM tests cover this regression.

A nested setup translating **amd64 QEMU itself on Apple Silicon** failed signal tests with QEMU's internal `rcu_read_unlock` assertion. Tests passed when separated into arm64-native QEMU and actual i686 kernel VMs. Where QEMU user mode does not implement `SOL_PACKET/PACKET_STATISTICS`, socket statistics fields are omitted. Statistics queries passed in the actual legacy-kernel VMs.

## Reproducing the general tests

Python runs test orchestration and executable checks on the development host or in containers. It is not a pktide runtime dependency. C parser tests run under ASan/UBSan; legacy VMs run a C init program. The Python scripts use only the standard library. The VM runner requires Python 3.9 or later; its external tools are installed by `tests/vm.Dockerfile`.

```sh
docker build --platform linux/amd64 -t pktide-builder:local .
docker run --rm --platform linux/amd64 --network none \
  -v "$PWD:/work" -w /work pktide-builder:local \
  sh -c 'make both && make test && make test-live'

# AddressSanitizer/UndefinedBehaviorSanitizer with the host compiler
make sanitize
```

Add `--cap-add NET_RAW` if the Docker configuration removes that capability by default. Test execution needs no external network access. Building the container image requires package downloads.

## Reproducing Linux 2.4.21 / 2.6.9 VM tests

Run these commands from the project root. Build the VM runner image for the **host's native architecture**.

```sh
docker run --rm --platform linux/amd64 --network none \
  -v "$PWD:/work" -w /work pktide-builder:local \
  sh -c 'make both && make vm-init && make ARCH=i386 vm-init'

docker build -f tests/vm.Dockerfile -t pktide-vm:local .

# Linux 2.4.21 / RHEL 3 era
docker run --rm -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/run_vm.py --profile centos3 --arch x86_64
docker run --rm -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/run_vm.py --profile centos3 --arch i386

# Linux 2.6.9 / RHEL 4 era (default profile)
docker run --rm -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/run_vm.py --arch x86_64
docker run --rm -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/run_vm.py --arch i386
```

The first run downloads public kernel RPMs from the CentOS vault and verifies SHA-256. Once `build/vm/` is populated, add `--network none` to subsequent runs. No network device, host disk, or shared folder is attached to the guest. Each VM boots a ramdisk containing the test `/init`, pktide, and synthetic PCAP data. The machine model `pc-i440fx-2.0` with 128 MiB is used for old-kernel BIOS memory-map compatibility.

Linux 2.4 uses an 8 MiB ext2 initrd with optional filesystem features disabled; Linux 2.6 uses a cpio initramfs. The 2.4 test profile requires `CONFIG_PACKET=y` and `CONFIG_EXT2_FS=y` because its minimal root has no 2.4 module loader. This does not exclude deployment systems that provide AF_PACKET as a module.

The 2.4.21 x86_64 kernel uses boot protocol 2.02. QEMU 7.2's [linuxboot implementation](https://github.com/qemu/qemu/blob/v7.2.22/pc-bios/optionrom/linuxboot.S) writes offset `0x22c` even for protocols below 2.03, overwriting setup instructions in this kernel. For that protocol, the runner uses a read-only boot ISO made with ISOLINUX. **Neither the kernel nor the pktide executable is modified.** ISO and ext2 generation are test-environment requirements only.

| RPM | SHA-256 |
|---|---|
| `kernel-2.4.21-15.0.2.EL.c0.x86_64.rpm` | `485914b519f3c63acb0d3ad9fcc76c0c001679d2c78bad21bc720c0a96cd67f9` |
| `kernel-2.4.21-9.0.1.EL.c0.i686.rpm` | `4a8432e9341d8401d05764de67391b5277b501acb1172167ed1588c0d6ec2f67` |
| `kernel-2.6.9-5.0.3.EL.x86_64.rpm` | `562d5b76b89873f7afd33469b680b1b312bca11018970c6803f5fa886923f387` |
| `kernel-2.6.9-5.0.3.EL.i686.rpm` | `1a1a86be59d4c7f5d5690a04209eadb0aceb6497a227d8f0572ace2221f3982c` |

Sources: [CentOS 3.1 x86_64](https://vault.centos.org/3.1/os/x86_64/RedHat/RPMS/), [CentOS 3.1 i386](https://vault.centos.org/3.1/os/i386/RedHat/RPMS/), [CentOS 4.0 x86_64](https://vault.centos.org/4.0/os/x86_64/CentOS/RPMS/), and [CentOS 4.0 i386](https://vault.centos.org/4.0/os/i386/CentOS/RPMS/). These digests pin the downloaded files for reproducibility; they do not represent independent RPM GPG verification.

Full boot logs are written to `build/vm/centos3/{x86_64,i386}/console.log` for 2.4 and `build/vm/{x86_64,i386}/console.log` for 2.6. Committed summaries include executable hashes: [2.4 x86_64](validation/centos3-x86_64.txt), [2.4 i386](validation/centos3-i386.txt), [2.6 x86_64](validation/legacy-x86_64.txt), and [2.6 i386](validation/legacy-i386.txt). The runner requires the expected kernel version and architecture, `PKTIDE_VM_SUCCESS`, and matching packet counts/kernel statistics from both live captures before reporting success.

## Reproducing modern-kernel i386 tests

Use QEMU user mode from the native-architecture VM runner image built above. This is separate from tests that boot a guest kernel.

```sh
docker run --rm --network none --cap-add NET_RAW \
  -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/test_cli.py --binary dist/pktide-i386 --runner qemu-i386
docker run --rm --network none --cap-add NET_RAW \
  -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/test_live.py --binary dist/pktide-i386 --runner qemu-i386
```

## Deployment scope

The results support running the same static Linux executables on the tested RHEL 3-era 2.4.21, RHEL 4-era 2.6.9, and modern-kernel environments. Kernels older than 2.4.21 are unsupported. Before production use, check `--version`, `-D`, a short `-c` capture, and tcpdump replay on the actual target CPU, kernel, and interface. This is not blanket compatibility certification for all RHEL versions.
