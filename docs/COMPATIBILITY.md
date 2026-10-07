# Compatibility design

pktide ships separate Linux static ELF and macOS Universal Mach-O executables. The C decoder, filter, and PCAP code is shared; capture and runtime I/O are implemented per platform.

## Baseline

The minimum Linux target is **2.4.21, from the RHEL 3 era**. [Red Hat's release/kernel table](https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates) lists RHEL 3 GA with a 2.4.21 kernel. Tests use CentOS 3.1 kernels `2.4.21-15.0.2.EL.c0` on x86_64 and `2.4.21-9.0.1.EL.c0` on i686.

The existing legacy syscall set works on both kernels without a separate 2.4 runtime path. `PT_LINUX_MIN` records the tested lower bound; execution is not blocked based solely on the kernel version string. Linux 2.4.0–2.4.20, 2.2, and 2.0 remain untested and unsupported. RHEL 4 is distinct from the 1990s Red Hat Linux 4.x releases.

Statically linking a modern libc does not by itself ensure old-kernel compatibility. pktide instead uses the required Linux ABI directly without linking libc. The kernel's [userspace ABI documentation](https://www.kernel.org/doc/html/latest/admin-guide/abi.html) describes syscalls as long-lived interfaces. This informs the design, but does not guarantee compatibility across all policies, architectures, or kernel configurations.

## Runtime system calls

| Function | x86_64 | i386 |
|---|---|---|
| File I/O | `read`, `write`, `open`, `close` | Same |
| Packet sockets | `socket`, `bind`, `recvfrom`, `setsockopt`, `getsockopt` | Legacy `socketcall` multiplexer |
| Receive wait | `poll` | `poll` |
| Interfaces/timestamps | `ioctl` | `ioctl` |
| Timestamp fallback | `gettimeofday` | Legacy 32-bit `gettimeofday` |
| Signal handling | `rt_sigaction`, `rt_sigreturn` | `rt_sigaction`, `sigreturn` |
| Process exit | `exit` | `exit` |

The runtime does not depend on `openat`, `getrandom`, `statx`, `recvmmsg`, `epoll`, `io_uring`, eBPF, or vDSO. Syscall numbers and data layouts are defined in `src/linux_abi.h`; calling conventions are implemented in `src/start.S`. The Linux implementation supports little-endian x86 ABIs only. Decimal formatting of 64-bit integers on 32-bit systems is implemented directly to avoid libgcc's `__udivdi3` dependency.

On i386, a handler registered through `rt_sigaction` without `SA_SIGINFO` receives a legacy signal frame. The return path pops the signal number from the stack before invoking `sigreturn(119)`. This differs from x86_64's `rt_sigreturn(15)` and is covered by SIGINT/SIGTERM tests on actual old kernels. Frame layout is described by `sys_sigreturn` and `setup_frame` in the [kernel's i386 signal implementation](https://github.com/torvalds/linux/blob/v2.6.12/arch/i386/kernel/signal.c).

`AF_PACKET` is the established interface documented in [packet(7)](https://www.man7.org/linux/man-pages/man7/packet.7.html). pktide uses `SOCK_RAW` for Ethernet and `SOCK_DGRAM` to construct SLL records for all-interface capture. A socket is created with protocol 0, then bound to start receiving on the selected interface. This avoids queuing packets from other interfaces before the bind.

Promiscuous mode uses `PACKET_ADD_MEMBERSHIP`, tying it to the socket lifetime instead of modifying global interface flags. The kernel releases membership when the socket or process closes. `SIOCGSTAMP` supplies kernel receive timestamps; on failure, `gettimeofday` is called immediately after receiving. `PACKET_STATISTICS` counters reset when read, so periodic readings are added to 64-bit totals.

## Linux build properties

- `-nostdlib -static -no-pie`: no dynamic loader or shared libraries.
- Baseline `x86-64` or `i486` instruction sets; no `-march=native`.
- `_start` reads the argc/argv supplied by the kernel.
- A non-executable GNU stack and no writable/executable load segments.
- No runtime malloc, thread-local storage, environment, or locale lookup.
- No external runtime symbols required by the syscall wrappers.

`tests/verify_elf.py` inspects ELF structure, including the absence of interpreter/dynamic segments, the machine type, and the NX stack. Structural checks do not replace execution on old kernels. See [VALIDATION.md](VALIDATION.md) for runtime results.

## Interpreting validation

An old userspace image in a modern container still uses the host kernel. That alone cannot establish old-kernel compatibility. `tests/run_vm.py` boots CentOS 3.1 Linux 2.4.21 and CentOS 4.0 Linux 2.6.9 in QEMU system VMs and runs the same release executables. The 2.4 guests use an ext2 initrd; the 2.6 guests use a cpio initramfs.

Python orchestrates these tests on the host. Guests contain a C test init program and pktide; they do not require Python or libc. Results apply to the tested vendor kernels, not every upstream/vendor patch combination or formal RHEL certification.

## macOS

`make macos` uses Apple Clang with `-arch arm64 -arch x86_64 -mmacosx-version-min=11.0` to produce a Universal executable. As described in [Apple's Universal binary documentation](https://developer.apple.com/documentation/apple-silicon/building-a-universal-macos-binary), both architecture slices are packaged in one file. macOS uses its system `libSystem` APIs rather than the Linux syscall wrappers. No additional libraries are installed, and `libpcap` is not linked. `tests/verify_macos.py` checks architectures, deployment targets, PIE, library dependencies, and signatures.

Capture uses the SDK's `<net/bpf.h>`. pktide opens `/dev/bpfN` read-only and nonblocking, then configures `BIOCSBLEN`, `BIOCSETIF`, `BIOCGDLT`, and `BIOCIMMEDIATE` in that order. Ethernet promiscuous mode is released when the BPF descriptor closes. A `poll` loop waits for data; records within each read are traversed using `BPF_WORDALIGN`. Header and captured lengths are checked before passing bytes to the shared parser.

Darwin's `DLT_RAW=12` is mapped to PCAP's `LINKTYPE_RAW=101`. Loopback `DLT_NULL=0` contains a four-byte host-endian address family; `DLT_LOOP=108` uses network byte order. BSD IPv6 family values 24, 28, and 30 are accepted. Linux can also read these macOS NULL/LOOP PCAP files.

BPF statistics are cumulative, so deltas from previous readings are added to 64-bit totals. Linux statistics instead reset when queried. The BPF read buffer is limited to 512 KiB, and individual saved packets to 65535 bytes. The signed 32-bit seconds field in legacy BPF timestamps limits live capture timestamps at the 2038 boundary.

macOS requires one interface, defaulting to `en0`. The `any` interface is explicitly rejected. Live validation coverage and permission limits are recorded in [VALIDATION.md](VALIDATION.md#macos-build-and-validation).
