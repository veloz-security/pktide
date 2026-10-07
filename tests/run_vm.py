#!/usr/bin/env python3
"""Boot a real CentOS 3.1 or 4.0 kernel; see vm.Dockerfile for dependencies.

No guest network device, host disk, or writable host share is exposed to the VM.
The only network operation is downloading the public kernel RPM before boot.
"""
import argparse
import gzip
import hashlib
import pathlib
import re
import stat
import subprocess
import tempfile

from fixtures import pcap, sample_packets

parser = argparse.ArgumentParser()
parser.add_argument("--arch", choices=["x86_64", "i386"], default="x86_64")
parser.add_argument("--profile", choices=["centos3", "centos4"], default="centos4")
parser.add_argument("--kernel-rpm", type=pathlib.Path)
parser.add_argument("--timeout", type=int, default=90)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parent.parent
work = root / "build" / "vm"
if args.profile != "centos4":
    work /= args.profile
work /= args.arch
work.mkdir(parents=True, exist_ok=True)
profiles = {
    "centos4": {
        "kernel": "2.6.9", "directory": "4.0/os/{arch}/CentOS/RPMS", "rootfs": "cpio",
        "x86_64": ("kernel-2.6.9-5.0.3.EL.x86_64.rpm", "562d5b76b89873f7afd33469b680b1b312bca11018970c6803f5fa886923f387"),
        "i386": ("kernel-2.6.9-5.0.3.EL.i686.rpm", "1a1a86be59d4c7f5d5690a04209eadb0aceb6497a227d8f0572ace2221f3982c"),
    },
    "centos3": {
        "kernel": "2.4.21", "directory": "3.1/os/{arch}/RedHat/RPMS", "rootfs": "ext2",
        "x86_64": ("kernel-2.4.21-15.0.2.EL.c0.x86_64.rpm", "485914b519f3c63acb0d3ad9fcc76c0c001679d2c78bad21bc720c0a96cd67f9"),
        "i386": ("kernel-2.4.21-9.0.1.EL.c0.i686.rpm", "4a8432e9341d8401d05764de67391b5277b501acb1172167ed1588c0d6ec2f67"),
    },
}
profile = profiles[args.profile]
binary = root / "dist" / f"pktide-{args.arch}"
print(f"Binary SHA256: {hashlib.sha256(binary.read_bytes()).hexdigest()}", flush=True)
rpm_name, expected_hash = profile[args.arch]
rpm_path = args.kernel_rpm or work / rpm_name
if not rpm_path.exists():
    url = "https://vault.centos.org/" + profile["directory"].format(arch=args.arch) + "/" + rpm_name
    download = rpm_path.with_suffix(".rpm.part")
    subprocess.run(["curl", "-fL", "--max-time", "120", "--retry", "2", url,
                    "-o", str(download)], check=True)
    download.rename(rpm_path)
digest = hashlib.sha256(rpm_path.read_bytes()).hexdigest()
print(f"Kernel RPM SHA256: {digest}", flush=True)
if not args.kernel_rpm:
    if digest != expected_hash:
        raise SystemExit("kernel RPM digest mismatch")


def unpack_newc(data):
    pos = 0
    while pos + 110 <= len(data):
        assert data[pos:pos + 6] in (b"070701", b"070702"), "unsupported cpio format"
        fields = [int(data[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        size, namesize = fields[6], fields[11]
        pos += 110
        name = data[pos:pos + namesize - 1].decode()
        pos = (pos + namesize + 3) & ~3
        content = data[pos:pos + size]
        pos = (pos + size + 3) & ~3
        if name == "TRAILER!!!":
            return
        yield name.removeprefix("./"), content


kernel = None
config = ""
modules = {}
unpacked = subprocess.run(["rpm2cpio", str(rpm_path)], check=True, stdout=subprocess.PIPE).stdout
for name, content in unpack_newc(unpacked):
    if name.startswith("boot/vmlinuz-"):
        kernel = content
    if name.endswith("/af_packet.ko"):
        modules["af_packet.ko"] = content
    if name.startswith("boot/config-"):
        (work / "kernel.config").write_bytes(content)
        config = content.decode()
assert kernel, "kernel image not found in RPM"
kernel_path = work / "vmlinuz"
kernel_path.write_bytes(kernel)

archive = bytearray()


def add(name, content=b"", mode=stat.S_IFREG | 0o755, rdevmajor=0, rdevminor=0):
    n = name.encode() + b"\0"
    fields = [1, mode, 0, 0, 1, 0, len(content), 0, 0, rdevmajor, rdevminor, len(n), 0]
    archive.extend(b"070701" + b"".join(f"{f:08x}".encode() for f in fields) + n)
    archive.extend(b"\0" * (-len(archive) % 4))
    archive.extend(content)
    archive.extend(b"\0" * (-len(archive) % 4))


add("dev", mode=stat.S_IFDIR | 0o755)
add("proc", mode=stat.S_IFDIR | 0o755)
add("dev/console", mode=stat.S_IFCHR | 0o600, rdevmajor=5, rdevminor=1)
add("init", (root / "build" / f"vm-init-{args.arch}").read_bytes())
add("pktide", (root / "dist" / f"pktide-{args.arch}").read_bytes())
add("fixture.pcap", pcap(sample_packets()), mode=stat.S_IFREG | 0o600)
for name, content in modules.items():
    add(name, content)
add("TRAILER!!!", mode=0)
initramfs = work / "initramfs.cpio.gz"
initramfs.write_bytes(gzip.compress(archive, mtime=0))
boot_args = "console=ttyS0,115200 earlyprintk=serial,ttyS0,115200 panic=-1 acpi=off noapic mem=128M"
if profile["rootfs"] == "ext2":
    if "CONFIG_EXT2_FS=y" not in config or "CONFIG_PACKET=y" not in config:
        raise SystemExit("2.4 VM profile requires built-in EXT2_FS and PACKET (no module loader in test root)")
    # 2.4 cannot unpack a newc initramfs. Boot a feature-free ext2 ramdisk instead.
    # Build device inodes with debugfs, so the runner does not need host mknod/root.
    filesystem = work / "root.ext2"
    with tempfile.TemporaryDirectory(prefix="pktide-vm-root-") as directory:
        tree = pathlib.Path(directory)
        for name in ("dev", "proc"):
            (tree / name).mkdir()
        for name, source in (("init", root / "build" / f"vm-init-{args.arch}"),
                             ("pktide", root / "dist" / f"pktide-{args.arch}")):
            (tree / name).write_bytes(source.read_bytes())
            (tree / name).chmod(0o755)
        (tree / "fixture.pcap").write_bytes(pcap(sample_packets()))
        filesystem.write_bytes(b"")
        with filesystem.open("r+b") as stream:
            stream.truncate(8 * 1024 * 1024)
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext2", "-b", "1024", "-I", "128",
                        "-O", "none", "-d", str(tree), str(filesystem)], check=True)
        commands = tree / "debugfs.commands"
        commands.write_text("cd /dev\nmknod console c 5 1\nset_inode_field console mode 020600\n"
                            "mknod ram0 b 1 0\nset_inode_field ram0 mode 060600\n")
        subprocess.run(["debugfs", "-w", "-f", str(commands), str(filesystem)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    initramfs = work / "initrd.ext2.gz"
    initramfs.write_bytes(gzip.compress(filesystem.read_bytes(), mtime=0))
    boot_args += " root=/dev/ram0 rw init=/init ramdisk_size=16384"
else:
    boot_args += " rdinit=/init"
command = ["qemu-system-x86_64", "-machine", "pc-i440fx-2.0,accel=tcg", "-cpu", "Opteron_G1",
           "-m", "128", "-nodefaults", "-nographic", "-monitor", "none",
           "-serial", "stdio", "-no-reboot", "-net", "none"]
if int.from_bytes(kernel[0x206:0x208], "little") < 0x203:
    # QEMU 7.2 linuxboot writes initrd_max at 0x22c even for protocol 2.02,
    # where this kernel has setup instructions. ISOLINUX leaves them intact.
    # Use the original kernel bytes on a read-only, generated boot CD.
    iso = work / "boot.iso"
    with tempfile.TemporaryDirectory(prefix="pktide-boot-cd-") as directory:
        tree = pathlib.Path(directory)
        for name, source in (("isolinux.bin", pathlib.Path("/usr/lib/ISOLINUX/isolinux.bin")),
                             ("ldlinux.c32", pathlib.Path("/usr/lib/syslinux/modules/bios/ldlinux.c32")),
                             ("vmlinuz", kernel_path), ("initrd.gz", initramfs)):
            (tree / name).write_bytes(source.read_bytes())
        (tree / "isolinux.cfg").write_text(
            "SERIAL 0 115200\nDEFAULT pktide\nPROMPT 0\nTIMEOUT 1\n"
            "LABEL pktide\n  KERNEL /vmlinuz\n  APPEND initrd=/initrd.gz " + boot_args + "\n")
        subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-o", str(iso),
                        "-b", "isolinux.bin", "-c", "boot.cat", "-no-emul-boot",
                        "-boot-load-size", "4", "-boot-info-table", str(tree)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("Boot loader: ISOLINUX (unaltered protocol 2.02 kernel)", flush=True)
    command += ["-cdrom", str(iso), "-boot", "d"]
else:
    command += ["-kernel", str(kernel_path), "-initrd", str(initramfs), "-append", boot_args]
try:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=args.timeout)
    log = result.stdout
except subprocess.TimeoutExpired as exc:
    log = exc.stdout or b""
    (work / "console.log").write_bytes(log)
    print(log.decode(errors="replace"))
    raise SystemExit("VM timed out; see console.log") from exc
(work / "console.log").write_bytes(log)
for line in log.decode(errors="replace").splitlines():
    if "VM " in line or "PKTIDE_" in line or "pktide" in line or "matched=" in line:
        print(line)
kernel_match = re.search(rb"VM kernel: ([^\r\n ]+) arch: ([^\r\n ]+)", log)
if (result.returncode != 0 or not kernel_match or not kernel_match[1].decode().startswith(profile["kernel"] + "-") or
        kernel_match[2] not in ([b"x86_64"] if args.arch == "x86_64" else [b"i386", b"i486", b"i586", b"i686"]) or
        b"PKTIDE_VM_SUCCESS" not in log or b"VM FAIL" in log or
        b"seen=11 matched=3 matched_bytes=210" not in log or
        b"matched=1 matched_bytes=53 socket_packets=" not in log or
        b"matched=1 matched_bytes=55 socket_packets=" not in log):
    print(log.decode(errors="replace"))
    raise SystemExit("VM validation failed")
print(f"PASS: real {kernel_match[1].decode()} kernel / {args.arch}; full boot log: {work / 'console.log'}")
