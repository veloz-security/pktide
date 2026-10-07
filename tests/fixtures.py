"""Synthetic documentation-range traffic; nothing is sent onto a network."""
import ipaddress
import struct


def ipv4(payload, proto=6, frag=0):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, frag,
                       64, proto, 0, ipaddress.ip_address("192.0.2.10").packed,
                       ipaddress.ip_address("198.51.100.20").packed) + payload


def ipv6(payload, proto=6):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, 64,
                       ipaddress.ip_address("2001:db8::1").packed,
                       ipaddress.ip_address("2001:db8::2").packed) + payload


def tcp(sport=12345, dport=443):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 2, 8192, 0, 0)


def udp(sport=12345, dport=53):
    return struct.pack("!HHHH", sport, dport, 12, 0) + b"test"


def ether(payload, kind=0x0800):
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", kind) + payload


def sll(payload, kind=0x0800):
    return struct.pack("!HHH8sH", 0, 1, 6, bytes.fromhex("0011223344550000"), kind) + payload


def pcap(records, endian="<", nano=False, link=1, snap=65535):
    result = struct.pack(endian + "IHHIIII", 0xA1B23C4D if nano else 0xA1B2C3D4,
                         2, 4, 0, 0, snap, link)
    for record in records:
        data, wire = record if isinstance(record, tuple) else (record, len(record))
        result += struct.pack(endian + "IIII", 1700000000, 123456789 if nano else 123456,
                              len(data), wire) + data
    return result


def sample_packets():
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1,
                      bytes.fromhex("66778899aabb"), bytes([192, 0, 2, 10]),
                      b"\0" * 6, bytes([198, 51, 100, 20]))
    return [
        ether(ipv4(tcp())),
        ether(ipv4(udp(), 17)),
        ether(ipv4(bytes([8, 0, 0, 0, 0, 0, 0, 0]), 1)),
        ether(arp, 0x0806),
        ether(ipv6(tcp()), 0x86DD),
        ether(ipv6(udp(), 17), 0x86DD),
        ether(ipv6(bytes([128, 0, 0, 0, 0, 0, 0, 0]), 58), 0x86DD),
        ether(struct.pack("!HH", 42, 0x0800) + ipv4(tcp(dport=80)), 0x8100),
        ether(ipv4(tcp(dport=443), frag=1)),
        ether(ipv6(bytes([6, 0]) + b"\0" * 6 + tcp(), 0), 0x86DD),
        ether(b"example", 0x88B5),
    ]
