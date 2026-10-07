#include "core.h"

static int need(struct packet *p, u32 end, u32 off, u32 n)
{
    if (off > end || n > end - off) {
        if (p->caplen < p->wirelen) p->truncated = 1;
        else p->malformed = 1;
        return 0;
    }
    return 1;
}

static u32 ip_end(struct packet *p, u32 off, u32 length)
{
    if (off > p->wirelen || length > p->wirelen - off) p->malformed = 1;
    if (off > p->caplen || length > p->caplen - off) {
        p->truncated = 1;
        return p->caplen;
    }
    return off + length;
}

void packet_decode(struct packet *p, const u8 *d, u32 cap, u32 wire, u32 link)
{
    u32 off = 0, end = cap, hlen, len, extensions = 0;
    u16 type = 0, frag;
    pt_memset(p, 0, sizeof(*p));
    p->caplen = cap; p->wirelen = wire;
    p->truncated = cap < wire;
    if (cap > wire) { p->malformed = 1; return; }
    if (link == PT_ETHERNET) {
        if (!need(p, end, 0, 14)) return;
        type = pt_be16(d + 12); off = 14;
    } else if (link == PT_LINUX_SLL) {
        if (!need(p, end, 0, 16)) return;
        type = pt_be16(d + 14); off = 16;
    } else if (link == PT_NULL || link == PT_LOOP) {
        u32 family;
        if (!need(p, end, 0, 4)) return;
        family = link == PT_LOOP ? pt_be32(d) : pt_le32(d);
        /* DLT_NULL uses the capturing host's endian and address-family ABI. */
        if (link == PT_NULL && family > 255) family = pt_be32(d);
        if (family == 2) type = 0x0800;
        else if (family == 24 || family == 28 || family == 30) type = 0x86dd;
        else return;
        off = 4;
    } else if (link == PT_RAW_IP) {
        if (!need(p, end, 0, 1)) return;
        if ((d[0] >> 4) == 4) type = 0x0800;
        else if ((d[0] >> 4) == 6) type = 0x86dd;
        else { p->malformed = 1; return; }
    } else { p->malformed = 1; return; }
    while (type == 0x8100 || type == 0x88a8 || type == 0x9100) {
        if (++extensions > 8) { p->malformed = 1; return; }
        if (!need(p, end, off, 4)) return;
        p->vlan = 1; p->vlan_id = pt_be16(d + off) & 4095;
        type = pt_be16(d + off + 2); off += 4;
    }
    p->ethertype = type;
    if (type == 0x0806) {
        p->arp = 1;
        if (!need(p, end, off, 8)) return;
        p->arp_op = pt_be16(d + off + 6);
        if (pt_be16(d + off) == 1 && pt_be16(d + off + 2) == 0x0800 &&
            d[off + 4] == 6 && d[off + 5] == 4) {
            if (!need(p, end, off, 28)) return;
            p->ipver = 4;
            pt_memcpy(p->src, d + off + 14, 4);
            pt_memcpy(p->dst, d + off + 24, 4);
        }
        return;
    }
    if (type == 0x0800) {
        if (!need(p, end, off, 20)) return;
        hlen = (d[off] & 15U) * 4;
        len = pt_be16(d + off + 2);
        if ((d[off] >> 4) != 4 || hlen < 20 || len < hlen) {
            p->malformed = 1; return;
        }
        end = ip_end(p, off, len);
        if (!need(p, end, off, hlen)) return;
        p->ipver = 4; p->protocol = d[off + 9];
        pt_memcpy(p->src, d + off + 12, 4);
        pt_memcpy(p->dst, d + off + 16, 4);
        frag = pt_be16(d + off + 6);
        p->fragment = (frag & 0x3fff) != 0;
        if (frag & 0x1fff) return; /* Never mistake fragment data for ports. */
        off += hlen;
    } else if (type == 0x86dd) {
        if (!need(p, end, off, 40)) return;
        if ((d[off] >> 4) != 6) { p->malformed = 1; return; }
        len = pt_be16(d + off + 4);
        end = ip_end(p, off, len + 40);
        p->ipver = 6; p->protocol = d[off + 6];
        pt_memcpy(p->src, d + off + 8, 16);
        pt_memcpy(p->dst, d + off + 24, 16);
        off += 40; extensions = 0;
        while (p->protocol == 0 || p->protocol == 43 || p->protocol == 60 ||
               p->protocol == 44 || p->protocol == 51) {
            u8 next;
            if (++extensions > 16) { p->malformed = 1; return; }
            if (!need(p, end, off, 2)) return;
            next = d[off];
            if (p->protocol == 44) {
                if (!need(p, end, off, 8)) return;
                frag = pt_be16(d + off + 2);
                p->fragment = 1; p->protocol = next;
                off += 8;
                if (frag & 0xfff8) return;
                continue;
            }
            hlen = p->protocol == 51 ? ((u32)d[off + 1] + 2) * 4 :
                                      ((u32)d[off + 1] + 1) * 8;
            if (!need(p, end, off, hlen)) return;
            p->protocol = next; off += hlen;
        }
    } else return;

    if (p->protocol == 6) {
        if (!need(p, end, off, 20)) return;
        hlen = (d[off + 12] >> 4) * 4U;
        if (hlen < 20) { p->malformed = 1; return; }
        if (!need(p, end, off, hlen)) return;
        p->tcp_flags = d[off + 13]; p->ports = 1; p->transport = 1;
    } else if (p->protocol == 17) {
        if (!need(p, end, off, 8)) return;
        len = pt_be16(d + off + 4);
        if (len < 8) { p->malformed = 1; return; }
        if (!p->fragment) (void)need(p, end, off, len);
        p->ports = 1; p->transport = 1;
    } else if (p->protocol == 1 || p->protocol == 58) {
        if (!need(p, end, off, 4)) return;
        p->icmp_type = d[off]; p->icmp_code = d[off + 1]; p->transport = 1;
    }
    if (p->ports) { p->sport = pt_be16(d + off); p->dport = pt_be16(d + off + 2); }
}

static void endpoint(struct text *t, const struct packet *p, const u8 *ip, u16 port)
{
    if (p->ipver == 6 && p->ports) text_char(t, '[');
    text_ip(t, ip, p->ipver);
    if (p->ipver == 6 && p->ports) text_char(t, ']');
    if (p->ports) { text_char(t, ':'); text_num(t, port, 0); }
}

void packet_summary(struct text *t, const struct packet *p)
{
    if (p->vlan) { text_str(t, "vlan "); text_num(t, p->vlan_id, 0); text_char(t, ' '); }
    if (p->arp) {
        text_str(t, "ARP op="); text_num(t, p->arp_op, 0);
        if (p->ipver) {
            text_char(t, ' '); text_ip(t, p->src, 4); text_str(t, " > "); text_ip(t, p->dst, 4);
        }
    } else if (p->ipver) {
        text_str(t, p->ipver == 4 ? "IP " : "IP6 ");
        endpoint(t, p, p->src, p->sport); text_str(t, " > "); endpoint(t, p, p->dst, p->dport);
        if (p->protocol == 6) {
            text_str(t, " TCP");
            if (p->transport) {
                static const char flags[] = "FSRPAUEC";
                unsigned i;
                text_str(t, " [");
                for (i = 0; i < 8; i++) if (p->tcp_flags & (1U << i)) text_char(t, flags[i]);
                text_char(t, ']');
            }
        } else if (p->protocol == 17) text_str(t, " UDP");
        else if (p->protocol == 1 || p->protocol == 58) {
            text_str(t, p->protocol == 1 ? " ICMP" : " ICMP6");
            if (p->transport) {
                text_str(t, " type="); text_num(t, p->icmp_type, 0);
                text_str(t, " code="); text_num(t, p->icmp_code, 0);
            }
        } else { text_str(t, " proto="); text_num(t, p->protocol, 0); }
    } else { text_str(t, "EtherType=0x"); text_hex(t, p->ethertype, 4); }
    text_str(t, " length="); text_num(t, p->wirelen, 0);
    if (p->fragment) text_str(t, " [fragment]");
    if (p->truncated) text_str(t, " [truncated]");
    if (p->malformed) text_str(t, " [malformed]");
}
