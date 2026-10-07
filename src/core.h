#ifndef PKTIDE_CORE_H
#define PKTIDE_CORE_H

/* Deliberately independent of libc and distribution header versions. */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef __SIZE_TYPE__ usize;

#define PT_VERSION "0.1.0"
#define PT_MAX_PACKET 65535U
#define PT_NULL 0U
#define PT_ETHERNET 1U
#define PT_RAW_IP 101U
#define PT_LOOP 108U
#define PT_LINUX_SLL 113U

void *pt_memcpy(void *dst, const void *src, usize n);
void *pt_memset(void *dst, int v, usize n);
int pt_equal(const void *a, const void *b, usize n);
usize pt_strlen(const char *s);
int pt_streq(const char *a, const char *b);
int pt_uint(const char *s, u32 max, u32 *out);
u16 pt_be16(const u8 *p);
u32 pt_be32(const u8 *p);
u32 pt_le32(const u8 *p);
void pt_put16(u8 *p, u16 v);
void pt_put32(u8 *p, u32 v);
int pt_address(const char *s, u8 *out); /* 4, 6 or 0; numeric only */

struct text {
    char data[1024];
    usize len;
};
void text_str(struct text *t, const char *s);
void text_char(struct text *t, char c);
void text_num(struct text *t, u64 n, unsigned width);
void text_hex(struct text *t, u32 n, unsigned width);
void text_ip(struct text *t, const u8 *ip, int version);

struct packet {
    u32 caplen, wirelen;
    u16 ethertype, sport, dport, vlan_id, arp_op;
    u8 src[16], dst[16];
    u8 ipver, protocol, ports, tcp_flags, icmp_type, icmp_code;
    u8 vlan, fragment, truncated, malformed, arp, transport;
};
void packet_decode(struct packet *p, const u8 *data, u32 caplen,
                   u32 wirelen, u32 linktype);
void packet_summary(struct text *t, const struct packet *p);

#define PT_FILTER_NODES 128
struct filter_node {
    int kind, left, right, direction, ipver;
    u32 value;
    u8 address[16];
};
struct filter {
    struct filter_node nodes[PT_FILTER_NODES];
    int count, root;
    const char *error;
};
int filter_parse(struct filter *f, const char *expression);
int filter_match(const struct filter *f, const struct packet *p);

#endif
