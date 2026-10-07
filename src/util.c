#include "core.h"

void *pt_memcpy(void *dst, const void *src, usize n)
{
    u8 *d = dst;
    const u8 *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *pt_memset(void *dst, int v, usize n)
{
    u8 *d = dst;
    while (n--) *d++ = (u8)v;
    return dst;
}

int pt_equal(const void *a, const void *b, usize n)
{
    const u8 *x = a, *y = b;
    while (n--) if (*x++ != *y++) return 0;
    return 1;
}

usize pt_strlen(const char *s)
{
    usize n = 0;
    while (s[n]) n++;
    return n;
}

int pt_streq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

int pt_uint(const char *s, u32 max, u32 *out)
{
    u32 n = 0;
    if (!*s) return 0;
    for (; *s; s++) {
        u32 d = (u32)(*s - '0');
        if (d > 9 || d > max || n > (max - d) / 10) return 0;
        n = n * 10 + d;
    }
    *out = n;
    return 1;
}

u16 pt_be16(const u8 *p) { return (u16)(((u16)p[0] << 8) | p[1]); }
u32 pt_be32(const u8 *p)
{
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}
u32 pt_le32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
void pt_put16(u8 *p, u16 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); }
void pt_put32(u8 *p, u32 v)
{
    p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24);
}

static int address4(const char *s, u8 *out)
{
    int i;
    for (i = 0; i < 4; i++) {
        unsigned n = 0, digits = 0;
        while (*s >= '0' && *s <= '9') {
            n = n * 10 + (unsigned)(*s++ - '0');
            if (++digits > 3 || n > 255) return 0;
        }
        if (!digits) return 0;
        out[i] = (u8)n;
        if (i < 3) { if (*s++ != '.') return 0; }
        else if (*s) return 0;
    }
    return 4;
}

int pt_address(const char *s, u8 *out)
{
    u8 tmp[16];
    int colon = 0, n = 0, gap = -1, i;
    const char *q;
    for (q = s; *q; q++) if (*q == ':') colon = 1;
    pt_memset(out, 0, 16);
    if (!colon) return address4(s, out);
    if (*s == ':') {
        if (s[1] != ':') return 0;
        gap = 0; s += 2;
    }
    while (*s) {
        unsigned v = 0, digits = 0;
        const char *start = s;
        if (n >= 16) return 0;
        for (q = s; *q && *q != ':'; q++) {
            if (*q == '.') {
                if (n > 12 || !address4(start, tmp + n)) return 0;
                n += 4;
                s += pt_strlen(s);
                goto complete;
            }
        }
        while (*s && *s != ':') {
            unsigned d;
            if (*s >= '0' && *s <= '9') d = (unsigned)(*s - '0');
            else if (*s >= 'a' && *s <= 'f') d = (unsigned)(*s - 'a') + 10;
            else if (*s >= 'A' && *s <= 'F') d = (unsigned)(*s - 'A') + 10;
            else return 0;
            if (++digits > 4) return 0;
            v = (v << 4) | d; s++;
        }
        if (!digits) return 0;
        tmp[n++] = (u8)(v >> 8); tmp[n++] = (u8)v;
        if (*s) {
            s++;
            if (*s == ':') {
                if (gap >= 0) return 0;
                gap = n; s++;
            } else if (!*s) return 0;
        }
    }
complete:
    if (gap < 0) {
        if (n != 16) return 0;
        pt_memcpy(out, tmp, 16);
    } else {
        if (n >= 16) return 0;
        pt_memcpy(out, tmp, (usize)gap);
        for (i = gap; i < n; i++) out[16 - n + i] = tmp[i];
    }
    return 6;
}

void text_char(struct text *t, char c)
{
    if (t->len < sizeof(t->data)) t->data[t->len++] = c;
}
void text_str(struct text *t, const char *s) { while (*s) text_char(t, *s++); }

/* Avoid __udivdi3 / libgcc on 32-bit builds. Only formatting needs u64 / 10. */
static u64 divide10(u64 n, unsigned *rem)
{
    u64 q = 0;
    unsigned r = 0;
    int bit;
    for (bit = 63; bit >= 0; bit--) {
        r = r * 2 + (unsigned)((n >> bit) & 1);
        if (r >= 10) { r -= 10; q |= (u64)1 << bit; }
    }
    *rem = r;
    return q;
}
void text_num(struct text *t, u64 n, unsigned width)
{
    char b[32];
    unsigned len = 0, r;
    do { n = divide10(n, &r); b[len++] = (char)('0' + r); } while (n);
    while (width > len) { text_char(t, '0'); width--; }
    while (len) text_char(t, b[--len]);
}
void text_hex(struct text *t, u32 n, unsigned width)
{
    char b[8];
    unsigned len = 0;
    do { b[len++] = "0123456789abcdef"[n & 15]; n >>= 4; } while (n);
    while (width > len) { text_char(t, '0'); width--; }
    while (len) text_char(t, b[--len]);
}
void text_ip(struct text *t, const u8 *ip, int version)
{
    int i;
    if (version == 4) {
        for (i = 0; i < 4; i++) {
            if (i) text_char(t, '.');
            text_num(t, ip[i], 0);
        }
    } else {
        /* Uncompressed, unambiguous numeric addresses; no DNS/NSS calls. */
        for (i = 0; i < 16; i += 2) {
            if (i) text_char(t, ':');
            text_hex(t, pt_be16(ip + i), 0);
        }
    }
}
