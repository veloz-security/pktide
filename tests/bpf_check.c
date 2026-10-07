#include "macos.h"
#include <net/bpf.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

volatile int pt_stopped;
static unsigned calls;
static int stop_after;
static u32 last_cap, last_wire, last_link;

static int packet(const u8 *data, u32 cap, u32 wire, u32 sec, u32 usec, u32 link)
{
    (void)data;
    if (sec != 1700000000 || usec != 123456) abort();
    calls++; last_cap = cap; last_wire = wire; last_link = link;
    return stop_after && calls == (unsigned)stop_after ? 1 : 0;
}
static usize record(u8 *buf, u32 cap, u32 wire)
{
    struct bpf_hdr h;
    pt_memset(&h, 0, sizeof(h));
    h.bh_tstamp.tv_sec = 1700000000; h.bh_tstamp.tv_usec = 123456;
    h.bh_hdrlen = (u16)sizeof(h); h.bh_caplen = cap; h.bh_datalen = wire;
    pt_memcpy(buf, &h, sizeof(h));
    pt_memset(buf + sizeof(h), 0, cap);
    return sizeof(h) + cap;
}
static void require(int condition) { if (!condition) abort(); }

int main(void)
{
    static u8 buf[70000];
    struct bpf_hdr h;
    usize first, total, i;
    u32 link;
    require(pt_macos_linktype(DLT_RAW, &link) && link == 101);
    require(pt_macos_linktype(DLT_NULL, &link) && link == 0);
    require(pt_macos_linktype(DLT_EN10MB, &link) && link == 1);
    require(!pt_macos_linktype(0xffffU, &link));
    first = record(buf, 5, 10);
    total = BPF_WORDALIGN(first);
    total += record(buf + total, 8, 8);
    require(pt_macos_bpf_batch(buf, total, PT_NULL, packet) == 0);
    require(calls == 2 && last_cap == 8 && last_wire == 8 && last_link == PT_NULL);
    calls = 0; stop_after = 1;
    require(pt_macos_bpf_batch(buf, total, PT_NULL, packet) == 1 && calls == 1);
    stop_after = 0;
    first = record(buf, 20, 40);
    for (i = 1; i < first; i++) require(pt_macos_bpf_batch(buf, i, PT_NULL, packet) == -1);
    pt_memcpy(&h, buf, sizeof(h)); h.bh_caplen = h.bh_datalen + 1;
    pt_memcpy(buf, &h, sizeof(h));
    require(pt_macos_bpf_batch(buf, first, PT_NULL, packet) == -1);
    first = record(buf, 0, 0);
    pt_memcpy(&h, buf, sizeof(h)); h.bh_hdrlen = 1;
    pt_memcpy(buf, &h, sizeof(h));
    require(pt_macos_bpf_batch(buf, first, PT_NULL, packet) == -1);
    first = record(buf, 66000, 70000);
    require(pt_macos_bpf_batch(buf, first, PT_RAW_IP, packet) == 0);
    require(last_cap == 65535 && last_wire == 70000);
    first = record(buf, 0, 0);
    pt_memcpy(&h, buf, sizeof(h)); h.bh_tstamp.tv_usec = 1000000;
    pt_memcpy(buf, &h, sizeof(h));
    require(pt_macos_bpf_batch(buf, first, PT_NULL, packet) == -1);
    puts("PASS: macOS BPF batches, padding, count limit, malformed/truncated records, RAW mapping");
    return 0;
}
