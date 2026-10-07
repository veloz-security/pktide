#include "macos.h"
#include <net/bpf.h>
#include <stddef.h>

int pt_macos_linktype(unsigned dlt, u32 *link)
{
    switch (dlt) {
    case DLT_EN10MB: *link = PT_ETHERNET; return 1;
    case DLT_NULL: *link = PT_NULL; return 1;
    case DLT_LOOP: *link = PT_LOOP; return 1;
    /* Darwin's in-memory DLT_RAW is 12; the portable PCAP LINKTYPE_RAW is 101. */
    case DLT_RAW: *link = PT_RAW_IP; return 1;
    default: return 0;
    }
}

int pt_macos_bpf_batch(const u8 *data, usize size, u32 link, pt_macos_packet_fn packet)
{
    const usize min_header = offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(u16);
    usize offset = 0;
    while (offset < size && !pt_stopped) {
        struct bpf_hdr h;
        usize remaining = size - offset, span, step;
        int result;
        if (remaining < min_header) return -1;
        /* BPF headers are 4-byte aligned, not necessarily C-pointer aligned. */
        pt_memset(&h, 0, sizeof(h));
        pt_memcpy(&h, data + offset, min_header);
        if (h.bh_hdrlen < min_header || h.bh_hdrlen > remaining ||
            h.bh_caplen > remaining - h.bh_hdrlen || h.bh_caplen > h.bh_datalen ||
            h.bh_tstamp.tv_sec < 0 || h.bh_tstamp.tv_usec < 0 || h.bh_tstamp.tv_usec >= 1000000)
            return -1;
        result = packet(data + offset + h.bh_hdrlen,
                        h.bh_caplen < PT_MAX_PACKET ? h.bh_caplen : PT_MAX_PACKET,
                        h.bh_datalen, (u32)h.bh_tstamp.tv_sec, (u32)h.bh_tstamp.tv_usec, link);
        if (result) return result;
        span = (usize)h.bh_hdrlen + h.bh_caplen;
        step = BPF_WORDALIGN(span);
        /* A final record need not include padding after its payload. */
        if (span == remaining) return 0;
        if (step > remaining) return -1;
        offset += step;
    }
    return 0;
}
