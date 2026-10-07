#include "macos.h"
#include <net/bpf.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

static int fail(const char *operation)
{
    fprintf(stderr, "pktide: %s (errno %d)\n", operation, errno);
    return 1;
}

int pt_macos_list(void)
{
    struct if_nameindex *interfaces = if_nameindex(), *entry;
    int result = 0;
    if (!interfaces) return fail("list interfaces");
    for (entry = interfaces; entry->if_index; entry++) {
        if (!pt_writeall(1, entry->if_name, pt_strlen(entry->if_name)) || !pt_writeall(1, "\n", 1)) {
            result = fail("write interface list"); break;
        }
    }
    if_freenameindex(interfaces);
    return result;
}

static int open_bpf(void)
{
    unsigned i;
    for (i = 0; i < 256; i++) {
        char path[32];
        int fd;
        (void)snprintf(path, sizeof(path), "/dev/bpf%u", i);
        /* Read-only descriptor: this backend cannot inject packets. */
        fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd >= 0) return fd;
        if (errno == EBUSY) continue;
        if (errno == EACCES || errno == EPERM) {
            fprintf(stderr, "pktide: packet capture requires root or read access to /dev/bpf*; use sudo\n");
            return -1;
        }
        fail("open BPF device");
        return -1;
    }
    errno = EBUSY; fail("all BPF devices are busy"); return -1;
}

/* BPF counters are cumulative, unlike Linux PACKET_STATISTICS. */
static void collect(int fd, struct pt_macos_stats *stats, struct bpf_stat *previous)
{
    struct bpf_stat current;
    if (ioctl(fd, BIOCGSTATS, &current) < 0) return;
    stats->packets += (u32)(current.bs_recv - previous->bs_recv);
    stats->drops += (u32)(current.bs_drop - previous->bs_drop);
    stats->available = 1;
    *previous = current;
}

int pt_macos_capture(const struct pt_macos_options *opt, pt_macos_ready_fn ready,
                     pt_macos_packet_fn packet, struct pt_macos_stats *stats)
{
    static u8 buffer[BPF_MAXBUFSIZE];
    struct ifreq request;
    struct bpf_stat previous = {0, 0};
    struct pollfd pfd;
    struct timeval last = {0, 0};
    u32 link;
    unsigned length, dlt, immediate = 1;
    usize name_length = pt_strlen(opt->interface);
    int fd, status = 1;
    pt_memset(stats, 0, sizeof(*stats));
    if (pt_streq(opt->interface, "any")) {
        fprintf(stderr, "pktide: macOS requires one interface; use -D, then -i en0 or -i lo0\n");
        return 1;
    }
    if (name_length >= sizeof(request.ifr_name)) {
        fprintf(stderr, "pktide: interface name is too long\n"); return 1;
    }
    if (!if_nametoindex(opt->interface)) return fail("interface lookup");
    fd = open_bpf();
    if (fd < 0) return 1;

    /* BIOCSBLEN must precede BIOCSETIF. BPF clamps the requested buffer size. */
    length = opt->buffer_kib * 1024;
    if (length > sizeof(buffer)) length = (unsigned)sizeof(buffer);
    if (ioctl(fd, BIOCSBLEN, &length) < 0) { fail("set BPF buffer length"); goto done; }
    pt_memset(&request, 0, sizeof(request));
    pt_memcpy(request.ifr_name, opt->interface, name_length);
    if (ioctl(fd, BIOCSETIF, &request) < 0) { fail("attach BPF to interface"); goto done; }
    if (ioctl(fd, BIOCGDLT, &dlt) < 0) { fail("query BPF link type"); goto done; }
    if (!pt_macos_linktype(dlt, &link)) {
        fprintf(stderr, "pktide: unsupported BPF link type %u (Ethernet/NULL/LOOP/RAW supported)\n", dlt);
        goto done;
    }
    if (ioctl(fd, BIOCGBLEN, &length) < 0) { fail("query BPF buffer length"); goto done; }
    if (!length || length > sizeof(buffer)) {
        fprintf(stderr, "pktide: invalid BPF buffer size\n"); goto done;
    }
    if (ioctl(fd, BIOCIMMEDIATE, &immediate) < 0) { fail("set BPF immediate mode"); goto done; }
    if (opt->promiscuous && dlt == DLT_EN10MB && ioctl(fd, BIOCPROMISC, 0) < 0) {
        fail("promiscuous membership (or use -p)"); goto done;
    }
    if (ready(opt->interface, link)) goto done;
    pfd.fd = fd; pfd.events = POLLIN; pfd.revents = 0;
    status = 0;
    while (!pt_stopped) {
        struct timeval now;
        ssize_t received;
        int result = poll(&pfd, 1, 1000);
        if (result < 0) {
            if (errno == EINTR) continue;
            status = fail("poll BPF"); break;
        }
        if (gettimeofday(&now, 0) == 0 && now.tv_sec != last.tv_sec) {
            collect(fd, stats, &previous); last = now;
        }
        if (!result) continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "pktide: capture device closed or failed\n"); status = 1; break;
        }
        if (!(pfd.revents & POLLIN)) continue;
        received = read(fd, buffer, length);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            status = fail("read BPF packets"); break;
        }
        if (!received) continue;
        result = pt_macos_bpf_batch(buffer, (usize)received, link, packet);
        if (result < 0) {
            fprintf(stderr, "pktide: invalid BPF record or packet output failure\n"); status = 1; break;
        }
        if (result > 0) break;
    }
    collect(fd, stats, &previous);
done:
    /* Closing BPF releases promiscuous mode on this descriptor. */
    close(fd);
    return status;
}
