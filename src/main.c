#ifdef __APPLE__
#include "macos.h"
#else
#include "linux_abi.h"
#endif

struct options {
    const char *interface, *input, *output;
    u32 snaplen, count, buffer_kib;
    int quiet, hex, promiscuous, list;
    char expression[4096];
};
static struct options opt;
static struct filter active_filter;
static u8 packet_data[PT_MAX_PACKET];
static int output_fd = -1, text_fd = 1;
static u64 seen, matched, bytes;
static u64 kernel_packets, kernel_drops;
static int stats_available;

static void message(const char *s)
{
    (void)pt_writeall(2, s, pt_strlen(s));
}
static int error(const char *s)
{
    message("pktide: "); message(s); message("\n"); return 1;
}
static int syserror(const char *s, long r)
{
    struct text t = {{0}, 0};
    text_str(&t, "pktide: "); text_str(&t, s); text_str(&t, " (errno ");
    text_num(&t, (u64)-r, 0); text_str(&t, ")\n");
    (void)pt_writeall(2, t.data, t.len); return 1;
}
static void stop_handler(int sig) { (void)sig; pt_stopped = 1; }

static const char help[] =
#ifdef __APPLE__
"pktide " PT_VERSION " - macOS packet monitor (" PT_ARCH ")\n"
"Usage: pktide [options] [filter expression]\n"
"  -i IFACE      Capture one interface, e.g. en0 or lo0 (default: en0)\n"
#else
"pktide " PT_VERSION " - standalone Linux packet monitor (" PT_ARCH ")\n"
"Usage: pktide [options] [filter expression]\n"
"  -i IFACE      Capture interface, or 'any' (default: any, Linux SLL)\n"
#endif
"  -r FILE       Read classic PCAP; '-' reads standard input\n"
"  -w FILE       Save matched packets to a NEW PCAP file; '-' writes stdout\n"
"  -c N          Stop after N matching packets\n"
"  -s N          Saved/displayed snapshot length, 1..65535 (default 65535)\n"
"  -B KiB        Request socket receive buffer (default 2048 KiB)\n"
"  -p            Disable promiscuous mode on a named interface\n"
"  -q            Suppress per-packet text (statistics remain on stderr)\n"
"  -X            Hex + ASCII dump of captured bytes\n"
"  -n, -nn       Accepted; addresses and ports are always numeric\n"
"  -D            List interfaces (no root needed)\n"
"  -h, --help    Show help\n"
"  --version     Show version and ABI\n"
"Filters: tcp udp icmp icmp6 arp ip ip6 vlan; [src|dst] port N;\n"
"         [src|dst] host NUMERIC_IP; and/or/not; parentheses; implicit and.\n"
"Precedence: not > and > or. Quote expressions containing parentheses.\n"
#ifdef __APPLE__
"Example: pktide -i en0 -c 100 -w trace.pcap 'tcp and port 443'\n"
"Capture needs root or read access to /dev/bpf*. Reading files needs neither.\n"
#else
"Example: pktide -i eth0 -c 100 -w trace.pcap 'tcp and port 443'\n"
"Capture needs root or CAP_NET_RAW. Reading files needs neither.\n"
#endif
"Text timestamps: Unix epoch seconds.microseconds. Ctrl-C prints statistics.\n";

static int options(int argc, char **argv)
{
    int i;
    usize used = 0;
#ifdef __APPLE__
    opt.interface = "en0";
#else
    opt.interface = "any";
#endif
    opt.snaplen = PT_MAX_PACKET;
    opt.buffer_kib = 2048; opt.promiscuous = 1;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i], *v;
        char c;
        if (pt_streq(a, "--")) { i++; break; }
        if (*a != '-') break;
        if (pt_streq(a, "--help") || pt_streq(a, "-h")) {
            if (!pt_writeall(1, help, sizeof(help) - 1)) return -1;
            return 1;
        }
        if (pt_streq(a, "--version")) {
#ifdef __APPLE__
            const char *s = "pktide " PT_VERSION " macOS/" PT_ARCH " BPF; system libSystem only; macOS 11+ target\n";
#else
            const char *s = "pktide " PT_VERSION " Linux/" PT_ARCH " static, no libc; Linux " PT_LINUX_MIN " ABI target\n";
#endif
            return pt_writeall(1, s, pt_strlen(s)) ? 1 : -1;
        }
        if (pt_streq(a, "-n") || pt_streq(a, "-nn")) continue;
        if (pt_streq(a, "-q")) { opt.quiet = 1; continue; }
        if (pt_streq(a, "-X")) { opt.hex = 1; continue; }
        if (pt_streq(a, "-p")) { opt.promiscuous = 0; continue; }
        if (pt_streq(a, "-D")) { opt.list = 1; continue; }
        c = a[1];
        if (!c || (c != 'i' && c != 'r' && c != 'w' && c != 'c' && c != 's' && c != 'B')) {
            error("unknown option (use --help)"); return -1;
        }
        if (a[2]) v = a + 2;
        else if (++i < argc) v = argv[i];
        else { error("option requires an argument"); return -1; }
        if (!*v) { error("empty option argument"); return -1; }
        if (c == 'i') opt.interface = v;
        else if (c == 'r') opt.input = v;
        else if (c == 'w') opt.output = v;
        else {
            u32 n, max = c == 'c' ? 0xffffffffU : 65535;
            if (!pt_uint(v, max, &n) || n == 0) { error("numeric option is out of range"); return -1; }
            if (c == 'c') opt.count = n;
            else if (c == 's') opt.snaplen = n;
            else opt.buffer_kib = n;
        }
    }
    for (; i < argc; i++) {
        usize n = pt_strlen(argv[i]);
        usize separator = used ? 1 : 0;
        if (used + separator >= sizeof(opt.expression) ||
            n > sizeof(opt.expression) - 1 - used - separator) {
            error("filter is too long"); return -1;
        }
        if (used) opt.expression[used++] = ' ';
        pt_memcpy(opt.expression + used, argv[i], n); used += n;
    }
    opt.expression[used] = 0;
    if (!filter_parse(&active_filter, opt.expression)) { error(active_filter.error); return -1; }
    return 0;
}

static int list_interfaces(void)
{
#ifdef __APPLE__
    return pt_macos_list();
#else
    char buf[32768];
    usize used = 0, start = 0, i;
    long fd = pt_open("/proc/net/dev", 0, 0);
    if (fd < 0) return syserror("open /proc/net/dev", fd);
    while (used < sizeof(buf)) {
        long r = pt_read((int)fd, buf + used, sizeof(buf) - used);
        if (r == -PT_EINTR) continue;
        if (r < 0) { pt_close((int)fd); return syserror("read /proc/net/dev", r); }
        if (!r) break;
        used += (usize)r;
    }
    pt_close((int)fd);
    if (used == sizeof(buf)) return error("too many interfaces for -D; specify -i directly");
    if (!pt_writeall(1, "any\n", 4)) return error("write interface list failed");
    for (i = 0; i < used; i++) {
        if (buf[i] == '\n') start = i + 1;
        if (buf[i] == ':') {
            while (start < i && (buf[start] == ' ' || buf[start] == '\t')) start++;
            if (!pt_writeall(1, buf + start, i - start) || !pt_writeall(1, "\n", 1))
                return error("write interface list failed");
        }
    }
    return 0;
#endif
}

static int begin_output(u32 linktype, u32 source_snaplen)
{
    u8 h[24];
    long fd;
    if (!opt.output) return 0;
    if (pt_streq(opt.output, "-")) { output_fd = 1; text_fd = 2; }
    else {
        /* O_EXCL also prevents clobbering the input file or following a symlink. */
        fd = pt_open(opt.output, PT_OPEN_NEW, 0600);
        if (fd < 0) return syserror("create PCAP (output must not already exist)", fd);
        output_fd = (int)fd;
    }
    pt_memset(h, 0, sizeof(h));
    pt_put32(h, 0xa1b2c3d4U); pt_put16(h + 4, 2); pt_put16(h + 6, 4);
    pt_put32(h + 16, opt.snaplen < source_snaplen ? opt.snaplen : source_snaplen);
    pt_put32(h + 20, linktype);
    if (!pt_writeall(output_fd, h, sizeof(h))) return error("write PCAP header failed");
    return 0;
}

static int hex_dump(const u8 *d, u32 n)
{
    u32 off, j;
    for (off = 0; off < n; off += 16) {
        struct text t = {{0}, 0};
        text_str(&t, "  "); text_hex(&t, off, 4); text_str(&t, "  ");
        for (j = 0; j < 16; j++) {
            if (off + j < n) { text_hex(&t, d[off + j], 2); text_char(&t, ' '); }
            else text_str(&t, "   ");
        }
        text_str(&t, " |");
        for (j = 0; j < 16 && off + j < n; j++) {
            u8 c = d[off + j]; text_char(&t, c >= 32 && c < 127 ? (char)c : '.');
        }
        text_str(&t, "|\n");
        if (!pt_writeall(text_fd, t.data, t.len)) return error("write hex dump failed");
    }
    return 0;
}

static int process(u32 sec, u32 usec, u32 caplen, u32 wirelen, u32 link)
{
    struct packet p;
    u32 saved = caplen < opt.snaplen ? caplen : opt.snaplen;
    packet_decode(&p, packet_data, caplen, wirelen, link); seen++;
    if (!filter_match(&active_filter, &p)) return 0;
    matched++; bytes += wirelen;
    if (output_fd >= 0) {
        u8 h[16];
        pt_put32(h, sec); pt_put32(h + 4, usec);
        pt_put32(h + 8, saved); pt_put32(h + 12, wirelen);
        if (!pt_writeall(output_fd, h, sizeof(h)) || !pt_writeall(output_fd, packet_data, saved))
            return error("write PCAP record failed (capture may be incomplete)");
    }
    if (!opt.quiet) {
        struct text t = {{0}, 0};
        /* Decode saved bytes for display, but filter on all available bytes. */
        if (saved != caplen) packet_decode(&p, packet_data, saved, wirelen, link);
        text_num(&t, sec, 0); text_char(&t, '.'); text_num(&t, usec, 6); text_char(&t, ' ');
        packet_summary(&t, &p); text_char(&t, '\n');
        if (!pt_writeall(text_fd, t.data, t.len)) return error("write packet summary failed");
        if (opt.hex && hex_dump(packet_data, saved)) return 1;
    }
    return 0;
}

static u32 file32(const u8 *p, int little) { return little ? pt_le32(p) : pt_be32(p); }
static u16 file16(const u8 *p, int little) { return little ? (u16)(p[0] | ((u16)p[1] << 8)) : pt_be16(p); }

static int read_pcap(void)
{
    u8 h[24];
    int fd = 0, little, nano, status = 1, r;
    u32 magic, source_snaplen, link;
    if (!pt_streq(opt.input, "-")) {
        long opened = pt_open(opt.input, 0, 0);
        if (opened < 0) return syserror("open input PCAP", opened);
        fd = (int)opened;
    }
    if (pt_readfull(fd, h, 24) != 1) { error("missing/truncated PCAP global header"); goto done; }
    magic = pt_le32(h);
    little = magic == 0xa1b2c3d4U || magic == 0xa1b23c4dU;
    nano = magic == 0xa1b23c4dU || magic == 0x4d3cb2a1U;
    if (!little && magic != 0xd4c3b2a1U && magic != 0x4d3cb2a1U) {
        error("unsupported capture format (classic PCAP required; no PCAPNG)"); goto done;
    }
    if (file16(h + 4, little) != 2 || file16(h + 6, little) != 4) {
        error("unsupported PCAP version (2.4 required)"); goto done;
    }
    source_snaplen = file32(h + 16, little); link = file32(h + 20, little);
    if (!source_snaplen) {
        error("PCAP snapshot length must be nonzero"); goto done;
    }
    if (link != PT_ETHERNET && link != PT_LINUX_SLL && link != PT_RAW_IP &&
        link != PT_NULL && link != PT_LOOP) {
        error("unsupported PCAP link type (Ethernet=1, NULL=0, RAW=101, LOOP=108, SLL=113 supported)"); goto done;
    }
    if (begin_output(link, source_snaplen)) goto done;
    status = 0;
    while (!pt_stopped && (!opt.count || matched < opt.count)) {
        u32 sec, fraction, caplen, wirelen;
        r = pt_readfull(fd, h, 16);
        if (!r) break;
        if (r < 0) {
            if (!pt_stopped) status = error("truncated/unreadable PCAP record header");
            break;
        }
        sec = file32(h, little); fraction = file32(h + 4, little);
        caplen = file32(h + 8, little); wirelen = file32(h + 12, little);
        if (caplen > PT_MAX_PACKET || caplen > source_snaplen || caplen > wirelen ||
            fraction >= (nano ? 1000000000U : 1000000U)) {
            status = error("invalid PCAP record length or timestamp"); break;
        }
        if (caplen && pt_readfull(fd, packet_data, caplen) != 1) {
            if (!pt_stopped) status = error("truncated/unreadable PCAP packet data");
            break;
        }
        if (process(sec, nano ? fraction / 1000 : fraction, caplen, wirelen, link)) {
            status = 1; break;
        }
    }
done:
    if (fd != 0) pt_close(fd);
    return status;
}

#ifndef __APPLE__
static void collect_stats(int fd)
{
    struct pt_packet_stats s;
    pt_memset(&s, 0, sizeof(s));
    if (pt_sockopt(fd, PT_SOL_PACKET, PT_PACKET_STATISTICS, &s, sizeof(s), 1) >= 0) {
        /* The kernel resets these 32-bit counters after every query. */
        kernel_packets += s.packets; kernel_drops += s.drops; stats_available = 1;
    }
}

static int capture(void)
{
    int any = pt_streq(opt.interface, "any"), status = 1, fd, index = 0;
    u32 link = any ? PT_LINUX_SLL : PT_ETHERNET, prefix = any ? 16 : 0;
    struct pt_sockaddr_ll bind_addr;
    struct pt_pollfd pollfd;
    struct pt_timeval last_stats = {0, 0};
    long r = pt_socket(any ? PT_SOCK_DGRAM : PT_SOCK_RAW);
    if (r < 0) {
        if (r == -1 || r == -13) return error("packet capture requires root or CAP_NET_RAW");
        return syserror("AF_PACKET socket", r);
    }
    fd = (int)r;
    if (!any) {
        struct pt_ifreq req;
        usize n = pt_strlen(opt.interface);
        if (n >= sizeof(req.name)) { error("interface name exceeds 15 bytes"); goto done; }
        pt_memset(&req, 0, sizeof(req)); pt_memcpy(req.name, opt.interface, n);
        r = pt_ioctl(fd, PT_SIOCGIFINDEX, &req);
        if (r < 0) { syserror("interface lookup", r); goto done; }
        index = req.u.index;
        r = pt_ioctl(fd, PT_SIOCGIFHWADDR, &req);
        if (r < 0) { syserror("interface hardware type", r); goto done; }
        if (req.u.hw.family != 1 && req.u.hw.family != 772) {
            error("named interface must be Ethernet/loopback; use -i any for other link types"); goto done;
        }
        if (opt.promiscuous && req.u.hw.family != 772) {
            struct pt_packet_mreq membership;
            pt_memset(&membership, 0, sizeof(membership)); membership.ifindex = index; membership.type = 1;
            r = pt_sockopt(fd, PT_SOL_PACKET, PT_PACKET_ADD_MEMBERSHIP, &membership, sizeof(membership), 0);
            if (r < 0) { syserror("promiscuous membership (or use -p)", r); goto done; }
        }
    }
    {
        u32 requested = opt.buffer_kib * 1024;
        r = pt_sockopt(fd, 1, 8, &requested, sizeof(requested), 0); /* SOL_SOCKET, SO_RCVBUF */
        if (r < 0) { syserror("SO_RCVBUF", r); goto done; }
    }
    pt_memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.family = PT_AF_PACKET; bind_addr.protocol = 0x0300; /* htons(ETH_P_ALL) */
    bind_addr.ifindex = index;
    r = pt_bind(fd, &bind_addr);
    if (r < 0) { syserror("bind packet socket", r); goto done; }
    if (begin_output(link, PT_MAX_PACKET)) goto done;
    message("pktide: listening on "); message(opt.interface);
    message(any ? " (Linux SLL), Ctrl-C to stop\n" : " (Ethernet), Ctrl-C to stop\n");
    pollfd.fd = fd; pollfd.events = 1; pollfd.revents = 0;
    status = 0;
    while (!pt_stopped && (!opt.count || matched < opt.count)) {
        struct pt_timeval now;
        struct pt_sockaddr_ll from;
        u32 wirelen, caplen;
        r = pt_poll(&pollfd, 1000);
        if (r == -PT_EINTR) continue;
        if (r < 0) { status = syserror("poll", r); break; }
        if (pt_time(&now) == 0 && now.sec != last_stats.sec) {
            collect_stats(fd); last_stats = now;
        }
        if (!r) continue;
        if (pollfd.revents & (8 | 16 | 32)) { status = error("capture socket closed or failed"); break; }
        if (!(pollfd.revents & 1)) continue;
        pt_memset(&from, 0, sizeof(from));
        r = pt_recv(fd, packet_data + prefix, sizeof(packet_data) - prefix, &from);
        if (r == -PT_EINTR || r == -PT_EAGAIN) continue;
        if (r < 0) { status = syserror("receive packet", r); break; }
        if (from.hatype == 772 && from.pkttype == 4) continue; /* Loopback duplicate. */
        if ((u64)r + prefix > 0xffffffffU) { status = error("packet length overflow"); break; }
        wirelen = (u32)r + prefix; caplen = wirelen < PT_MAX_PACKET ? wirelen : PT_MAX_PACKET;
        if (any) {
            packet_data[0] = 0; packet_data[1] = from.pkttype;
            packet_data[2] = (u8)(from.hatype >> 8); packet_data[3] = (u8)from.hatype;
            packet_data[4] = 0; packet_data[5] = from.halen > 8 ? 8 : from.halen;
            pt_memset(packet_data + 6, 0, 8);
            pt_memcpy(packet_data + 6, from.addr, packet_data[5]);
            pt_memcpy(packet_data + 14, &from.protocol, 2);
        }
        r = pt_ioctl(fd, PT_SIOCGSTAMP, &now);
        if (r < 0) r = pt_time(&now);
        if (r < 0) { status = syserror("packet timestamp", r); break; }
        if (now.sec < 0 || (u64)now.sec > 0xffffffffU || now.usec < 0 || now.usec >= 1000000) {
            status = error("timestamp outside classic PCAP range"); break;
        }
        if (process((u32)now.sec, (u32)now.usec, caplen, wirelen, link)) { status = 1; break; }
    }
    collect_stats(fd);
done:
    /* Closing the socket also releases its promiscuous membership. */
    pt_close(fd);
    return status;
}
#else
static int macos_ready(const char *interface, u32 link)
{
    if (begin_output(link, PT_MAX_PACKET)) return 1;
    message("pktide: listening on "); message(interface);
    message(" (macOS BPF), Ctrl-C to stop\n");
    return 0;
}
static int macos_packet(const u8 *data, u32 cap, u32 wire, u32 sec, u32 usec, u32 link)
{
    pt_memcpy(packet_data, data, cap);
    if (process(sec, usec, cap, wire, link)) return -1;
    return opt.count && matched >= opt.count ? 1 : 0;
}
static int capture(void)
{
    struct pt_macos_options config;
    struct pt_macos_stats stats;
    int result;
    config.interface = opt.interface; config.buffer_kib = opt.buffer_kib;
    config.promiscuous = opt.promiscuous;
    result = pt_macos_capture(&config, macos_ready, macos_packet, &stats);
    kernel_packets = stats.packets; kernel_drops = stats.drops; stats_available = stats.available;
    return result;
}
#endif

static void statistics(void)
{
    struct text t = {{0}, 0};
    text_str(&t, "pktide: seen="); text_num(&t, seen, 0);
    text_str(&t, " matched="); text_num(&t, matched, 0);
    text_str(&t, " matched_bytes="); text_num(&t, bytes, 0);
    if (stats_available) {
#ifdef __APPLE__
        text_str(&t, " bpf_packets="); text_num(&t, kernel_packets, 0);
        text_str(&t, " bpf_drops="); text_num(&t, kernel_drops, 0);
#else
        text_str(&t, " socket_packets="); text_num(&t, kernel_packets, 0);
        text_str(&t, " socket_drops="); text_num(&t, kernel_drops, 0);
#endif
    }
    text_char(&t, '\n'); (void)pt_writeall(2, t.data, t.len);
}

int pt_main(int argc, char **argv)
{
    int status, result;
    result = options(argc, argv);
    if (result != 0) return result < 0 ? 2 : 0;
    if (opt.list) return list_interfaces();
    if (pt_signal(2, stop_handler) < 0 || pt_signal(15, stop_handler) < 0 ||
        pt_signal(13, (void (*)(int))1) < 0) return error("install signal handlers failed");
    status = opt.input ? read_pcap() : capture();
    if (output_fd > 2 && pt_close(output_fd) < 0) status = error("close PCAP output failed");
    statistics();
    return status;
}
#ifndef __APPLE__
void pt_start(unsigned long *stack)
{
    pt_exit(pt_main((int)stack[0], (char **)(stack + 1)));
}
#endif
