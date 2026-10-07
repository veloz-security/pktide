/* Minimal test-only PID 1. Boot a real legacy kernel, without a modern libc. */
#include "linux_abi.h"

#if defined(__x86_64__)
#define V_fork 57
#define V_execve 59
#define V_wait4 61
#define V_kill 62
#define V_mount 165
#define V_reboot 169
#define V_init_module 175
#define V_nanosleep 35
#define V_uname 63
#define V_sigprocmask 14
#else
#define V_fork 2
#define V_execve 11
#define V_wait4 114
#define V_kill 37
#define V_mount 21
#define V_reboot 88
#define V_init_module 128
#define V_nanosleep 162
#define V_uname 122
#define V_sigprocmask 175
#endif

static int failures;
static u8 module_data[1024 * 1024];

static void say(const char *s) { (void)pt_writeall(1, s, pt_strlen(s)); }
static void check(const char *name, int success)
{
    say(success ? "VM PASS: " : "VM FAIL: "); say(name); say("\n");
    if (!success) failures++;
}
static void pause_ms(long ms)
{
    struct { long sec, nsec; } t;
    t.sec = ms / 1000; t.nsec = (ms % 1000) * 1000000;
    pt_call(V_nanosleep, (long)&t, 0, 0, 0, 0, 0);
}
static long spawn(char **argv)
{
    long pid = pt_call(V_fork, 0, 0, 0, 0, 0, 0);
    if (!pid) {
        char *env[] = {0};
        pt_call(V_execve, (long)argv[0], (long)argv, (long)env, 0, 0, 0);
        pt_exit(127);
    }
    return pid;
}
static int wait_child(long pid)
{
    int status = -1;
    unsigned i;
    if (pid < 0) return 0;
    for (i = 0; i < 100; i++) {
        long r = pt_call(V_wait4, pid, (long)&status, 1, 0, 0, 0); /* WNOHANG */
        if (r == pid) {
            if (status != 0) {
                struct text t = {{0}, 0};
                text_str(&t, "VM child wait status: "); text_num(&t, (u32)status, 0);
                text_char(&t, '\n'); (void)pt_writeall(1, t.data, t.len);
            }
            return status == 0;
        }
        if (r < 0) return 0;
        pause_ms(100);
    }
    pt_call(V_kill, pid, 9, 0, 0, 0, 0);
    pt_call(V_wait4, pid, (long)&status, 0, 0, 0, 0);
    return 0;
}
static void module(const char *path)
{
    usize total = 0;
    long fd = pt_open(path, 0, 0), r;
    if (fd < 0) return; /* Built-in on some kernels. */
    while (total < sizeof(module_data)) {
        r = pt_read((int)fd, module_data + total, sizeof(module_data) - total);
        if (r <= 0) break;
        total += (usize)r;
    }
    pt_close((int)fd);
    r = pt_call(V_init_module, (long)module_data, (long)total, (long)"", 0, 0, 0);
    if (r < 0) { say("VM module load failed: "); say(path); say("\n"); }
}
static long udp_socket(void)
{
#ifdef NR_socketcall
    unsigned long a[] = {2, 2, 0};
    return pt_call(NR_socketcall, 1, (long)a, 0, 0, 0, 0);
#else
    return pt_call(NR_socket, 2, 2, 0, 0, 0, 0);
#endif
}
static void send_udp(void)
{
    struct { u16 family; u8 port[2], ip[4], pad[8]; } a;
    long fd = udp_socket(), result;
    pt_memset(&a, 0, sizeof(a)); a.family = 2;
    a.port[0] = 0xaf; a.port[1] = 0xc8; /* 45000 */
    a.ip[0] = 127; a.ip[3] = 1;
#ifdef NR_socketcall
    {
        unsigned long args[] = {(unsigned long)fd, (unsigned long)"legacy-test", 11, 0,
                                (unsigned long)&a, sizeof(a)};
        result = pt_call(NR_socketcall, 11, (long)args, 0, 0, 0, 0);
    }
#else
    result = pt_call(44, fd, (long)"legacy-test", 11, 0, (long)&a, sizeof(a));
#endif
    check("send loopback UDP", result == 11);
    pt_close((int)fd);
}

void pt_start(unsigned long *stack)
{
    long fd, pid;
    struct pt_ifreq req;
    u64 empty_mask = 0;
    char uts[6][65];
    char *version[] = {"/pktide", "--version", 0};
    char *offline[] = {"/pktide", "-r", "/fixture.pcap", "tcp port 443", 0};
    char *capture[] = {"/pktide", "-i", "lo", "-c", "1", "-w", "/capture.pcap", "udp dst port 45000", 0};
    char *replay[] = {"/pktide", "-r", "/capture.pcap", "udp dst port 45000", 0};
    char *any[] = {"/pktide", "-i", "any", "-c", "1", "-w", "/any.pcap", "udp dst port 45000", 0};
    char *stop[] = {"/pktide", "-i", "lo", "-q", "-w", "/stopped.pcap", "tcp port 9", 0};
    (void)stack;
    /* Kernel-created PID 1 inherits blocked signals; a normal init/shell clears them. */
    pt_call(V_sigprocmask, 2, (long)&empty_mask, 0, 8, 0, 0);
    pt_call(V_mount, (long)"proc", (long)"/proc", (long)"proc", 0, 0, 0);
    pt_memset(uts, 0, sizeof(uts));
    if (pt_call(V_uname, (long)uts, 0, 0, 0, 0, 0) == 0) {
        say("VM kernel: "); say(uts[2]); say(" arch: "); say(uts[4]); say("\n");
    }
    module("/af_packet.ko");
    fd = udp_socket();
    pt_memset(&req, 0, sizeof(req)); pt_memcpy(req.name, "lo", 3);
    req.u.hw.family = 2;
    req.u.hw.address[2] = 127; req.u.hw.address[5] = 1;
    check("assign loopback IPv4 address", fd >= 0 && pt_ioctl((int)fd, 0x8916, &req) >= 0);
    pt_memset(&req.u, 0, sizeof(req.u));
    req.u.hw.family = 2; req.u.hw.address[2] = 255;
    check("assign loopback netmask", fd >= 0 && pt_ioctl((int)fd, 0x891c, &req) >= 0);
    pt_memset(&req.u, 0, sizeof(req.u));
    req.u.hw.family = 0x49; /* IFF_UP | IFF_LOOPBACK | IFF_RUNNING */
    check("bring loopback up", fd >= 0 && pt_ioctl((int)fd, 0x8914, &req) >= 0);
    pt_close((int)fd);
    check("version", wait_child(spawn(version)));
    check("PCAP filter replay", wait_child(spawn(offline)));
    pid = spawn(capture); pause_ms(500); send_udp();
    check("live loopback Ethernet capture", wait_child(pid));
    check("live PCAP replay", wait_child(spawn(replay)));
    pid = spawn(any); pause_ms(500); send_udp();
    check("live any/SLL capture", wait_child(pid));
    pid = spawn(stop); pause_ms(500);
    if (pid > 0) pt_call(V_kill, pid, 2, 0, 0, 0, 0);
    check("SIGINT cleanup", wait_child(pid));
    stop[5] = "/term.pcap";
    pid = spawn(stop); pause_ms(500);
    if (pid > 0) pt_call(V_kill, pid, 15, 0, 0, 0, 0);
    check("SIGTERM cleanup", wait_child(pid));
    say(failures ? "PKTIDE_VM_FAILURE\n" : "PKTIDE_VM_SUCCESS\n");
    pt_call(V_reboot, (long)0xfee1deadU, 672274793, 0x01234567, 0, 0, 0);
    for (;;) pause_ms(1000);
}
