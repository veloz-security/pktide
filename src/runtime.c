#include "linux_abi.h"

volatile int pt_stopped;

void pt_exit(int status)
{
    pt_call(NR_exit, status, 0, 0, 0, 0, 0);
    for (;;) { }
}
long pt_read(int fd, void *buf, usize n) { return pt_call(NR_read, fd, (long)buf, (long)n, 0, 0, 0); }
long pt_write(int fd, const void *buf, usize n) { return pt_call(NR_write, fd, (long)buf, (long)n, 0, 0, 0); }
long pt_open(const char *path, int flags, unsigned mode)
{
    return pt_call(NR_open, (long)path, flags | 0100000, (long)mode, 0, 0, 0);
}
long pt_close(int fd) { return pt_call(NR_close, fd, 0, 0, 0, 0, 0); }
long pt_ioctl(int fd, unsigned long req, void *arg) { return pt_call(NR_ioctl, fd, (long)req, (long)arg, 0, 0, 0); }

long pt_socket(int type)
{
    /* Protocol zero until bind: no traffic from other interfaces can be queued. */
#ifdef NR_socketcall
    unsigned long a[3] = { PT_AF_PACKET, (unsigned long)type, 0 };
    return pt_call(NR_socketcall, 1, (long)a, 0, 0, 0, 0);
#else
    return pt_call(NR_socket, PT_AF_PACKET, type, 0, 0, 0, 0);
#endif
}
long pt_bind(int fd, const struct pt_sockaddr_ll *addr)
{
#ifdef NR_socketcall
    unsigned long a[3] = { (unsigned long)fd, (unsigned long)addr, sizeof(*addr) };
    return pt_call(NR_socketcall, 2, (long)a, 0, 0, 0, 0);
#else
    return pt_call(NR_bind, fd, (long)addr, sizeof(*addr), 0, 0, 0);
#endif
}
long pt_recv(int fd, void *buf, usize n, struct pt_sockaddr_ll *addr)
{
    u32 len = sizeof(*addr);
#ifdef NR_socketcall
    unsigned long a[6] = { (unsigned long)fd, (unsigned long)buf, n, PT_MSG_TRUNC,
                           (unsigned long)addr, (unsigned long)&len };
    return pt_call(NR_socketcall, 12, (long)a, 0, 0, 0, 0);
#else
    return pt_call(NR_recvfrom, fd, (long)buf, (long)n, PT_MSG_TRUNC, (long)addr, (long)&len);
#endif
}
long pt_sockopt(int fd, int level, int option, void *value, u32 length, int get)
{
#ifdef NR_socketcall
    unsigned long a[5] = { (unsigned long)fd, (unsigned long)level, (unsigned long)option,
                          (unsigned long)value, get ? (unsigned long)&length : length };
    return pt_call(NR_socketcall, get ? 15 : 14, (long)a, 0, 0, 0, 0);
#else
    return pt_call(get ? NR_getsockopt : NR_setsockopt, fd, level, option, (long)value,
                   get ? (long)&length : (long)length, 0);
#endif
}
long pt_poll(struct pt_pollfd *p, int timeout) { return pt_call(NR_poll, (long)p, 1, timeout, 0, 0, 0); }
long pt_time(struct pt_timeval *tv) { return pt_call(NR_gettimeofday, (long)tv, 0, 0, 0, 0, 0); }
long pt_signal(int sig, void (*handler)(int))
{
    struct kernel_action {
        void (*handler)(int);
        unsigned long flags;
        void (*restorer)(void);
        u64 mask;
    } a;
    pt_memset(&a, 0, sizeof(a));
    a.handler = handler; a.flags = 0x04000000UL; a.restorer = pt_sigreturn;
    return pt_call(NR_sigaction, sig, (long)&a, 0, 8, 0, 0);
}
int pt_writeall(int fd, const void *buf, usize n)
{
    const u8 *p = buf;
    while (n) {
        long r = pt_write(fd, p, n);
        if (r == -PT_EINTR) continue;
        if (r <= 0) return 0;
        p += r; n -= (usize)r;
    }
    return 1;
}
int pt_readfull(int fd, void *buf, usize n)
{
    u8 *p = buf;
    usize have = 0;
    while (have < n) {
        long r = pt_read(fd, p + have, n - have);
        if (r == -PT_EINTR && !pt_stopped) continue;
        if (!r) return have ? -1 : 0;
        if (r < 0) return -1;
        have += (usize)r;
    }
    return 1;
}

/* Compiler-emitted struct copies may use these even in a freestanding build. */
void *memcpy(void *d, const void *s, usize n) { return pt_memcpy(d, s, n); }
void *memset(void *d, int c, usize n) { return pt_memset(d, c, n); }
