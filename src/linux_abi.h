#ifndef PKTIDE_LINUX_ABI_H
#define PKTIDE_LINUX_ABI_H
#include "core.h"

/* Oldest validated kernel family; exact vendor builds are in docs/VALIDATION.md. */
#define PT_LINUX_MIN "2.4.21"

#if defined(__x86_64__) && !defined(__ILP32__)
#define PT_ARCH "x86_64"
#define NR_read 0
#define NR_write 1
#define NR_open 2
#define NR_close 3
#define NR_poll 7
#define NR_sigaction 13
#define NR_ioctl 16
#define NR_socket 41
#define NR_recvfrom 45
#define NR_bind 49
#define NR_setsockopt 54
#define NR_getsockopt 55
#define NR_exit 60
#define NR_gettimeofday 96
#elif defined(__i386__)
#define PT_ARCH "i386"
#define NR_exit 1
#define NR_read 3
#define NR_write 4
#define NR_open 5
#define NR_close 6
#define NR_ioctl 54
#define NR_gettimeofday 78
#define NR_socketcall 102
#define NR_poll 168
#define NR_sigaction 174
#else
#error "Supported Linux ABIs: x86_64 (LP64) and i386"
#endif

#define PT_EINTR 4
#define PT_OPEN_NEW (1 | 64 | 128)
#define PT_EAGAIN 11
#define PT_AF_PACKET 17
#define PT_SOCK_RAW 3
#define PT_SOCK_DGRAM 2
#define PT_SOL_PACKET 263
#define PT_PACKET_ADD_MEMBERSHIP 1
#define PT_PACKET_STATISTICS 6
#define PT_MSG_TRUNC 0x20
#define PT_SIOCGIFINDEX 0x8933
#define PT_SIOCGIFHWADDR 0x8927
#define PT_SIOCGSTAMP 0x8906

struct pt_sockaddr_ll {
    u16 family, protocol;
    int ifindex;
    u16 hatype;
    u8 pkttype, halen, addr[8];
};
struct pt_packet_mreq { int ifindex; u16 type, alen; u8 address[8]; };
struct pt_pollfd { int fd; short events, revents; };
struct pt_timeval { long sec, usec; };
struct pt_ifreq {
    char name[16];
    union { int index; struct { u16 family; u8 address[14]; } hw;
            unsigned long alignment; u8 storage[sizeof(long) == 8 ? 24 : 16]; } u;
};
struct pt_packet_stats { u32 packets, drops; };

long pt_call(long nr, long a, long b, long c, long d, long e, long f);
void pt_sigreturn(void);
void pt_exit(int status) __attribute__((noreturn));
long pt_read(int fd, void *buf, usize n);
long pt_write(int fd, const void *buf, usize n);
long pt_open(const char *path, int flags, unsigned mode);
long pt_close(int fd);
long pt_ioctl(int fd, unsigned long request, void *arg);
long pt_socket(int type);
long pt_bind(int fd, const struct pt_sockaddr_ll *addr);
long pt_recv(int fd, void *buf, usize n, struct pt_sockaddr_ll *addr);
long pt_sockopt(int fd, int level, int option, void *value, u32 length, int get);
long pt_poll(struct pt_pollfd *p, int timeout);
long pt_time(struct pt_timeval *tv);
long pt_signal(int sig, void (*handler)(int));
int pt_writeall(int fd, const void *buf, usize n);
int pt_readfull(int fd, void *buf, usize n); /* 1 success, 0 clean EOF, -1 partial/error */
extern volatile int pt_stopped;
#endif
