#ifndef PKTIDE_MACOS_H
#define PKTIDE_MACOS_H

#include "core.h"
#include <errno.h>
#include <fcntl.h>

#if defined(__arm64__) || defined(__aarch64__)
#define PT_ARCH "arm64"
#elif defined(__x86_64__)
#define PT_ARCH "x86_64"
#else
#error "Supported macOS architectures: arm64 and x86_64"
#endif

#define PT_EINTR EINTR
#define PT_OPEN_NEW (O_WRONLY | O_CREAT | O_EXCL)

long pt_read(int fd, void *buf, usize n);
long pt_write(int fd, const void *buf, usize n);
long pt_open(const char *path, int flags, unsigned mode);
long pt_close(int fd);
long pt_signal(int sig, void (*handler)(int));
int pt_writeall(int fd, const void *buf, usize n);
int pt_readfull(int fd, void *buf, usize n);
extern volatile int pt_stopped;
int pt_main(int argc, char **argv);

struct pt_macos_options {
    const char *interface;
    u32 buffer_kib;
    int promiscuous;
};
struct pt_macos_stats { u64 packets, drops; int available; };

/* ready: 0 = success. packet: 0 = continue, 1 = stop, -1 = error. */
typedef int (*pt_macos_ready_fn)(const char *interface, u32 link);
typedef int (*pt_macos_packet_fn)(const u8 *data, u32 cap, u32 wire,
                                u32 sec, u32 usec, u32 link);
int pt_macos_list(void);
int pt_macos_capture(const struct pt_macos_options *opt, pt_macos_ready_fn ready,
                     pt_macos_packet_fn packet, struct pt_macos_stats *stats);
int pt_macos_bpf_batch(const u8 *data, usize size, u32 link, pt_macos_packet_fn packet);
int pt_macos_linktype(unsigned dlt, u32 *link);
#endif
