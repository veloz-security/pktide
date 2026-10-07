#include "macos.h"
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

volatile int pt_stopped;

long pt_read(int fd, void *buf, usize n)
{
    ssize_t r = read(fd, buf, n);
    return r < 0 ? -errno : (long)r;
}
long pt_write(int fd, const void *buf, usize n)
{
    ssize_t r = write(fd, buf, n);
    return r < 0 ? -errno : (long)r;
}
long pt_open(const char *path, int flags, unsigned mode)
{
    int fd = open(path, flags, (mode_t)mode);
    return fd < 0 ? -errno : fd;
}
long pt_close(int fd) { return close(fd) < 0 ? -errno : 0; }
long pt_signal(int sig, void (*handler)(int))
{
    struct sigaction action;
    pt_memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    /* No SA_RESTART: a stop signal must interrupt a pending capture read. */
    return sigaction(sig, &action, 0) < 0 ? -errno : 0;
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
int main(int argc, char **argv) { return pt_main(argc, argv); }
