#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>

/* Fine scan around 408 to find exact PP_START_JOB size */

#define MALI_IOC_BASE 0x82
#define _MALI_UK_PP_SUBSYSTEM 2
#define MALI_IOC_PP_BASE (_MALI_UK_PP_SUBSYSTEM + MALI_IOC_BASE)
#define _MALI_UK_PP_START_JOB 0

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))

static volatile int g_to = 0;
static void alh(int s) { g_to = 1; }

static int tio(int fd, unsigned int cmd, void *buf, int t) {
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno;
    alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

int main() {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] PP_START_JOB fine scan (size 392-424, step 4)\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    printf("%-6s  %-10s  %-8s  %s\n", "SIZE", "IOC", "ERRNO", "STATUS");
    printf("------------------------------------------\n");

    int best = -1;
    for (int sz = 392; sz <= 424; sz += 4) {
        uint8_t buf[1024];
        memset(buf, 0, sizeof(buf));
        /* Try with a non-zero priority at offset 16 to see if it changes error */
        *(uint32_t *)(buf + 16) = 128; /* priority guess */

        unsigned int cmd = _IOWR(MALI_IOC_PP_BASE, _MALI_UK_PP_START_JOB, sz);
        int r = tio(fd, cmd, buf, 3);

        const char *s = "ENOTTY";
        if (r == -999) s = "TIMEOUT";
        else if (r == 0) s = "SUCCESS";
        else if (r != -ENOTTY) s = "EXISTS";

        printf("  %4d  0x%08x  %-8d  %s\n", sz, cmd, r == -999 ? 999 : -r, s);

        if (r == -999) { close(fd); return 1; }
        if (r != -ENOTTY && best < 0) best = sz;
    }

    printf("\nBest guess: %d bytes\n", best);

    /* Also test GET_VERSION to see if core subsystem works */
    printf("\n--- CORE subsystem tests ---\n");
    printf("Testing GET_API_VERSION (core nr=0):\n");
    for (int sz = 4; sz <= 32; sz += 4) {
        uint32_t val = 0;
        int r = tio(fd, _IOWR(0x82, 0, sz), &val, 2);
        if (r != -ENOTTY) {
            printf("  size=%d: err=%d val=0x%x\n", sz, r == -999 ? 999 : -r, val);
        }
        if (r == -999) break;
    }

    close(fd);
    return 0;
}
