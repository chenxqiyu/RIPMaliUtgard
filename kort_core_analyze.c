#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>

/* Examine the output data of found CORE ioctls */

#define MALI_IOC_CORE_BASE 0x82

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

static void dump_hex(const uint8_t *buf, int len) {
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %02x: ", i);
        printf("%02x ", buf[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

int main() {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] CORE ioctl output analysis\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    /* Test each interesting ioctl with its correct size, with different inputs */
    struct {
        int nr;
        int sz;
        const char *desc;
    } tests[] = {
        {3, 4,  "nr=3 sz=4 (maybe version?)"},
        {3, 16, "nr=3 sz=16 (has data)"},
        {4, 16, "nr=4 sz=16"},
        {8, 16, "nr=8 sz=16"},
        {9, 32, "nr=9 sz=32 (has data)"},
        {10, 32, "nr=10 sz=32 (has data)"},
        {13, 8, "nr=13 sz=8 (ctx create?)"},
    };

    for (int t = 0; t < 7; t++) {
        printf("=== %s ===\n", tests[t].desc);

        uint8_t buf[256];
        memset(buf, 0xA5, sizeof(buf)); /* fill with pattern */

        unsigned int cmd = _IOWR(MALI_IOC_CORE_BASE, tests[t].nr, tests[t].sz);
        int r = tio(fd, cmd, buf, 2);

        if (r == -999) {
            printf("  TIMEOUT\n\n");
            continue;
        }

        printf("  ret=%d (errno=%d)\n", r, r == 0 ? 0 : -r);
        printf("  Output (%d bytes):\n", tests[t].sz);
        dump_hex(buf, tests[t].sz);

        /* Print as uint32 array */
        printf("  As uint32:");
        for (int i = 0; i < tests[t].sz; i += 4) {
            uint32_t v = *(uint32_t *)(buf + i);
            printf(" 0x%08x", v);
        }
        printf("\n\n");
    }

    /* Now test if nr=13 creates a context - call it twice */
    printf("=== Context creation test (nr=13 sz=8) ===\n");
    {
        uint64_t ctx1 = 0, ctx2 = 0;
        int r1 = tio(fd, _IOWR(MALI_IOC_CORE_BASE, 13, 8), &ctx1, 2);
        int r2 = tio(fd, _IOWR(MALI_IOC_CORE_BASE, 13, 8), &ctx2, 2);
        printf("  Call 1: ret=%d ctx=0x%016llx\n", r1, (unsigned long long)ctx1);
        printf("  Call 2: ret=%d ctx=0x%016llx\n", r2, (unsigned long long)ctx2);
        if (r1 == 0 && r2 == 0 && ctx1 != 0 && ctx2 != 0 && ctx1 != ctx2)
            printf("  [+] Different values each call - likely context creation!\n");
    }

    close(fd);
    printf("\ndone\n");
    return 0;
}
