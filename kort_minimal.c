#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>

/*
 * Minimal probe - test CORE subsystem ioctls first
 * These are simpler and less likely to hang
 *
 * Known: ALLOC_MEM = _IOWR(0x83, 0, 40) = 0xc0288300
 * But ALLOC_MEM hangs if ctx/vaddr is not set correctly?
 *
 * Let's test GET_API_VERSION (core nr=0) which is read-only and should never hang.
 */

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))

#define _IOR(type, nr, size) \
    (((2) << 30) | ((size) << 16) | ((type) << 8) | (nr))

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

    printf("[1] start\n");

    int fd = open("/dev/mali", O_RDWR);
    printf("[2] open fd=%d err=%d\n", fd, errno);
    if (fd < 0) return 1;

    /* Test GET_API_VERSION - should be safe, read-only
     * type=0x82 (core base), nr=0 */
    printf("[3] test GET_API_VERSION (type=0x82, nr=0)...\n");

    /* Try different sizes for version query */
    for (int sz = 4; sz <= 32; sz += 4) {
        uint32_t val = 0xDEADBEEF;
        int r = tio(fd, _IOR(0x82, 0, sz), &val, 2);
        if (r == -999) {
            printf("  sz=%2d: TIMEOUT\n", sz);
            break;
        }
        if (r == 0) {
            printf("  sz=%2d: OK val=0x%08x\n", sz, val);
        } else if (r == -ENOTTY) {
            printf("  sz=%2d: ENOTTY\n", sz);
        } else {
            printf("  sz=%2d: err=%d val=0x%08x\n", sz, -r, val);
        }
    }

    /* Test ALLOC_MEM with zeroed buffer */
    printf("[4] test ALLOC_MEM (type=0x83, nr=0, size=40)...\n");
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    int r = tio(fd, _IOWR(0x83, 0, 40), buf, 3);
    if (r == -999) printf("  TIMEOUT\n");
    else if (r == 0) {
        printf("  SUCCESS!\n");
        for (int i = 0; i < 40; i++) {
            if (i % 16 == 0) printf("  %02x: ", i);
            printf("%02x ", buf[i]);
            if (i % 16 == 15) printf("\n");
        }
    } else printf("  err=%d\n", -r);

    close(fd);
    printf("[5] done\n");
    return 0;
}
