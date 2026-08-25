#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/*
 * Find where ALLOC_MEM output fields are.
 * Test with larger struct sizes and look for modified words.
 * Also test if this really is ALLOC_MEM by trying mmap.
 */

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

static void test_size(int fd, int sz, uint32_t cmd_base_type, int nr) {
    uint8_t buf[256];
    memset(buf, 0xAA, sizeof(buf));

    /* Put input at expected positions */
    *(uint32_t *)(buf + 8)  = 0x40000000;
    *(uint32_t *)(buf + 12) = 0x4000;
    *(uint32_t *)(buf + 16) = 0x4000;

    unsigned int cmd = _IOWR(cmd_base_type, nr, sz);
    int r = tio(fd, cmd, buf, 3);

    printf("  size=%3d: %s", sz,
           r == 0 ? "OK     " : (r == -999 ? "TIMEOUT" : "err"));
    if (r < 0 && r != -999) printf("=%-3d", -r);
    printf(" | ");

    if (r == 0) {
        int found = 0;
        for (int i = 0; i < sz; i += 4) {
            uint32_t v = *(uint32_t *)(buf + i);
            if (v != 0xAAAAAAAA &&
                v != 0x40000000 && v != 0x00004000) {
                printf("off%d=0x%08x ", i, v);
                found = 1;
            }
        }
        if (!found) printf("(only input words changed)");
    }
    printf("\n");
}

int main() {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] ALLOC_MEM output field search\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    printf("[+] fd=%d\n\n", fd);

    /* Test type=0x80 vs type=0x83 with various sizes */
    int types[] = {0x80, 0x83};
    for (int t = 0; t < 2; t++) {
        printf("=== type=0x%02x, nr=0 ===\n", types[t]);
        int sizes[] = {24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 72, 80, 96, 128};
        for (int i = 0; i < 15; i++) {
            test_size(fd, sizes[i], types[t], 0);
        }
        printf("\n");
    }

    /* Also test: can we mmap at 0x40000000? If yes, memory was allocated. */
    printf("=== mmap test ===\n");
    {
        /* First allocate */
        uint8_t buf[64];
        memset(buf, 0, sizeof(buf));
        *(uint32_t *)(buf + 8)  = 0x40000000;
        *(uint32_t *)(buf + 12) = 0x4000;
        *(uint32_t *)(buf + 16) = 0x4000;

        unsigned int cmd = _IOWR(0x83, 0, 40); /* type=0x83, nr=0, size=40 */
        int r = tio(fd, cmd, buf, 3);
        printf("  ALLOC (type=0x83, size=40): %s\n", r == 0 ? "OK" : "FAIL");

        if (r == 0) {
            void *p = mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0x40000000);
            if (p != MAP_FAILED) {
                printf("  [+] mmap at offset 0x40000000 OK: %p\n", p);
                memset(p, 0x42, 0x4000);
                __builtin___clear_cache(p, (char*)p+0x4000);
                printf("  [+] first word = 0x%08x (should be 0x42424242)\n", *(uint32_t *)p);
                munmap(p, 0x4000);
            } else {
                printf("  [-] mmap failed: %s\n", strerror(errno));
            }

            /* Also try mmap at offset 0 */
            void *p0 = mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
            if (p0 != MAP_FAILED) {
                printf("  [+] mmap at offset 0 OK: %p, first=0x%08x\n", p0, *(uint32_t *)p0);
                munmap(p0, 0x4000);
            } else {
                printf("  [-] mmap offset 0 failed: %s\n", strerror(errno));
            }
        }
    }

    close(fd);
    printf("\ndone\n");
    return 0;
}
