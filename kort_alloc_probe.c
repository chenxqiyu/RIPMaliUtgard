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
 * Systematic ALLOC_MEM field probing.
 * We know ALLOC_MEM works with size=40 bytes.
 * Test each 4-byte slot as potential "size" input by putting 0x1000 there,
 * and see if we get non-zero output (gpu_vaddr, etc).
 */

#define MALI_IOC_MEMORY_BASE 0x80
#define _MALI_UK_ALLOC_MEM 5

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

static void dump_u32(const uint8_t *buf, int len) {
    for (int i = 0; i < len; i += 4) {
        uint32_t v = *(uint32_t *)(buf + i);
        if (v != 0) printf("  off%d: 0x%08x", i, v);
    }
    printf("\n");
}

int main() {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] ALLOC_MEM field probing (size=40)\n");
    printf("[*] Putting 0x1000 at each 4-byte offset, checking output\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    printf("Offset | Result | Non-zero output fields\n");
    printf("-------+--------+----------------------\n");

    for (int off = 0; off < 40; off += 4) {
        uint8_t buf[64];
        memset(buf, 0, sizeof(buf));

        /* Put 0x1000 at this offset as potential size input */
        *(uint32_t *)(buf + off) = 0x1000;

        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, 40);
        int r = tio(fd, cmd, buf, 3);

        printf("  %2d   | ", off);
        if (r == -999) { printf("TIMEOUT\n"); continue; }
        if (r != 0) { printf("err=%-3d |\n", -r); continue; }

        /* Check which output fields are non-zero */
        int nz = 0;
        printf("OK     | ");
        for (int i = 0; i < 40; i += 4) {
            uint32_t v = *(uint32_t *)(buf + i);
            if (v != 0 && v != 0x1000) { /* skip our input */
                printf("off%d=0x%08x ", i, v);
                nz++;
            }
        }
        if (nz == 0) printf("(all zero except input)");
        printf("\n");
    }

    /* Also test: what if we put size at offset 8 AND offset 12 (both psize and vsize)? */
    printf("\n=== Double-size test (both psize and vsize) ===\n");
    {
        uint8_t buf[64];
        memset(buf, 0, sizeof(buf));
        *(uint32_t *)(buf + 8) = 0x1000;   /* psize */
        *(uint32_t *)(buf + 12) = 0x1000;  /* vsize */
        *(uint32_t *)(buf + 16) = 0x1;     /* flags? */

        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, 40);
        int r = tio(fd, cmd, buf, 3);
        printf("  result: %s\n", r == 0 ? "OK" : (r == -999 ? "TIMEOUT" : "error"));
        if (r == 0) {
            printf("  output: ");
            for (int i = 0; i < 40; i += 4) {
                uint32_t v = *(uint32_t *)(buf + i);
                printf("0x%08x ", v);
            }
            printf("\n");
        }
    }

    close(fd);
    printf("\ndone\n");
    return 0;
}
