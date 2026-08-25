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
 * ALLOC_MEM returns success but all zeros.
 * We need to find which input fields control allocation.
 * Test: put 0x1000 at every 4-byte offset, see if output changes.
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

int main() {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("ALLOC_MEM input offset probe (size=40)\n");
    printf("Put 0x1000 at each offset, check if output changes\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    printf("fd=%d\n\n", fd);

    printf("%-6s  %-6s  %s\n", "IN_OFF", "OUT_OFF", "Output values (first 40 bytes)");
    printf("-----------------------------------------------------------\n");

    for (int in_off = 0; in_off <= 36; in_off += 4) {
        uint8_t buf[64];
        memset(buf, 0, sizeof(buf));

        /* Put 0x1000 at this input offset */
        *(uint32_t *)(buf + in_off) = 0x1000;

        int r = tio(fd, _IOWR(0x83, 0, 40), buf, 3);
        if (r == -999) {
            printf("off=%2d: TIMEOUT\n", in_off);
            break;
        }
        if (r != 0) {
            printf("off=%2d: FAILED err=%d\n", in_off, -r);
            continue;
        }

        /* Check if output has non-zero values */
        int nonzero = 0;
        for (int i = 0; i < 40; i++) {
            if (buf[i] != 0) { nonzero = 1; break; }
        }

        if (!nonzero) {
            printf("off=%2d: all zeros\n", in_off);
        } else {
            printf("off=%2d: ", in_off);
            for (int i = 0; i < 40; i++) {
                if (i % 8 == 0 && i > 0) printf(" ");
                printf("%02x", buf[i]);
            }
            printf("\n");

            /* Interpret as uint32 fields */
            printf("        ");
            for (int i = 0; i < 40; i += 4) {
                uint32_t v = *(uint32_t *)(buf + i);
                if (v != 0) printf(" [%d]=0x%x", i/4, v);
            }
            printf("\n");
        }
    }

    close(fd);
    printf("\ndone\n");
    return 0;
}
