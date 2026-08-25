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
 * Probe CORE subsystem ioctls to find CREATE_CONTEXT and GET_API_VERSION.
 * Core subsystem base = 0x82
 */

#define MALI_IOC_CORE_BASE 0x82

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))
#define _IOR(type, nr, size) \
    (((2) << 30) | ((size) << 16) | ((type) << 8) | (nr))
#define _IOW(type, nr, size) \
    (((1) << 30) | ((size) << 16) | ((type) << 8) | (nr))

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

    printf("[*] Mali CORE subsystem ioctl probe\n");
    printf("[*] base=0x82, scanning nr 0-31 with various sizes\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    printf("fd=%d\n\n", fd);

    /* Test each ioctl number with multiple sizes */
    printf("%-4s  ", "NR");
    for (int sz = 4; sz <= 64; sz *= 2) printf("sz=%-3d ", sz);
    printf("\n");
    printf("-----");
    for (int sz = 4; sz <= 64; sz *= 2) printf("--------");
    printf("\n");

    for (int nr = 0; nr < 32; nr++) {
        printf("%3d: ", nr);
        for (int sz = 4; sz <= 64; sz *= 2) {
            uint8_t buf[256];
            memset(buf, 0, sizeof(buf));

            unsigned int cmd = _IOWR(MALI_IOC_CORE_BASE, nr, sz);
            int r = tio(fd, cmd, buf, 2);

            if (r == -999) {
                printf("TIMEOUT  ");
                break;
            } else if (r == 0) {
                /* Check if output has non-zero data */
                int nz = 0;
                for (int i = 0; i < sz; i++) if (buf[i]) { nz = 1; break; }
                if (nz) printf("OK+DATA  ");
                else printf("OK+ZERO  ");
            } else if (r == -ENOTTY) {
                printf("ENOTTY   ");
            } else if (r == -EINVAL) {
                printf("EINVAL   ");
            } else {
                printf("err=%-4d ", -r);
            }
        }
        printf("\n");
    }

    close(fd);
    printf("\ndone\n");
    return 0;
}
