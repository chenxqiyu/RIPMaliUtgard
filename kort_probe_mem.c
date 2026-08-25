#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

/*
 * Safe probe: only MEMORY subsystem ioctls.
 * Mi Box S confirmed: ALLOC_MEM = _IOWR(0x83, 0, 40) = 0xc0288300
 */

#define MALI_IOC_BASE 0x82
#define _MALI_UK_MEMORY_SUBSYSTEM 1
#define MALI_IOC_MEMORY_BASE (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE) /* 0x83 */

#define _MALI_UK_ALLOC_MEM  0
#define _MALI_UK_FREE_MEM   1
#define _MALI_UK_BIND_MEM   2
#define _MALI_UK_UNBIND_MEM 3

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))

static int test_ioctl(int fd, unsigned int cmd, void *buf) {
    int ret = ioctl(fd, cmd, buf);
    int err = errno;
    if (ret == 0) return 1;       /* Success */
    if (err != ENOTTY) return 2;  /* Exists but other error */
    return 0;                     /* ENOTTY = not a valid ioctl */
}

int main() {
    printf("[*] Mali MEMORY ioctl size probe (Mi Box S)\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n\n", fd);

    void *buf = calloc(1, 256);
    if (!buf) { perror("calloc"); return 1; }

    const char *names[] = {"ALLOC_MEM(0)", "FREE_MEM(1)", "BIND_MEM(2)", "UNBIND_MEM(3)"};

    printf("%-15s  ", "SIZE");
    for (int n = 0; n < 4; n++) printf("%-12s", names[n]);
    printf("\n");
    printf("------------------------------------------------------------\n");

    for (int sz = 20; sz <= 72; sz += 4) {
        printf("%3d B (0x%02x)  ", sz, sz);
        for (int n = 0; n < 4; n++) {
            unsigned int cmd = _IOWR(0x83, n, sz);
            memset(buf, 0, 256);
            int r = test_ioctl(fd, cmd, buf);
            if (r == 1) printf("  0x%08x OK ", cmd);
            else if (r == 2) printf("  0x%08x E? ", cmd);
            else printf("    --       ");
        }
        printf("\n");
    }

    free(buf);
    close(fd);
    printf("\n[*] done\n");
    return 0;
}
