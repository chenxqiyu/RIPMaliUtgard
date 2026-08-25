#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/*
 * Probe all key Mali Utgard ioctls to find correct structure sizes.
 * Mi Box S (oneday) has larger structures than other devices.
 */

#define MALI_IOC_BASE 0x82
#define _MALI_UK_CORE_SUBSYSTEM 0
#define _MALI_UK_MEMORY_SUBSYSTEM 1
#define _MALI_UK_PP_SUBSYSTEM 2

#define MALI_IOC_CORE_BASE   (_MALI_UK_CORE_SUBSYSTEM + MALI_IOC_BASE)   /* 0x82 */
#define MALI_IOC_MEMORY_BASE (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE) /* 0x83 */
#define MALI_IOC_PP_BASE     (_MALI_UK_PP_SUBSYSTEM + MALI_IOC_BASE)     /* 0x84 */

#define _MALI_UK_GET_API_VERSION  0
#define _MALI_UK_GET_BIG_ENDIAN   1
#define _MALI_UK_CREATE_CONTEXT   3
#define _MALI_UK_DELETE_CONTEXT   4

#define _MALI_UK_ALLOC_MEM  0
#define _MALI_UK_FREE_MEM   1
#define _MALI_UK_BIND_MEM   2
#define _MALI_UK_UNBIND_MEM 3
#define _MALI_UK_MAP_EXT_MEM  8
#define _MALI_UK_UNMAP_EXT_MEM 9

#define _MALI_UK_PP_START_JOB 0
#define _MALI_UK_PP_JOB_DONE   1
#define _MALI_UK_WAIT_FOR_NOTIFICATION 2

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))

#define _IOR(type, nr, size) \
    (((2) << 30) | ((size) << 16) | ((type) << 8) | (nr))

#define _IOW(type, nr, size) \
    (((1) << 30) | ((size) << 16) | ((type) << 8) | (nr))

static void probe_range(const char *name, unsigned char type, int nr_start, int nr_end,
                         int sz_min, int sz_max, int sz_step, void *buf) {
    int found = 0;
    printf("=== %s (type=0x%02x, nr %d..%d) ===\n", name, type, nr_start, nr_end);
    printf("%-4s  ", "NR");
    for (int sz = sz_min; sz <= sz_max; sz += sz_step) {
        printf("%3dB ", sz);
    }
    printf("\n");

    for (int nr = nr_start; nr <= nr_end; nr++) {
        printf("%-4d  ", nr);
        for (int sz = sz_min; sz <= sz_max; sz += sz_step) {
            unsigned int cmd = _IOWR(type, nr, sz);
            memset(buf, 0, 512);
            int ret = ioctl(((int)(long)buf) & 0, cmd, buf); /* won't work, use fd later */
            /* placeholder - we'll do it properly below */
            printf("??  ");
        }
        printf("\n");
    }
}

int main() {
    printf("[*] Mali ioctl structure size probe for Mi Box S\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        perror("open /dev/mali");
        return 1;
    }
    printf("[+] opened /dev/mali fd=%d\n\n", fd);

    uint32_t *buf = calloc(1, 1024);
    if (!buf) { perror("calloc"); return 1; }

    /* === MEMORY SUBSYSTEM (type=0x83) === */
    printf("=== MEMORY SUBSYSTEM (type=0x83) ===\n");
    printf("%-4s  ", "NR");
    for (int sz = 16; sz <= 80; sz += 4) {
        printf("%3dB ", sz);
    }
    printf("\n");

    for (int nr = 0; nr <= 10; nr++) {
        printf("%-4d  ", nr);
        for (int sz = 16; sz <= 80; sz += 4) {
            unsigned int cmd = _IOWR(0x83, nr, sz);
            memset(buf, 0, 1024);
            int ret = ioctl(fd, cmd, buf);
            int err = errno;
            if (ret == 0)
                printf(" OK ");
            else if (err != ENOTTY)
                printf(" E%02d", err);
            else
                printf(" --  ");
        }
        printf("\n");
    }
    printf("\n");

    /* === PP SUBSYSTEM (type=0x84) === */
    printf("=== PP SUBSYSTEM (type=0x84) ===\n");
    printf("%-4s  ", "NR");
    for (int sz = 64; sz <= 512; sz += 16) {
        printf("%4dB ", sz);
    }
    printf("\n");

    for (int nr = 0; nr <= 6; nr++) {
        printf("%-4d  ", nr);
        for (int sz = 64; sz <= 512; sz += 16) {
            unsigned int cmd = _IOWR(0x84, nr, sz);
            memset(buf, 0, 1024);
            int ret = ioctl(fd, cmd, buf);
            int err = errno;
            if (ret == 0)
                printf(" OK  ");
            else if (err != ENOTTY)
                printf(" E%02d ", err);
            else
                printf(" --   ");
        }
        printf("\n");
    }
    printf("\n");

    /* === CORE SUBSYSTEM (type=0x82) === */
    printf("=== CORE SUBSYSTEM (type=0x82) ===\n");
    printf("%-4s  ", "NR");
    for (int sz = 4; sz <= 64; sz += 4) {
        printf("%3dB ", sz);
    }
    printf("\n");

    for (int nr = 0; nr <= 8; nr++) {
        printf("%-4d  ", nr);
        for (int sz = 4; sz <= 64; sz += 4) {
            unsigned int cmd = _IOWR(0x82, nr, sz);
            memset(buf, 0, 1024);
            int ret = ioctl(fd, cmd, buf);
            int err = errno;
            if (ret == 0)
                printf(" OK ");
            else if (err != ENOTTY)
                printf(" E%02d", err);
            else
                printf(" --  ");
        }
        printf("\n");
    }

    free(buf);
    close(fd);
    printf("\n[*] probe done\n");
    return 0;
}
