#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

/*
 * Safe probe: test only ALLOC_MEM ioctl with different structure sizes.
 * This is safe because ALLOC_MEM only allocates memory - it won't crash the kernel
 * even if the structure size is wrong (it will just copy fewer/more bytes).
 */

#define MALI_IOC_BASE 0x82
#define _MALI_UK_MEMORY_SUBSYSTEM 1
#define MALI_IOC_MEMORY_BASE (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE)
#define _MALI_UK_ALLOC_MEM 0

/* _IOC definitions */
#define _IOC_DIRMASK   0x3
#define _IOC_DIRSHIFT  30
#define _IOC_SIZESHIFT 16
#define _IOC_TYPESHIFT 8
#define _IOC_NRSHIFT   0

#define _IOC(dir, type, nr, size) \
    (((dir)  << _IOC_DIRSHIFT) | \
     ((size) << _IOC_SIZESHIFT) | \
     ((type) << _IOC_TYPESHIFT) | \
     ((nr)   << _IOC_NRSHIFT))

#define _IOWR(type, nr, size) _IOC(3, type, nr, size)

int main() {
    printf("[*] Safe ALLOC_MEM size probe\n");
    printf("[*] MALI_IOC_MEMORY_BASE = 0x%02x\n", MALI_IOC_MEMORY_BASE);

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        perror("open /dev/mali");
        return 1;
    }
    printf("[+] opened /dev/mali fd=%d\n\n", fd);

    /* Allocate a zeroed buffer large enough for any size */
    uint32_t *buf = calloc(1, 512);
    if (!buf) { perror("calloc"); return 1; }

    /* Test sizes from 16 to 64 bytes */
    printf("%-6s  %-10s  %-8s  %s\n", "SIZE", "IOCTL", "RET", "ERRNO");
    printf("--------------------------------------------------\n");

    for (int sz = 16; sz <= 80; sz += 4) {
        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, sz);
        int ret = ioctl(fd, cmd, buf);
        int err = errno;

        const char *status = "";
        if (ret == 0) status = " <-- SUCCESS!";
        else if (err != ENOTTY) status = " <-- EXISTS (not ENOTTY)";

        printf("%3d B   0x%08x  %4d     %2d %s\n", sz, cmd, ret, err, status);
    }

    /* Also test type 0x82 (without adding subsystem) */
    printf("\n=== Also testing type 0x82 (CORE base) ===\n");
    for (int sz = 16; sz <= 80; sz += 4) {
        unsigned int cmd = _IOWR(0x82, _MALI_UK_ALLOC_MEM, sz);
        int ret = ioctl(fd, cmd, buf);
        int err = errno;

        if (ret == 0 || err != ENOTTY) {
            printf("%3d B   0x%08x  %4d     %2d  <--\n", sz, cmd, ret, err);
        }
    }

    free(buf);
    close(fd);
    printf("\n[*] probe done\n");
    return 0;
}
