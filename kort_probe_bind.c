#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>

/*
 * Quick BIND_MEM probe - test only a few candidate sizes.
 * ALLOC_MEM confirmed: size=40 (0x28) -> ioctl=0xc0288300
 *
 * Since ALLOC_MEM is 40 bytes (8 bytes bigger than standard 32),
 * BIND_MEM is likely also 8 bytes bigger.
 * Standard BIND_MEM ~= 36-40 bytes, so Mi Box S ~= 44-52 bytes.
 */

#define MALI_IOC_MEMORY_BASE 0x83
#define _MALI_UK_BIND_MEM 2
#define _MALI_UK_UNBIND_MEM 3
#define _MALI_UK_FREE_MEM 1

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))

#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

static volatile int g_timeout = 0;
static void alarm_handler(int sig) { g_timeout = 1; }

static int test_bind(int fd, int size, uint32_t phys_addr) {
    /* Construct a bind_mem structure with external phys memory */
    /* We don't know exact layout, so we fill with known values at likely offsets */
    uint8_t *buf = calloc(1, size + 8);
    if (!buf) return -999;

    /* The structure likely starts with ctx (uint64_t = 8 bytes) */
    /* Then vaddr, size, flags, then union with phys_addr + rights + flags */

    /* For external memory bind:
     * - flags must have EXTERNAL_MEMORY bit set
     * - phys_addr is the physical address
     * - We need a valid ctx handle (but 0 might be accepted for testing)
     */

    /* Try putting flags at offset 16 (after ctx=8, vaddr=4, size=4) */
    *(uint32_t *)(buf + 16) = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;

    /* Try putting phys_addr at offset 24 in the union
     * (after ctx=8, vaddr=4, size=4, flags=4, padding=4 = 24) */
    /* But Mi Box S struct is bigger, so maybe offset 32? */
    *(uint32_t *)(buf + 24) = phys_addr;

    /* Set alarm to avoid hanging */
    alarm(2);
    g_timeout = 0;

    unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, size);
    int ret = ioctl(fd, cmd, buf);
    int err = errno;

    alarm(0);

    free(buf);

    if (g_timeout) {
        printf("  [TIMEOUT] size=%d cmd=0x%08x\n", size, cmd);
        return -100;
    }

    return ret == 0 ? 0 : -err;
}

int main() {
    signal(SIGALRM, alarm_handler);

    printf("[*] Quick BIND_MEM size probe\n");
    printf("[*] ALLOC_MEM confirmed: 40 bytes (0x28)\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n\n", fd);

    /* Test candidate sizes for BIND_MEM */
    /* Standard Utgard: ~36-40 bytes. Mi Box S likely 48-56 bytes. */
    int sizes[] = {32, 36, 40, 44, 48, 52, 56, 60, 64, 72, 80};
    int n_sizes = sizeof(sizes)/sizeof(sizes[0]);

    /* Use a physical address that's likely valid (e.g., 0x00000000 or a known RAM addr) */
    /* 0x01080000 is kernel phys load address from earlier output */
    uint32_t test_phys = 0x01080000;

    printf("Testing BIND_MEM with phys=0x%08x:\n", test_phys);
    printf("%-6s  %-10s  %-6s  %s\n", "SIZE", "IOCTL", "RET", "STATUS");
    printf("--------------------------------------------------\n");

    for (int i = 0; i < n_sizes; i++) {
        int sz = sizes[i];
        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, sz);
        int ret = test_bind(fd, sz, test_phys);
        if (ret == 0) {
            printf("%3d B   0x%08x    0     SUCCESS\n", sz, cmd);
        } else if (ret == -ENOTTY) {
            printf("%3d B   0x%08x   -%2d    ENOTTY (wrong size)\n", sz, cmd, -ret);
        } else if (ret == -EINVAL) {
            printf("%3d B   0x%08x   -%2d    EINVAL (ioctl exists!)\n", sz, cmd, -ret);
        } else if (ret == -100) {
            printf("%3d B   0x%08x   ---    TIMEOUT\n", sz, cmd);
        } else {
            printf("%3d B   0x%08x   %3d    (errno=%d)\n", sz, cmd, ret, -ret);
        }
        fflush(stdout);
    }

    close(fd);
    printf("\n[*] done\n");
    return 0;
}
