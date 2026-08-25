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
 * Diagnose ALLOC_MEM: which fields are outputs?
 * Fill buffer with pattern, call ALLOC_MEM, see which words changed.
 * Also test: does gpu_vaddr=0 let driver assign address?
 */

#define MALI_IOC_MEM_ALLOC 0xC0288300u  /* MEMORY nr=0 size=40 */
#define MALI_IOC_MEM_FREE  0xC0108301u  /* MEMORY nr=1 size=16 */

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

static void print_buf(const uint8_t *buf, int len, const char *label) {
    printf("  %s:\n", label);
    for (int i = 0; i < len; i += 4) {
        uint32_t v = *(uint32_t *)(buf + i);
        printf("    off%02d: 0x%08x\n", i, v);
    }
}

int main() {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] ALLOC_MEM output field diagnosis\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    printf("[+] fd=%d\n\n", fd);

    /* Test 1: standard alloc at 0x40000000 */
    printf("=== Test 1: gpu_vaddr=0x40000000, vsize=0x4000, psize=0x4000 ===\n");
    {
        uint8_t buf[64];
        memset(buf, 0xDE, sizeof(buf));

        /* Set input fields at expected offsets */
        *(uint32_t *)(buf + 8)  = 0x40000000;  /* gpu_vaddr */
        *(uint32_t *)(buf + 12) = 0x4000;      /* vsize */
        *(uint32_t *)(buf + 16) = 0x4000;      /* psize */
        *(uint32_t *)(buf + 20) = 0;           /* flags */

        int r = tio(fd, MALI_IOC_MEM_ALLOC, buf, 3);
        printf("  result: %s\n", r == 0 ? "OK" : (r == -999 ? "TIMEOUT" : strerror(-r)));
        if (r == 0) {
            print_buf(buf, 40, "after ALLOC");
            printf("  Changed fields (not 0xDEADDEAD):\n");
            for (int i = 0; i < 40; i += 4) {
                uint32_t v = *(uint32_t *)(buf + i);
                if (v != 0xDEADDEAD)
                    printf("    off%02d: was 0xDEADDEAD, now 0x%08x\n", i, v);
            }
            
            /* Free it */
            uint8_t freebuf[32];
            memset(freebuf, 0, sizeof(freebuf));
            *(uint32_t *)(freebuf + 8) = 0x40000000;
            tio(fd, MALI_IOC_MEM_FREE, freebuf, 3);
        }
    }

    /* Test 2: gpu_vaddr=0 (let driver assign) */
    printf("\n=== Test 2: gpu_vaddr=0 (driver-assigned) ===\n");
    {
        uint8_t buf[64];
        memset(buf, 0xDE, sizeof(buf));

        *(uint32_t *)(buf + 8)  = 0;           /* gpu_vaddr = 0 */
        *(uint32_t *)(buf + 12) = 0x4000;      /* vsize */
        *(uint32_t *)(buf + 16) = 0x4000;      /* psize */
        *(uint32_t *)(buf + 20) = 0;           /* flags */

        int r = tio(fd, MALI_IOC_MEM_ALLOC, buf, 3);
        printf("  result: %s\n", r == 0 ? "OK" : (r == -999 ? "TIMEOUT" : strerror(-r)));
        if (r == 0) {
            print_buf(buf, 40, "after ALLOC");
            printf("  Changed fields:\n");
            for (int i = 0; i < 40; i += 4) {
                uint32_t v = *(uint32_t *)(buf + i);
                if (v != 0xDEADDEAD)
                    printf("    off%02d: was 0xDEADDEAD, now 0x%08x\n", i, v);
            }

            uint32_t assigned_va = *(uint32_t *)(buf + 8);
            if (assigned_va != 0) {
                printf("  [+] Driver assigned gpu_vaddr = 0x%08x\n", assigned_va);
                /* Try mmap */
                void *p = mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, assigned_va);
                if (p != MAP_FAILED) {
                    printf("  [+] mmap OK at %p\n", p);
                    /* Write pattern and read back */
                    memset(p, 0x42, 0x4000);
                    printf("  [+] wrote 0x42 pattern, first word = 0x%08x\n", *(uint32_t *)p);
                    munmap(p, 0x4000);
                } else {
                    printf("  [-] mmap failed: %s\n", strerror(errno));
                }
            }
        }
    }

    /* Test 3: does flags affect anything? Try flag=1 (MALI_MEM_PROT_CPU_RD) */
    printf("\n=== Test 3: with flags=0x1 (PROT_CPU_RD) ===\n");
    {
        uint8_t buf[64];
        memset(buf, 0xDE, sizeof(buf));

        *(uint32_t *)(buf + 8)  = 0x50000000;
        *(uint32_t *)(buf + 12) = 0x4000;
        *(uint32_t *)(buf + 16) = 0x4000;
        *(uint32_t *)(buf + 20) = 0x1;  /* flags */

        int r = tio(fd, MALI_IOC_MEM_ALLOC, buf, 3);
        printf("  result: %s\n", r == 0 ? "OK" : (r == -999 ? "TIMEOUT" : strerror(-r)));
        if (r == 0) {
            printf("  Changed fields:\n");
            for (int i = 0; i < 40; i += 4) {
                uint32_t v = *(uint32_t *)(buf + i);
                if (v != 0xDEADDEAD)
                    printf("    off%02d: 0x%08x\n", i, v);
            }
            uint8_t freebuf[32];
            memset(freebuf, 0, sizeof(freebuf));
            *(uint32_t *)(freebuf + 8) = 0x50000000;
            tio(fd, MALI_IOC_MEM_FREE, freebuf, 3);
        }
    }

    close(fd);
    printf("\ndone\n");
    return 0;
}
