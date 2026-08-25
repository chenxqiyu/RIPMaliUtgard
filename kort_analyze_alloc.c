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
 * Analyze ALLOC_MEM return structure to determine field layout.
 * ALLOC_MEM confirmed: size=40 bytes, ioctl=0xc0288300
 *
 * Standard mali_uk_alloc_mem_s (32 bytes):
 *   uint64_t ctx;          // offset 0
 *   uint32_t gpu_vaddr;    // offset 8
 *   uint32_t vsize;        // offset 12
 *   uint32_t psize;        // offset 16
 *   uint32_t flags;        // offset 20
 *   uint64_t backend_handle; // offset 24
 *
 * Mi Box S is 40 bytes. 8 extra bytes could be:
 *   - secure_shared_fd (int32 + padding = 8 bytes) at end
 *   - or other fields
 *
 * We'll allocate memory and dump all 40 bytes to see which fields are populated.
 */

#define MALI_IOC_MEMORY_BASE 0x83
#define _MALI_UK_ALLOC_MEM 0

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] ALLOC_MEM structure analysis\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n", fd);

    /* Allocate with different sizes to see which fields change */
    uint32_t test_sizes[] = {0x1000, 0x2000, 0x4000, 0x8000};
    int n_tests = sizeof(test_sizes)/sizeof(test_sizes[0]);

    for (int t = 0; t < n_tests; t++) {
        uint8_t buf[64] = {0};
        uint32_t req_size = test_sizes[t];

        /* We're not sure which field is psize (requested physical size).
         * Let's try putting it at offset 16 (standard location). */
        *(uint32_t *)(buf + 16) = req_size;  /* psize? */
        *(uint32_t *)(buf + 12) = req_size;  /* vsize? */

        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, 40);
        int ret = ioctl(fd, cmd, buf);
        int err = errno;

        printf("\n--- Test %d: requested size=0x%x ---\n", t, req_size);
        if (ret != 0) {
            printf("  FAILED: ret=%d errno=%d (%s)\n", ret, err, strerror(err));
            continue;
        }

        printf("  Returned 40 bytes (hex):\n");
        printf("  Offset:  00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F\n");
        for (int row = 0; row < 3; row++) {
            printf("  0x%02x:    ", row * 16);
            for (int col = 0; col < 16 && row*16+col < 40; col++) {
                printf("%02x ", buf[row*16+col]);
                if (col == 3 || col == 7 || col == 11) printf(" ");
            }
            printf("\n");
        }

        /* Interpret as standard fields */
        uint64_t ctx = *(uint64_t *)(buf + 0);
        uint32_t vaddr = *(uint32_t *)(buf + 8);
        uint32_t vsize = *(uint32_t *)(buf + 12);
        uint32_t psize = *(uint32_t *)(buf + 16);
        uint32_t flags = *(uint32_t *)(buf + 20);
        uint64_t backend = *(uint64_t *)(buf + 24);
        uint32_t extra1 = *(uint32_t *)(buf + 32);
        uint32_t extra2 = *(uint32_t *)(buf + 36);

        printf("\n  Interpreted (standard layout):\n");
        printf("    ctx            = 0x%016llx\n", (unsigned long long)ctx);
        printf("    gpu_vaddr      = 0x%08x\n", vaddr);
        printf("    vsize          = 0x%08x\n", vsize);
        printf("    psize          = 0x%08x\n", psize);
        printf("    flags          = 0x%08x\n", flags);
        printf("    backend_handle = 0x%016llx\n", (unsigned long long)backend);
        printf("    extra1         = 0x%08x\n", extra1);
        printf("    extra2         = 0x%08x\n", extra2);

        /* Try to mmap using the returned vaddr to verify */
        if (vaddr != 0 && vsize >= 0x1000) {
            void *map = mmap(0, vsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, vaddr);
            if (map != MAP_FAILED) {
                printf("  [+] mmap at gpu_vaddr=0x%08x SUCCESS (size=0x%x)\n", vaddr, vsize);
                /* Write a test pattern and read back */
                memset(map, 0xAB, 256);
                printf("  [+] first 16 bytes at mmap: ");
                for (int i = 0; i < 16; i++) printf("%02x ", ((uint8_t*)map)[i]);
                printf("\n");
                munmap(map, vsize);
            } else {
                printf("  [-] mmap failed: %s\n", strerror(errno));
            }
        }

        /* Free the memory */
        /* Try FREE_MEM with size 16 (ctx + free_pages_nr) */
        /* We'll try multiple sizes */
    }

    close(fd);
    printf("\n[*] done\n");
    return 0;
}
