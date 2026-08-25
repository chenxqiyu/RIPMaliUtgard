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
 * Safe probe with alarm timeout to prevent Mali driver hangs.
 * ALLOC_MEM confirmed: size=40, ioctl=0xc0288300
 */

#define MALI_IOC_MEMORY_BASE 0x83
#define _MALI_UK_ALLOC_MEM  0
#define _MALI_UK_FREE_MEM   1
#define _MALI_UK_BIND_MEM   2
#define _MALI_UK_UNBIND_MEM 3

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))

#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

static volatile int g_timed_out = 0;
static void alarm_handler(int sig) { g_timed_out = 1; }

static int safe_ioctl(int fd, unsigned int cmd, void *buf, int timeout_sec) {
    alarm(timeout_sec);
    g_timed_out = 0;
    int ret = ioctl(fd, cmd, buf);
    int err = errno;
    alarm(0);
    if (g_timed_out) return -999;
    return ret == 0 ? 0 : -err;
}

static void dump_hex(const uint8_t *buf, int len) {
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %02x: ", i);
        printf("%02x ", buf[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

int main() {
    signal(SIGALRM, alarm_handler);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] Mali ALLOC_MEM structure analysis\n");
    printf("[*] (with 3s timeout per ioctl)\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n", fd);

    /* === Step 1: ALLOC_MEM analysis === */
    printf("\n=== Step 1: ALLOC_MEM (size=40) ===\n");

    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    /* Request 4KB. Put psize at offset 16, vsize at offset 12 (standard layout guess) */
    *(uint32_t *)(buf + 12) = 0x1000;  /* vsize */
    *(uint32_t *)(buf + 16) = 0x1000;  /* psize */

    int ret = safe_ioctl(fd, _IOWR(0x83, 0, 40), buf, 3);
    if (ret == -999) {
        printf("TIMEOUT!\n");
        close(fd);
        return 1;
    }
    if (ret != 0) {
        printf("ALLOC_MEM failed: %d (errno=%d)\n", ret, -ret);
        close(fd);
        return 1;
    }

    printf("ALLOC_MEM success!\n");
    printf("Returned 40 bytes:\n");
    dump_hex(buf, 40);

    /* Interpret fields */
    uint64_t ctx = *(uint64_t *)(buf + 0);
    uint32_t vaddr = *(uint32_t *)(buf + 8);
    uint32_t vsize = *(uint32_t *)(buf + 12);
    uint32_t psize = *(uint32_t *)(buf + 16);
    uint32_t flags = *(uint32_t *)(buf + 20);
    uint64_t backend = *(uint64_t *)(buf + 24);
    uint32_t extra1 = *(uint32_t *)(buf + 32);
    uint32_t extra2 = *(uint32_t *)(buf + 36);

    printf("\nField interpretation (standard layout guess):\n");
    printf("  ctx            = 0x%016llx\n", (unsigned long long)ctx);
    printf("  gpu_vaddr (8)  = 0x%08x\n", vaddr);
    printf("  vsize (12)     = 0x%08x\n", vsize);
    printf("  psize (16)     = 0x%08x\n", psize);
    printf("  flags (20)     = 0x%08x\n", flags);
    printf("  backend (24)   = 0x%016llx\n", (unsigned long long)backend);
    printf("  extra1 (32)    = 0x%08x\n", extra1);
    printf("  extra2 (36)    = 0x%08x\n", extra2);

    /* Try mmap with the vaddr to verify it's correct */
    if (vaddr != 0 && vsize >= 0x1000) {
        printf("\nTrying mmap at vaddr=0x%08x (size=0x%x)...\n", vaddr, vsize);
        void *map = mmap(0, vsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, vaddr);
        if (map != MAP_FAILED) {
            printf("  [+] mmap SUCCESS!\n");
            memset(map, 0x41, 64);
            printf("  Wrote 'AAAA...', reading back: ");
            for (int i = 0; i < 16; i++) printf("%02x ", ((uint8_t*)map)[i]);
            printf("\n");
            munmap(map, vsize);
        } else {
            printf("  [-] mmap failed: %s\n", strerror(errno));
        }
    }

    /* === Step 2: FREE_MEM size probe === */
    printf("\n=== Step 2: FREE_MEM size probe ===\n");
    int free_sizes[] = {12, 16, 20, 24, 28, 32, 36, 40};
    for (int i = 0; i < 8; i++) {
        int sz = free_sizes[i];
        uint8_t fbuf[64] = {0};
        *(uint64_t *)fbuf = ctx;  /* use valid ctx */
        *(uint32_t *)(fbuf + 8) = 0; /* free_pages_nr = 0 means free all? */

        unsigned int cmd = _IOWR(0x83, _MALI_UK_FREE_MEM, sz);
        /* Don't actually free - use ctx=0 to get EINVAL not ENOTTY */
        *(uint64_t *)fbuf = 0;
        int r = safe_ioctl(fd, cmd, fbuf, 2);
        if (r == -999)
            printf("  size=%2d  cmd=0x%08x  TIMEOUT\n", sz, cmd);
        else if (r == 0)
            printf("  size=%2d  cmd=0x%08x  OK (ctx=0 freed?)\n", sz, cmd);
        else if (r == -ENOTTY)
            printf("  size=%2d  cmd=0x%08x  ENOTTY (wrong)\n", sz, cmd);
        else
            printf("  size=%2d  cmd=0x%08x  err=%d (EXISTS!)\n", sz, cmd, -r);
    }

    /* === Step 3: BIND_MEM size probe (with valid ctx) === */
    printf("\n=== Step 3: BIND_MEM size probe ===\n");
    int bind_sizes[] = {32, 36, 40, 44, 48, 52, 56, 60, 64, 72, 80};
    int n_bind = sizeof(bind_sizes)/sizeof(bind_sizes[0]);

    /* Use a known physical address - 0x01080000 (kernel load addr) */
    uint32_t test_phys = 0x01080000;

    for (int i = 0; i < n_bind; i++) {
        int sz = bind_sizes[i];
        uint8_t bbuf[128];
        memset(bbuf, 0, sizeof(bbuf));

        /* ctx at offset 0 */
        *(uint64_t *)bbuf = ctx;

        /* We don't know the exact layout.
         * Try to put EXTERNAL flag at multiple offsets */
        for (int off = 12; off <= 28; off += 4) {
            *(uint32_t *)(bbuf + off) = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
        }
        /* Try phys_addr at multiple offsets */
        for (int off = 20; off <= 56; off += 4) {
            *(uint32_t *)(bbuf + off) = test_phys;
        }

        unsigned int cmd = _IOWR(0x83, _MALI_UK_BIND_MEM, sz);
        int r = safe_ioctl(fd, cmd, bbuf, 3);

        if (r == -999)
            printf("  size=%2d  cmd=0x%08x  TIMEOUT\n", sz, cmd);
        else if (r == 0)
            printf("  size=%2d  cmd=0x%08x  SUCCESS!\n", sz, cmd);
        else if (r == -ENOTTY)
            printf("  size=%2d  cmd=0x%08x  ENOTTY\n", sz, cmd);
        else
            printf("  size=%2d  cmd=0x%08x  err=%d (EXISTS)\n", sz, cmd, -r);
    }

    /* Cleanup: free the allocated memory (try size=16 first) */
    printf("\n=== Cleanup: free allocated memory ===\n");
    uint8_t fbuf[64] = {0};
    *(uint64_t *)fbuf = ctx;
    *(uint32_t *)(fbuf + 8) = 0;
    /* Try standard FREE_MEM size = 16 (ctx + free_pages_nr) */
    int r = safe_ioctl(fd, _IOWR(0x83, _MALI_UK_FREE_MEM, 16), fbuf, 2);
    printf("  FREE_MEM (size=16): ret=%d\n", r);

    close(fd);
    printf("\n[*] done\n");
    return 0;
}
