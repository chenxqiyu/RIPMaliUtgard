/*
 * kort_pp_align_test.c - Test WB write alignment granularity
 *
 * Write to offsets 0,1,2,3,4,5,6,7 and see which ones affect offset 0.
 * This tells us the alignment requirement of WB_ADDRESS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>

#define MALI_IOC_MEM_ALLOC      0xC0288300u
#define MALI_IOC_PP_START_JOB   0xC1988400u
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202u
#define _MALI_NOTIFICATION_PP_FINISHED ((2 << 16) | 0x10)

typedef struct {
    uint64_t ctx; uint32_t gpu_vaddr; uint32_t vsize; uint32_t psize;
    uint32_t flags; uint64_t backend_handle; int32_t secure_shared_fd;
} mali_uk_alloc_mem_s;

#define MALI_UK_TIMELINE_MAX 3
typedef struct { uint32_t points[MALI_UK_TIMELINE_MAX]; int32_t sync_fd; } mali_uk_fence_t;

typedef struct {
    uint64_t ctx; uint64_t user_job_ptr; uint32_t priority;
    uint32_t frame_registers[23];
    uint32_t frame_registers_addr_frame[7];
    uint32_t frame_registers_addr_stack[7];
    uint32_t wb0_registers[12]; uint32_t wb1_registers[12]; uint32_t wb2_registers[12];
    uint32_t dlbu_registers[4];
    uint32_t num_cores; uint32_t perf_counter_flag;
    uint32_t perf_counter_src0; uint32_t perf_counter_src1;
    uint32_t frame_builder_id; uint32_t flush_id; uint32_t flags;
    uint32_t tilesx; uint32_t tilesy; uint32_t heatmap_mem;
    uint32_t num_memory_cookies; uint64_t memory_cookies;
    mali_uk_fence_t fence; uint64_t timeline_point_ptr;
} mali_uk_pp_start_job_s;

typedef struct {
    uint64_t ctx; uint32_t type; uint32_t _pad; uint8_t data[88];
} mali_uk_wait_for_notification_s;

#define FR_PLBU_ARRAY_ADDR 0
#define FR_RENDER_ADDR     1
#define FR_FLAGS           3
#define FR_CLEAR_COLOR_0   6
#define FR_CLEAR_COLOR_1   7
#define FR_CLEAR_COLOR_2   8
#define FR_CLEAR_COLOR_3   9
#define FR_WIDTH          10
#define FR_HEIGHT         11
#define FR_FRAG_STACK_ADDR 12
#define FR_FRAG_STACK_SIZE 13

#define WB_TYPE         0
#define WB_ADDRESS      1
#define WB_PIXEL_FORMAT 2
#define WB_DOWNSAMPLE   3
#define WB_PIXEL_LAYOUT 4
#define WB_PITCH        5
#define WB_TARGET_FLAGS 6
#define WB_MRT_ENABLE   7

#define GPU_VA_DATA  0x40000000u
#define BUF_SIZE     0x4000
#define TEST_OFF     0x3000
#define FILL_BYTE    0x55

static int fd = -1;
static volatile int g_to = 0;
static void alh(int s) { (void)s; g_to = 1; }

static int tio(unsigned int cmd, void *buf, int t) {
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno;
    alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

/* Write RGBA at given GPU VA offset (within GPU_VA_DATA buffer) */
static int wb_write(uint8_t *buf, uint32_t tgt_offset, uint32_t rgba)
{
    /* Only clear job area, not target area */
    memset(buf, 0, 0x1000);

    /* Tile block at 0x200 */
    memset(buf + 0x200, 0, 64);

    /* Shader at 0x080 */
    static const uint32_t shader[] = {
        0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
    };
    memcpy(buf + 0x080, shader, sizeof(shader));

    /* FIXED PLB */
    uint32_t *plb = (uint32_t *)buf;
    uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
    plb[0] = 0x00000000;
    plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u);
    plb[3] = 0xBC000000;

    /* RSW at 0x100 */
    uint32_t *rsw = (uint32_t *)(buf + 0x100);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = (GPU_VA_DATA + 0x080) | 5;
    rsw[0x0D] = 0x00000100;

    uint32_t wb_addr = GPU_VA_DATA + tgt_offset;

    mali_uk_pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

    job.frame_registers[FR_PLBU_ARRAY_ADDR] = GPU_VA_DATA + 0x000;
    job.frame_registers[FR_RENDER_ADDR]     = GPU_VA_DATA + 0x100;
    job.frame_registers[FR_FLAGS]           = 0x01;
    job.frame_registers[FR_CLEAR_COLOR_0]   = rgba;
    job.frame_registers[FR_CLEAR_COLOR_1]   = rgba;
    job.frame_registers[FR_CLEAR_COLOR_2]   = rgba;
    job.frame_registers[FR_CLEAR_COLOR_3]   = rgba;
    job.frame_registers[FR_WIDTH]           = 1;
    job.frame_registers[FR_HEIGHT]          = 1;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + 0x1000;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0x400;

    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = wb_addr;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
    job.wb0_registers[WB_DOWNSAMPLE]   = 0;
    job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
    job.wb0_registers[WB_PITCH]        = 1;
    job.wb0_registers[WB_TARGET_FLAGS] = 0;
    job.wb0_registers[WB_MRT_ENABLE]   = 0;

    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    __builtin___clear_cache((char *)buf, (char *)buf + BUF_SIZE);

    int ret = tio(MALI_IOC_PP_START_JOB, &job, 5);
    if (ret == -999) return -999;
    if (ret != 0) return ret;

    mali_uk_wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    ret = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    if (ret == -999) return -999;
    if (ret != 0) return ret;

    uint32_t status;
    memcpy(&status, notif.data + 8, 4);
    if (!(status & (1 << 16))) return -1;
    return 0;
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== WB Alignment Test ===\n\n");

    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    if (tio(MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) {
        printf("ALLOC failed\n"); return 1;
    }

    uint8_t *buf = (uint8_t *)mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE,
                                    MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[+] ready\n\n");

    /*
     * Test: write to offset N with a unique color,
     * then check if byte 0 was modified.
     * If byte 0 was modified, the write alignment is > N bytes.
     */

    /* First fill with FILL_BYTE */
    memset(buf + TEST_OFF, FILL_BYTE, 256);

    printf("Test: write unique color to each offset, check if byte[0] changed\n\n");

    /* We'll use R channel to encode the offset (0x01, 0x02, 0x04, 0x08, etc.) */
    uint8_t markers[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

    for (int off = 0; off < 8; off++) {
        /* Reset target area */
        memset(buf + TEST_OFF, FILL_BYTE, 256);

        /* RGBA = marker, 0x00, 0x00, 0x00 */
        uint32_t rgba = ((uint32_t)markers[off] << 24) | 0x00000000;

        printf("  Write offset %d (R=0x%02x): ", off, markers[off]);

        int rc = wb_write(buf, TEST_OFF + off, rgba);
        if (rc != 0) {
            printf("FAILED (rc=%d)\n", rc);
            continue;
        }

        /* Check byte 0 */
        uint8_t byte0 = buf[TEST_OFF];
        printf("byte[0]=0x%02x", byte0);

        if (byte0 == FILL_BYTE) {
            printf(" (unchanged - aligned at %d)\n", off);
        } else if (byte0 == markers[off]) {
            printf(" (MATCHED marker - write started before offset %d)\n", off);
        } else {
            printf(" (unexpected)\n");
        }

        /* Also show first 16 bytes for off=0 and off=4 */
        if (off == 0 || off == 4 || off == 7) {
            printf("    first 16: ");
            for (int i = 0; i < 16; i++) printf("%02x ", buf[TEST_OFF + i]);
            printf("\n");
        }
    }

    /*
     * Now test: what is the exact write size and pattern?
     * Write at offset 0 and see the modified region.
     */
    printf("\n--- Write size and pattern (offset 0, RGBA=0xAABBCCDD) ---\n");
    memset(buf + TEST_OFF, FILL_BYTE, 512);
    uint32_t test_rgba = 0xDDCCBBAA;  /* ARGB = 0xAABBCCDD → RGBA bytes = AA BB CC DD */
    wb_write(buf, TEST_OFF, test_rgba);

    int first_mod = -1, last_mod = -1, mod_count = 0;
    for (int i = 0; i < 512; i++) {
        if (buf[TEST_OFF + i] != FILL_BYTE) {
            if (first_mod < 0) first_mod = i;
            last_mod = i;
            mod_count++;
        }
    }
    printf("  Modified: %d bytes (offset %d - %d)\n", mod_count, first_mod, last_mod);
    printf("  First 32 bytes:\n    ");
    for (int i = 0; i < 32; i++) printf("%02x ", buf[TEST_OFF + i]);
    printf("\n");

    munmap(buf, BUF_SIZE);
    close(fd);
    printf("\n=== done ===\n");
    return 0;
}
