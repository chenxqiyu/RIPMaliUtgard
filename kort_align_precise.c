/*
 * kort_align_precise.c - Precise WB alignment test (using Mali mem)
 *
 * Write unique 4-byte patterns at each offset 0-7,
 * then check which bytes actually changed.
 *
 * Uses Mali ALLOC_MEM buffer (safe, no kernel crash risk).
 * Layout: [0x0000-0x0FFF] job data, [0x2000-0x2FFF] test target
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

#define GPU_VA_DATA 0x40300000u
#define DATA_SIZE   0x5000   /* 20KB: job + target area */
#define TGT_OFF     0x2000   /* target starts at 8KB offset */

#define MALI_IOC_MEM_ALLOC      0xC0288300u
#define MALI_IOC_PP_START_JOB   0xC1988400u
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202u

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

static int fd = -1;
static void *data_buf = NULL;
static volatile int g_to = 0;
static void alarm_handler(int s) { (void)s; g_to = 1; }

static int tio(unsigned int cmd, void *buf, int timeout) {
    alarm(timeout); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno;
    alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

/* Write RGBA8888 1x1 frame at given GPU VA */
static int wb_write_rgba(uint32_t tgt_gpu_va, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    uint8_t *buf = (uint8_t *)data_buf;
    memset(buf, 0, 0x1000);  /* only clear job area */

    memset(buf + 0x200, 0, 64);

    static const uint32_t shader[] = {
        0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
    };
    memcpy(buf + 0x080, shader, sizeof(shader));

    uint32_t *plb = (uint32_t *)buf;
    uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
    plb[0] = 0x00000000;
    plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u);
    plb[3] = 0xBC000000;

    uint32_t *rsw = (uint32_t *)(buf + 0x100);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = (GPU_VA_DATA + 0x080) | 5;
    rsw[0x0D] = 0x00000100;

    uint32_t clear_color = ((uint32_t)a << 24) | ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;

    mali_uk_pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

    job.frame_registers[FR_PLBU_ARRAY_ADDR] = GPU_VA_DATA + 0x000;
    job.frame_registers[FR_RENDER_ADDR]     = GPU_VA_DATA + 0x100;
    job.frame_registers[FR_FLAGS]           = 0x01;
    job.frame_registers[FR_CLEAR_COLOR_0]   = clear_color;
    job.frame_registers[FR_CLEAR_COLOR_1]   = clear_color;
    job.frame_registers[FR_CLEAR_COLOR_2]   = clear_color;
    job.frame_registers[FR_CLEAR_COLOR_3]   = clear_color;
    job.frame_registers[FR_WIDTH]           = 1;
    job.frame_registers[FR_HEIGHT]          = 1;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + 0x1000;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0x400;

    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = tgt_gpu_va;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;  /* RGBA8888 */
    job.wb0_registers[WB_DOWNSAMPLE]   = 0;
    job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
    job.wb0_registers[WB_PITCH]        = 1;
    job.wb0_registers[WB_TARGET_FLAGS] = 0;
    job.wb0_registers[WB_MRT_ENABLE]   = 0;

    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    __builtin___clear_cache((char *)buf, (char *)buf + DATA_SIZE);

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
    sa.sa_handler = alarm_handler;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== Precise WB Alignment Test ===\n\n");

    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali\n");

    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = DATA_SIZE;
    alloc.psize = DATA_SIZE;
    if (tio(MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) {
        printf("[-] ALLOC_MEM failed\n"); return 1;
    }
    printf("[+] ALLOC_MEM OK (%d bytes)\n", DATA_SIZE);

    data_buf = mmap(NULL, DATA_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (data_buf == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[+] mmap OK (%p)\n", data_buf);

    /* Target area is at offset TGT_OFF in the buffer */
    uint8_t *tgt = (uint8_t*)data_buf + TGT_OFF;
    uint32_t tgt_gpu = GPU_VA_DATA + TGT_OFF;
    printf("[+] target area: CPU=%p GPU=0x%08x\n\n", tgt, tgt_gpu);

    uint8_t markers[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    #define FILL 0xAA

    printf("Test: write unique R-marker at each offset 0-7\n");
    printf("Fill byte = 0x%02x, marker R values = 0x11..0x88\n", FILL);
    printf("1x1 frame, RGBA8888 format\n\n");

    for (int off = 0; off < 8; off++) {
        /* Reset target area */
        memset(tgt, FILL, 64);
        __builtin___clear_cache((char*)tgt, (char*)tgt + 64);

        uint8_t mr = markers[off];
        printf("Write offset %d (R=0x%02x): ", off, mr);

        int rc = wb_write_rgba(tgt_gpu + off, mr, 0x00, 0x00, 0x00);
        if (rc != 0) { printf("FAILED (rc=%d)\n", rc); continue; }

        /* Find first changed byte */
        int first = -1, last = -1, count = 0;
        for (int i = 0; i < 64; i++) {
            if (tgt[i] != FILL) {
                if (first < 0) first = i;
                last = i;
                count++;
            }
        }

        if (first < 0) {
            printf("NO CHANGE\n");
            continue;
        }

        printf("write_start=%d write_end=%d size=%d\n", first, last, count);
        printf("  first 16 bytes: ");
        for (int i = 0; i < 16; i++) {
            if (i > 0) printf(" ");
            printf("%02x", tgt[i]);
        }
        printf("\n");

        /* Check alignment: does the write start at 'off' or at a rounded-down address? */
        int expected_start = off;
        int aligned_start = off & ~7;  /* round down to 8 */
        if (first == expected_start) {
            printf("  -> Exact byte alignment! (starts exactly at offset %d)\n", off);
        } else if (first == aligned_start) {
            printf("  -> 8-byte aligned (starts at %d, requested %d)\n", first, off);
        } else if (first < off) {
            printf("  -> Write started BEFORE requested offset (first=%d, requested=%d, diff=%d)\n",
                   first, off, off - first);
        } else {
            printf("  -> Write started AFTER requested offset (first=%d, requested=%d)\n",
                   first, off);
        }
        printf("\n");
    }

    munmap(data_buf, DATA_SIZE);
    close(fd);
    printf("[*] Done\n");
    return 0;
}
