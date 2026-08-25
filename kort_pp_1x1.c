/*
 * kort_pp_1x1.c - Test 1x1 pixel WB write (exactly 4 bytes)
 *
 * Goal: verify that a 1x1 frame works with the FIXED PLB.
 * If yes, we can do precise 4-byte writes to kernel memory
 * without clobbering surrounding data.
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

static const char *status_str(uint32_t s) {
    if (s & (1 << 16)) return "SUCCESS";
    if (s & (1 << 23)) return "UNKNOWN_ERR";
    return "???";
}

static int test_size(uint32_t *buf, int w, int h)
{
    memset(buf, 0, BUF_SIZE);

    /* Tile block (empty) at 0x200 */
    memset((uint8_t *)buf + 0x200, 0, 64);

    /* Shader at 0x080 */
    static const uint32_t shader[] = {
        0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
    };
    memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));

    /* FIXED PLB (no B0) */
    uint32_t *plb = buf;
    uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
    plb[0] = 0x00000000;
    plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u);
    plb[3] = 0xBC000000;

    /* RSW at 0x100 */
    uint32_t *rsw = (uint32_t *)((uint8_t *)buf + 0x100);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = (GPU_VA_DATA + 0x080) | 5;
    rsw[0x0D] = 0x00000100;

    /* WB target at 0x3000 */
    uint32_t wb_tgt = GPU_VA_DATA + 0x3000;
    uint32_t *tgt_in_buf = (uint32_t *)((uint8_t *)buf + 0x3000);
    tgt_in_buf[0] = 0xDEADBEEF;
    tgt_in_buf[1] = 0xDEADBEEF;
    tgt_in_buf[2] = 0xDEADBEEF;
    tgt_in_buf[3] = 0xDEADBEEF;

    mali_uk_pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

    job.frame_registers[FR_PLBU_ARRAY_ADDR] = GPU_VA_DATA + 0x000;
    job.frame_registers[FR_RENDER_ADDR]     = GPU_VA_DATA + 0x100;
    job.frame_registers[FR_FLAGS]           = 0x01;
    job.frame_registers[FR_CLEAR_COLOR_0]   = 0x41424344;
    job.frame_registers[FR_CLEAR_COLOR_1]   = 0x41424344;
    job.frame_registers[FR_CLEAR_COLOR_2]   = 0x41424344;
    job.frame_registers[FR_CLEAR_COLOR_3]   = 0x41424344;
    job.frame_registers[FR_WIDTH]           = w;
    job.frame_registers[FR_HEIGHT]          = h;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + 0x1000;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0x400;

    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = wb_tgt;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
    job.wb0_registers[WB_DOWNSAMPLE]   = 0;
    job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
    /* Pitch: try (w*4)/8, but minimum 1 */
    job.wb0_registers[WB_PITCH]        = (w * 4) / 8;
    if (job.wb0_registers[WB_PITCH] < 1) job.wb0_registers[WB_PITCH] = 1;
    job.wb0_registers[WB_TARGET_FLAGS] = 0;
    job.wb0_registers[WB_MRT_ENABLE]   = 0;

    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    __builtin___clear_cache((char *)buf, (char *)buf + BUF_SIZE);

    printf("  [%dx%d] pitch=%d ", w, h, job.wb0_registers[WB_PITCH]);

    int r = tio(MALI_IOC_PP_START_JOB, &job, 5);
    if (r == -999) { printf("HUNG\n"); return -999; }
    if (r != 0) { printf("START err=%d\n", -r); return r; }

    mali_uk_wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    r = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    if (r == -999) { printf("WAIT HUNG\n"); return -999; }
    if (r != 0) { printf("WAIT err=%d\n", -r); return r; }

    uint32_t status;
    memcpy(&status, notif.data + 8, 4);
    printf("%s", status_str(status));

    if (status & (1 << 16)) {
        printf(" data[0]=0x%08x data[1]=0x%08x data[2]=0x%08x",
               tgt_in_buf[0], tgt_in_buf[1], tgt_in_buf[2]);
    }
    printf("\n");
    return (status & (1 << 16)) ? 0 : -1;
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== 1x1 / small frame WB test ===\n\n");

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

    uint32_t *buf = (uint32_t *)mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE,
                                      MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[+] ready\n\n");

    test_size(buf, 16, 16);  /* baseline known good */
    test_size(buf, 8, 8);
    test_size(buf, 4, 4);
    test_size(buf, 2, 2);
    test_size(buf, 1, 1);

    /* Also test: 1x1 with different pitch values */
    printf("\n  [1x1 pitch variants]\n");
    {
        int pitches[] = { 1, 2, 4, 8 };
        for (int i = 0; i < 4; i++) {
            memset(buf, 0, BUF_SIZE);
            memset((uint8_t *)buf + 0x200, 0, 64);

            static const uint32_t shader[] = {
                0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
            };
            memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));

            uint32_t *plb = buf;
            uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
            plb[0] = 0x00000000;
            plb[1] = 0xB8000000;
            plb[2] = 0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u);
            plb[3] = 0xBC000000;

            uint32_t *rsw = (uint32_t *)((uint8_t *)buf + 0x100);
            rsw[0x08] = 0x0000F008;
            rsw[0x09] = (GPU_VA_DATA + 0x080) | 5;
            rsw[0x0D] = 0x00000100;

            uint32_t wb_tgt = GPU_VA_DATA + 0x3000;
            uint32_t *tgt = (uint32_t *)((uint8_t *)buf + 0x3000);
            tgt[0] = 0xDEADBEEF;

            mali_uk_pp_start_job_s job;
            memset(&job, 0, sizeof(job));
            job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
            job.num_cores = 1;
            job.frame_registers[FR_PLBU_ARRAY_ADDR] = GPU_VA_DATA + 0x000;
            job.frame_registers[FR_RENDER_ADDR]     = GPU_VA_DATA + 0x100;
            job.frame_registers[FR_FLAGS]           = 0x01;
            job.frame_registers[FR_CLEAR_COLOR_0]   = 0x41424344;
            job.frame_registers[FR_CLEAR_COLOR_1]   = 0x41424344;
            job.frame_registers[FR_CLEAR_COLOR_2]   = 0x41424344;
            job.frame_registers[FR_CLEAR_COLOR_3]   = 0x41424344;
            job.frame_registers[FR_WIDTH]           = 1;
            job.frame_registers[FR_HEIGHT]          = 1;
            job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + 0x1000;
            job.frame_registers[FR_FRAG_STACK_SIZE] = 0x400;

            job.wb0_registers[WB_TYPE]         = 0x02;
            job.wb0_registers[WB_ADDRESS]      = wb_tgt;
            job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
            job.wb0_registers[WB_DOWNSAMPLE]   = 0;
            job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
            job.wb0_registers[WB_PITCH]        = pitches[i];
            job.wb0_registers[WB_TARGET_FLAGS] = 0;
            job.wb0_registers[WB_MRT_ENABLE]   = 0;

            job.fence.sync_fd = -1;
            uint32_t tl = 0;
            job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

            __builtin___clear_cache((char *)buf, (char *)buf + BUF_SIZE);

            printf("    pitch=%d: ", pitches[i]);
            int r = tio(MALI_IOC_PP_START_JOB, &job, 5);
            if (r == -999) { printf("HUNG\n"); break; }
            if (r != 0) { printf("START err=%d\n", -r); continue; }

            mali_uk_wait_for_notification_s notif;
            memset(&notif, 0, sizeof(notif));
            r = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
            if (r == -999) { printf("WAIT HUNG\n"); break; }
            if (r != 0) { printf("WAIT err=%d\n", -r); continue; }

            uint32_t status;
            memcpy(&status, notif.data + 8, 4);
            printf("%s", status_str(status));
            if (status & (1 << 16)) {
                printf(" data[0]=0x%08x", tgt[0]);
            }
            printf("\n");
        }
    }

    munmap(buf, BUF_SIZE);
    close(fd);
    printf("\n=== done ===\n");
    return 0;
}
