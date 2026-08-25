/*
 * kort_pp_diag2.c - Phase 2: build on the working PLB (no B0 instruction)
 *
 * T7a worked: PLB = [NOP, B8, tile_ptr, BC] (no B0)
 * Now add shader, then WB, to verify write primitive works.
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
    if (s & (1 << 22)) return "ILLEGAL_JOB";
    if (s & (1 << 21)) return "SEG_FAULT";
    if (s & (1 << 20)) return "HANG";
    return "???";
}

static int run_job(uint32_t *buf, const char *name,
                   const uint32_t *plb, int plb_nw,
                   const uint32_t *rsw, int rsw_nw,
                   int wb_en, uint32_t wb_tgt,
                   uint32_t w, uint32_t h,
                   uint32_t clear_color)
{
    printf("  [%s] ", name);
    memset(buf, 0, BUF_SIZE);
    if (plb && plb_nw > 0) memcpy(buf, plb, plb_nw * 4);
    if (rsw && rsw_nw > 0) memcpy((uint8_t *)buf + 0x100, rsw, rsw_nw * 4);

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
    job.frame_registers[FR_WIDTH]           = w;
    job.frame_registers[FR_HEIGHT]          = h;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + 0x1000;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0x400;

    if (wb_en) {
        job.wb0_registers[WB_TYPE]         = 0x02;
        job.wb0_registers[WB_ADDRESS]      = wb_tgt;
        job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
        job.wb0_registers[WB_DOWNSAMPLE]   = 0;
        job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
        job.wb0_registers[WB_PITCH]        = (w * 4) / 8;
        job.wb0_registers[WB_TARGET_FLAGS] = 0;
        job.wb0_registers[WB_MRT_ENABLE]   = 0;
    }

    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    __builtin___clear_cache((char *)buf, (char *)buf + BUF_SIZE);

    int r = tio(MALI_IOC_PP_START_JOB, &job, 5);
    if (r == -999) { printf("PP_START_JOB TIMEOUT\n"); return -999; }
    if (r != 0) { printf("PP_START_JOB err=%d (%s)\n", -r, strerror(-r)); return r; }

    mali_uk_wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    r = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    if (r == -999) { printf("WAIT TIMEOUT\n"); return -999; }
    if (r != 0) { printf("WAIT err=%d (%s)\n", -r, strerror(-r)); return r; }

    if (notif.type != _MALI_NOTIFICATION_PP_FINISHED) {
        printf("notif=0x%08x (not PP_FINISHED)\n", notif.type);
        return -2;
    }

    uint32_t status;
    memcpy(&status, notif.data + 8, 4);
    printf("status=0x%08x (%s)", status, status_str(status));

    if (wb_en && (status & (1 << 16))) {
        uint32_t off = wb_tgt - GPU_VA_DATA;
        uint32_t *p = (uint32_t *)((uint8_t *)buf + off);
        printf(", wb_data[0]=0x%08x", *p);
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

    printf("=== PP Job Diagnosis Phase 2 ===\n\n");

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
    printf("[+] ALLOC + mmap OK\n\n");

    uint32_t *buf = (uint32_t *)mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE,
                                      MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }

    uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
    uint32_t shader_gpu  = GPU_VA_DATA + 0x080;
    uint32_t wb_tgt      = GPU_VA_DATA + 0x3000;

    /* Tile block data (empty tile) */
    memset((uint8_t *)buf + 0x200, 0, 64);

    /* Fragment shader: constant color from clear_color register */
    static const uint32_t shader[] = {
        0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
    };
    memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));

    /* RSW setup */
    uint32_t rsw[32] = { 0 };
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = shader_gpu | 5;
    rsw[0x0D] = 0x00000100;

    /* ---- Baseline: working PLB from T7a (no B0) ---- */
    printf("--- Baseline: working PLB (no B0, no shader, no WB) ---\n");
    {
        uint32_t plb[] = {
            0x00000000,
            0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xBC000000,
        };
        run_job(buf, "baseline", plb, 4, NULL, 0, 0, 0, 16, 16, 0);
    }

    /* ---- Test A: add shader (no WB) ---- */
    printf("\n--- Test A: add shader (no WB) ---\n");
    {
        uint32_t plb[] = {
            0x00000000,
            0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xBC000000,
        };
        run_job(buf, "+shader", plb, 4, rsw, 32, 0, 0, 16, 16, 0x42424242);
    }

    /* ---- Test B: shader + WB (write clear_color to GPU memory) ---- */
    printf("\n--- Test B: shader + WB (write to GPU own mem) ---\n");
    {
        uint32_t plb[] = {
            0x00000000,
            0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xBC000000,
        };
        /* Pre-fill with 0xDEAD to see if write changes it */
        uint32_t *p = (uint32_t *)((uint8_t *)buf + 0x3000);
        p[0] = 0xDEADBEEF;
        p[1] = 0xDEADBEEF;
        run_job(buf, "+WB", plb, 4, rsw, 32, 1, wb_tgt, 16, 16, 0x41424344);
    }

    /* ---- Test C: WB with different pitch values ---- */
    printf("\n--- Test C: WB pitch variants ---\n");
    {
        uint32_t plb[] = {
            0x00000000,
            0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xBC000000,
        };

        /* Try different pitch formulas */
        uint32_t pitches[] = {
            (16 * 4),       /* 64 - bytes per row */
            (16 * 4) / 8,   /*  8 - kort legacy (pitch in 8-byte units?) */
            16,             /* 16 - pixels per row */
            (16 * 2),       /* 32 - half bytes? */
        };
        const char *pnames[] = { "pitch=64(=W*4)", "pitch=8(=W*4/8)", "pitch=16(=W)", "pitch=32(=W*2)" };

        for (int i = 0; i < 4; i++) {
            /* Re-setup job with custom pitch */
            memset(buf, 0, BUF_SIZE);
            memcpy(buf, plb, sizeof(plb));
            memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));
            memcpy((uint8_t *)buf + 0x100, rsw, sizeof(rsw));
            memset((uint8_t *)buf + 0x200, 0, 64);

            uint32_t *p = (uint32_t *)((uint8_t *)buf + 0x3000);
            p[0] = 0xDEADBEEF;

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
            job.frame_registers[FR_WIDTH]           = 16;
            job.frame_registers[FR_HEIGHT]          = 16;
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

            printf("  [%s] ", pnames[i]);
            int r = tio(MALI_IOC_PP_START_JOB, &job, 5);
            if (r == -999) { printf("TIMEOUT\n"); continue; }
            if (r != 0) { printf("START err=%d\n", -r); continue; }

            mali_uk_wait_for_notification_s notif;
            memset(&notif, 0, sizeof(notif));
            r = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
            if (r == -999) { printf("WAIT TIMEOUT\n"); continue; }
            if (r != 0) { printf("WAIT err=%d\n", -r); continue; }

            uint32_t status;
            memcpy(&status, notif.data + 8, 4);
            printf("status=0x%08x (%s)", status, status_str(status));
            if (status & (1 << 16)) {
                uint32_t *p2 = (uint32_t *)((uint8_t *)buf + 0x3000);
                printf(", data[0]=0x%08x", *p2);
            }
            printf("\n");
        }
    }

    /* ---- Test D: verify WB write actually lands (pattern check) ---- */
    printf("\n--- Test D: full WB verification (16x16 RGBA8888 = 1024 bytes) ---\n");
    {
        uint32_t plb[] = {
            0x00000000,
            0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xBC000000,
        };

        /* Fill target with 0x55 first */
        memset((uint8_t *)buf + 0x3000, 0x55, 1024);

        /* Use pitch = W * 4 = 64 (bytes per row) */
        memset(buf, 0, BUF_SIZE);
        memcpy(buf, plb, sizeof(plb));
        memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));
        memcpy((uint8_t *)buf + 0x100, rsw, sizeof(rsw));
        memset((uint8_t *)buf + 0x200, 0, 64);

        mali_uk_pp_start_job_s job;
        memset(&job, 0, sizeof(job));
        job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
        job.num_cores = 1;
        job.frame_registers[FR_PLBU_ARRAY_ADDR] = GPU_VA_DATA + 0x000;
        job.frame_registers[FR_RENDER_ADDR]     = GPU_VA_DATA + 0x100;
        job.frame_registers[FR_FLAGS]           = 0x01;
        job.frame_registers[FR_CLEAR_COLOR_0]   = 0xDEADBEEF;
        job.frame_registers[FR_CLEAR_COLOR_1]   = 0xDEADBEEF;
        job.frame_registers[FR_CLEAR_COLOR_2]   = 0xDEADBEEF;
        job.frame_registers[FR_CLEAR_COLOR_3]   = 0xDEADBEEF;
        job.frame_registers[FR_WIDTH]           = 16;
        job.frame_registers[FR_HEIGHT]          = 16;
        job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + 0x1000;
        job.frame_registers[FR_FRAG_STACK_SIZE] = 0x400;

        job.wb0_registers[WB_TYPE]         = 0x02;
        job.wb0_registers[WB_ADDRESS]      = wb_tgt;
        job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
        job.wb0_registers[WB_DOWNSAMPLE]   = 0;
        job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
        job.wb0_registers[WB_PITCH]        = 16 * 4;  /* 64 bytes per row */
        job.wb0_registers[WB_TARGET_FLAGS] = 0;
        job.wb0_registers[WB_MRT_ENABLE]   = 0;

        job.fence.sync_fd = -1;
        uint32_t tl = 0;
        job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

        __builtin___clear_cache((char *)buf, (char *)buf + BUF_SIZE);

        printf("  [full-WB] ");
        int r = tio(MALI_IOC_PP_START_JOB, &job, 5);
        if (r == -999) { printf("TIMEOUT\n"); goto done; }
        if (r != 0) { printf("START err=%d\n", -r); goto done; }

        mali_uk_wait_for_notification_s notif;
        memset(&notif, 0, sizeof(notif));
        r = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
        if (r == -999) { printf("WAIT TIMEOUT\n"); goto done; }
        if (r != 0) { printf("WAIT err=%d\n", -r); goto done; }

        uint32_t status;
        memcpy(&status, notif.data + 8, 4);
        printf("status=0x%08x (%s)\n", status, status_str(status));

        if (status & (1 << 16)) {
            uint32_t *p = (uint32_t *)((uint8_t *)buf + 0x3000);
            printf("    first 8 words: ");
            for (int i = 0; i < 8; i++) printf("0x%08x ", p[i]);
            printf("\n");
            printf("    word[64] (row 1): 0x%08x\n", p[16]);
            printf("    word[255] (last): 0x%08x\n", p[255]);

            /* Count how many words == 0xDEADBEEF */
            int match = 0;
            for (int i = 0; i < 256; i++) if (p[i] == 0xDEADBEEF) match++;
            printf("    words == 0xDEADBEEF: %d / 256\n", match);
        }
    }

done:
    printf("\n=== Phase 2 complete ===\n");
    munmap(buf, BUF_SIZE);
    close(fd);
    return 0;
}
