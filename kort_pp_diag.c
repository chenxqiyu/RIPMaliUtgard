/*
 * kort_pp_diag.c - Systematic PP job diagnosis for Mali-450 r10p1
 *
 * Goal: find why PP jobs return UNKNOWN_ERR (0x00800000) instead of SUCCESS.
 * We start from the simplest possible job and add complexity step by step.
 *
 * Build:
 *   armv7a-linux-androideabi24-clang.cmd kort_pp_diag.c -o kort_pp_diag -static
 *   adb push kort_pp_diag /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/kort_pp_diag
 *   adb shell /data/local/tmp/kort_pp_diag
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

/* ---- ioctl numbers (from mali.ko r10p1 disasm, verified by probes) ---- */
#define MALI_IOC_MEM_ALLOC      0xC0288300u
#define MALI_IOC_MEM_FREE       0xC0108301u
#define MALI_IOC_PP_START_JOB   0xC1988400u
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202u

#define _MALI_NOTIFICATION_PP_FINISHED ((2 << 16) | 0x10)

/* ---- structs (32-bit userland layout, 408 / 104 bytes) ---- */
typedef struct {
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t vsize;
    uint32_t psize;
    uint32_t flags;
    uint64_t backend_handle;
    int32_t  secure_shared_fd;
} mali_uk_alloc_mem_s;  /* 40 bytes */

#define MALI_UK_TIMELINE_MAX 3
typedef struct {
    uint32_t points[MALI_UK_TIMELINE_MAX];
    int32_t  sync_fd;
} mali_uk_fence_t;

typedef struct {
    uint64_t ctx;                              /* 0-7 */
    uint64_t user_job_ptr;                     /* 8-15 */
    uint32_t priority;                         /* 16-19 */
    uint32_t frame_registers[23];              /* 20-111 */
    uint32_t frame_registers_addr_frame[7];    /* 112-139 */
    uint32_t frame_registers_addr_stack[7];    /* 140-167 */
    uint32_t wb0_registers[12];                /* 168-215 */
    uint32_t wb1_registers[12];                /* 216-263 */
    uint32_t wb2_registers[12];                /* 264-311 */
    uint32_t dlbu_registers[4];                /* 312-327 */
    uint32_t num_cores;                        /* 328-331 */
    uint32_t perf_counter_flag;                /* 332-335 */
    uint32_t perf_counter_src0;                /* 336-339 */
    uint32_t perf_counter_src1;                /* 340-343 */
    uint32_t frame_builder_id;                 /* 344-347 */
    uint32_t flush_id;                         /* 348-351 */
    uint32_t flags;                            /* 352-355 */
    uint32_t tilesx;                           /* 356-359 */
    uint32_t tilesy;                           /* 360-363 */
    uint32_t heatmap_mem;                      /* 364-367 */
    uint32_t num_memory_cookies;               /* 368-371 */
    uint64_t memory_cookies;                   /* 372-379 */
    mali_uk_fence_t fence;                     /* 380-395 */
    uint64_t timeline_point_ptr;               /* 396-403 */
} mali_uk_pp_start_job_s;  /* 408 bytes */

typedef struct {
    uint64_t ctx;
    uint32_t type;
    uint32_t _pad;
    uint8_t  data[88];
} mali_uk_wait_for_notification_s;  /* 104 bytes */

/* ---- frame register indices ---- */
#define FR_PLBU_ARRAY_ADDR 0
#define FR_RENDER_ADDR     1
#define FR_FLAGS           3
#define FR_CLEAR_DEPTH     4
#define FR_CLEAR_STENCIL   5
#define FR_CLEAR_COLOR_0   6
#define FR_WIDTH          10
#define FR_HEIGHT         11
#define FR_FRAG_STACK_ADDR 12
#define FR_FRAG_STACK_SIZE 13

/* ---- WB register indices (r10p1 hardware layout) ---- */
#define WB_TYPE         0  /* Source Select: 0=disabled, 2=color */
#define WB_ADDRESS      1  /* Target Address */
#define WB_PIXEL_FORMAT 2  /* Target Pixel Format */
#define WB_DOWNSAMPLE   3  /* Target AA Format */
#define WB_PIXEL_LAYOUT 4  /* Target Layout */
#define WB_PITCH        5  /* Target Scanline Length */
#define WB_TARGET_FLAGS 6  /* Target Flags */
#define WB_MRT_ENABLE   7  /* MRT Enable */

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
    if (s & (1 << 17)) return "OUT_OF_MEMORY";
    if (s & (1 << 18)) return "ABORT";
    if (s & (1 << 19)) return "TIMEOUT_SW";
    if (s & (1 << 20)) return "HANG";
    if (s & (1 << 21)) return "SEG_FAULT";
    if (s & (1 << 22)) return "ILLEGAL_JOB";
    if (s & (1 << 23)) return "UNKNOWN_ERR";
    return "???";
}

/*
 * Submit a PP job with given configuration.
 * plb_words: pointer to PLB data (in GPU buffer at offset 0)
 * plb_nwords: number of u32 words in PLB
 * rsw_words: pointer to RSW data (at offset 0x100) - can be NULL
 * rsw_nwords: number of u32 words in RSW
 * fr_flags: FR_FLAGS register value
 * wb_enabled: 0=WB disabled, 1=WB enabled
 * wb_target: GPU VA of writeback target (only if wb_enabled)
 * width, height: frame dimensions
 * has_shader: if 0, shader-related RSW entries are skipped
 */
static int submit_pp_job(uint32_t *buf,
                         const uint32_t *plb_words, int plb_nwords,
                         const uint32_t *rsw_words, int rsw_nwords,
                         uint32_t fr_flags,
                         int wb_enabled, uint32_t wb_target,
                         uint32_t width, uint32_t height,
                         uint32_t stack_size,
                         int has_shader,
                         const char *test_name)
{
    printf("  [%s] ", test_name);
    memset(buf, 0, BUF_SIZE);

    /* Copy PLB to offset 0 */
    if (plb_words && plb_nwords > 0) {
        memcpy(buf, plb_words, plb_nwords * 4);
    }

    /* Copy RSW to offset 0x100 */
    if (rsw_words && rsw_nwords > 0) {
        memcpy((uint8_t *)buf + 0x100, rsw_words, rsw_nwords * 4);
    }

    mali_uk_pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

    job.frame_registers[FR_PLBU_ARRAY_ADDR] = GPU_VA_DATA + 0x000;  /* PLB at offset 0 */
    job.frame_registers[FR_RENDER_ADDR]     = GPU_VA_DATA + 0x100;  /* RSW at offset 0x100 */
    job.frame_registers[FR_FLAGS]           = fr_flags;
    job.frame_registers[FR_WIDTH]           = width;
    job.frame_registers[FR_HEIGHT]          = height;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + 0x1000; /* stack at 0x1000 */
    job.frame_registers[FR_FRAG_STACK_SIZE] = stack_size;

    if (wb_enabled) {
        job.wb0_registers[WB_TYPE]         = 0x02;   /* color source */
        job.wb0_registers[WB_ADDRESS]      = wb_target;
        job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;   /* RGBA8888 */
        job.wb0_registers[WB_DOWNSAMPLE]   = 0;
        job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
        job.wb0_registers[WB_PITCH]        = (width * 4) / 8;
        job.wb0_registers[WB_TARGET_FLAGS] = 0;
        job.wb0_registers[WB_MRT_ENABLE]   = 0;
    }

    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    /* Flush caches */
    __builtin___clear_cache((char *)buf, (char *)buf + BUF_SIZE);

    int r = tio(MALI_IOC_PP_START_JOB, &job, 5);
    if (r == -999) { printf("PP_START_JOB TIMEOUT (HUNG!)\n"); return -999; }
    if (r != 0) { printf("PP_START_JOB err=%d (%s)\n", -r, strerror(-r)); return r; }

    mali_uk_wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    r = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    if (r == -999) { printf("WAIT TIMEOUT (HUNG!)\n"); return -999; }
    if (r != 0) { printf("WAIT err=%d (%s)\n", -r, strerror(-r)); return r; }

    if (notif.type != _MALI_NOTIFICATION_PP_FINISHED) {
        printf("unexpected notif type 0x%08x\n", notif.type);
        return -2;
    }

    uint32_t status;
    memcpy(&status, notif.data + 8, 4);
    printf("status=0x%08x (%s)", status, status_str(status));

    /* If WB enabled and success, verify the write */
    if (wb_enabled && (status & (1 << 16))) {
        uint32_t *target = (uint32_t *)((uint8_t *)buf + (wb_target - GPU_VA_DATA));
        printf(", first_word=0x%08x", *target);
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

    printf("=== PP Job Diagnosis (Mali-450 r10p1) ===\n\n");

    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali (fd=%d)\n", fd);

    /* Allocate GPU memory */
    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    int r = tio(MALI_IOC_MEM_ALLOC, &alloc, 3);
    if (r != 0) { printf("[-] ALLOC_MEM: %s\n", strerror(-r)); return 1; }
    printf("[+] ALLOC_MEM OK\n");

    uint32_t *buf = (uint32_t *)mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE,
                                      MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[+] mmap OK (%p)\n\n", buf);

    /* ================================================================
     * Test 1: Minimal PLB - only a single tile with terminator
     * This is the absolute minimum PLB that should produce END_OF_FRAME.
     * ================================================================ */
    printf("--- Test 1: Minimal PLB (1 tile, no shader, no WB) ---\n");
    {
        uint32_t plb[] = {
            0x00000000,  /* NOP */
            0xB8000000,  /* tile header (0,0) */
            0xB0000000,  /* ??? */
            0x00000000,  /* NOP terminator */
            0xBC000000,  /* final terminator */
        };
        uint32_t rsw[] = { 0 };  /* all zeros */

        submit_pp_job(buf, plb, 5, rsw, 1,
                      0x01,    /* FR_FLAGS */
                      0,       /* no WB */
                      0,       /* wb_target */
                      16, 16,  /* 16x16 */
                      0x400,   /* stack size */
                      0,       /* no shader */
                      "T1:min-plb");
    }

    /* ================================================================
     * Test 2: Same as Test 1 but with tile block pointer
     * ================================================================ */
    printf("\n--- Test 2: PLB with tile block (no shader, no WB) ---\n");
    {
        /* Tile block at offset 0x200 - all zeros = empty tile */
        memset((uint8_t *)buf + 0x200, 0, 64);

        uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;

        uint32_t plb[] = {
            0x00000000,  /* NOP */
            0xB8000000,  /* tile header (0,0) */
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),  /* tile data ptr */
            0xB0000000,  /* ??? */
            0x00000000,  /* NOP terminator */
            0xBC000000,  /* final terminator */
        };
        uint32_t rsw[] = { 0 };

        submit_pp_job(buf, plb, 6, rsw, 1,
                      0x01,
                      0, 0,
                      16, 16,
                      0x400,
                      0,
                      "T2:tile-blk");
    }

    /* ================================================================
     * Test 3: With fragment shader (constant color)
     * ================================================================ */
    printf("\n--- Test 3: With constant-color shader (no WB) ---\n");
    {
        static const uint32_t shader[] = {
            0x00020425,
            0x0000000c,
            0x01e007cf,
            0xb0000000,
            0x000005f5,
        };
        /* Copy shader to offset 0x080 */
        memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));

        memset((uint8_t *)buf + 0x200, 0, 64);  /* tile block */
        uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
        uint32_t shader_gpu = GPU_VA_DATA + 0x080;

        uint32_t plb[] = {
            0x00000000,
            0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xB0000000,
            0x00000000,
            0xBC000000,
        };

        /* RSW with shader pointer */
        uint32_t rsw[32] = { 0 };
        rsw[0x08] = 0x0000F008;
        rsw[0x09] = shader_gpu | 5;
        rsw[0x0D] = 0x00000100;

        submit_pp_job(buf, plb, 6, rsw, 32,
                      0x01,
                      0, 0,
                      16, 16,
                      0x400,
                      1,
                      "T3:shader");
    }

    /* ================================================================
     * Test 4: With shader + WB enabled (write to GPU own memory)
     * ================================================================ */
    printf("\n--- Test 4: Shader + WB (write to GPU own memory) ---\n");
    {
        static const uint32_t shader[] = {
            0x00020425,
            0x0000000c,
            0x01e007cf,
            0xb0000000,
            0x000005f5,
        };
        memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));

        memset((uint8_t *)buf + 0x200, 0, 64);
        uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
        uint32_t shader_gpu = GPU_VA_DATA + 0x080;
        uint32_t wb_target = GPU_VA_DATA + 0x3000;

        /* Pre-fill target with 0xDEAD to verify write */
        uint32_t *target_in_buf = (uint32_t *)((uint8_t *)buf + 0x3000);
        *target_in_buf = 0xDEADBEEF;

        uint32_t plb[] = {
            0x00000000,
            0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xB0000000,
            0x00000000,
            0xBC000000,
        };

        uint32_t rsw[32] = { 0 };
        rsw[0x08] = 0x0000F008;
        rsw[0x09] = shader_gpu | 5;
        rsw[0x0D] = 0x00000100;

        submit_pp_job(buf, plb, 6, rsw, 32,
                      0x01,
                      1, wb_target,
                      16, 16,
                      0x400,
                      1,
                      "T4:shader+wb");
    }

    /* ================================================================
     * Test 5: Different FR_FLAGS values
     * ================================================================ */
    printf("\n--- Test 5: FR_FLAGS variants ---\n");
    {
        static const uint32_t shader[] = {
            0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
        };
        memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));
        memset((uint8_t *)buf + 0x200, 0, 64);

        uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
        uint32_t shader_gpu = GPU_VA_DATA + 0x080;

        uint32_t plb[] = {
            0x00000000, 0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xB0000000, 0x00000000, 0xBC000000,
        };

        uint32_t rsw[32] = { 0 };
        rsw[0x08] = 0x0000F008;
        rsw[0x09] = shader_gpu | 5;
        rsw[0x0D] = 0x00000100;

        uint32_t flags[] = { 0x00, 0x01, 0x02, 0x03, 0x10, 0x11 };
        const char *fnames[] = { "0x00", "0x01", "0x02", "0x03", "0x10", "0x11" };
        for (int i = 0; i < 6; i++) {
            char name[32];
            snprintf(name, sizeof(name), "flags=%s", fnames[i]);
            submit_pp_job(buf, plb, 6, rsw, 32,
                          flags[i],
                          0, 0,
                          16, 16,
                          0x400,
                          1,
                          name);
        }
    }

    /* ================================================================
     * Test 6: 1x1 frame (smallest possible)
     * ================================================================ */
    printf("\n--- Test 6: 1x1 frame size ---\n");
    {
        static const uint32_t shader[] = {
            0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
        };
        memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));
        memset((uint8_t *)buf + 0x200, 0, 64);

        uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
        uint32_t shader_gpu = GPU_VA_DATA + 0x080;
        uint32_t wb_target = GPU_VA_DATA + 0x3000;

        uint32_t plb[] = {
            0x00000000, 0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xB0000000, 0x00000000, 0xBC000000,
        };

        uint32_t rsw[32] = { 0 };
        rsw[0x08] = 0x0000F008;
        rsw[0x09] = shader_gpu | 5;
        rsw[0x0D] = 0x00000100;

        submit_pp_job(buf, plb, 6, rsw, 32,
                      0x01,
                      1, wb_target,
                      1, 1,
                      0x400,
                      1,
                      "T6:1x1+wb");
    }

    /* ================================================================
     * Test 7: Different PLB tile header encoding
     * ================================================================ */
    printf("\n--- Test 7: PLB tile header variants ---\n");
    {
        static const uint32_t shader[] = {
            0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
        };
        memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));
        memset((uint8_t *)buf + 0x200, 0, 64);

        uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
        uint32_t shader_gpu = GPU_VA_DATA + 0x080;

        uint32_t rsw[32] = { 0 };
        rsw[0x08] = 0x0000F008;
        rsw[0x09] = shader_gpu | 5;
        rsw[0x0D] = 0x00000100;

        /* Variant A: B8 first tile, then BC terminator (no B0) */
        uint32_t plb_a[] = {
            0x00000000,
            0xB8000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xBC000000,
        };
        submit_pp_job(buf, plb_a, 4, rsw, 32,
                      0x01, 0, 0, 16, 16, 0x400, 1, "T7a:no-B0");

        /* Variant B: B8 tile with B4 sub-tile header */
        uint32_t plb_b[] = {
            0x00000000,
            0xB8000000,
            0xB4000000,
            0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u),
            0xB0000000,
            0x00000000,
            0xBC000000,
        };
        submit_pp_job(buf, plb_b, 7, rsw, 32,
                      0x01, 0, 0, 16, 16, 0x400, 1, "T7b:B4-subtile");
    }

    printf("\n=== Diagnosis complete ===\n");

    munmap(buf, BUF_SIZE);
    close(fd);
    return 0;
}
