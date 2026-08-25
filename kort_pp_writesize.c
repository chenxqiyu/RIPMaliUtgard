/*
 * kort_pp_writesize.c - Measure exact WB write size per frame
 *
 * Also test different pixel formats to see if we can get smaller writes.
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
#define WB_OFF       0x2000  /* WB target at offset 0x2000 in buffer */
#define FILL_BYTE    0x55    /* pre-fill pattern */
#define WRITE_BYTE_R 0x41    /* R */
#define WRITE_BYTE_G 0x42    /* G */
#define WRITE_BYTE_B 0x43    /* B */
#define WRITE_BYTE_A 0x44    /* A */

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

/*
 * Run WB job and return number of modified bytes.
 * Pixel format: 0x03=RGBA8888, 0x02=RGB565, 0x01=A8? (guess)
 */
static int test_wb(uint8_t *buf, int w, int h, uint32_t pixfmt, const char *name)
{
    /* Fill target area with FILL_BYTE pattern */
    memset(buf + WB_OFF, FILL_BYTE, 2048);

    /* Tile block (empty) at 0x200 */
    memset(buf + 0x200, 0, 64);

    /* Shader at 0x080 */
    static const uint32_t shader[] = {
        0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
    };
    memcpy(buf + 0x080, shader, sizeof(shader));

    /* FIXED PLB (no B0) */
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

    /* clear_color: ARGB = 0x44414243 -> RGBA bytes = 0x41 0x42 0x43 0x44 */
    uint32_t clear_color = (WRITE_BYTE_A << 24) | (WRITE_BYTE_R << 16) | (WRITE_BYTE_G << 8) | WRITE_BYTE_B;

    uint32_t wb_tgt = GPU_VA_DATA + WB_OFF;

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

    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = wb_tgt;
    job.wb0_registers[WB_PIXEL_FORMAT] = pixfmt;
    job.wb0_registers[WB_DOWNSAMPLE]   = 0;
    job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
    /* pitch = width * bpp, in bytes. For pitch register: in 8-byte units? */
    /* We'll compute based on format: 0x03=4BPP, 0x02=2BPP, 0x01=1BPP */
    int bpp = 4;
    if (pixfmt == 0x02) bpp = 2;
    else if (pixfmt == 0x01) bpp = 1;
    job.wb0_registers[WB_PITCH]        = (w * bpp) / 8;
    if (job.wb0_registers[WB_PITCH] < 1) job.wb0_registers[WB_PITCH] = 1;
    job.wb0_registers[WB_TARGET_FLAGS] = 0;
    job.wb0_registers[WB_MRT_ENABLE]   = 0;

    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    __builtin___clear_cache((char *)buf, (char *)buf + BUF_SIZE);

    printf("  [%-18s] ", name);
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

    if (!(status & (1 << 16))) {
        printf("FAILED (status=0x%08x)\n", status);
        return -1;
    }

    /* Count modified bytes (not FILL_BYTE) */
    int modified = 0;
    int first_mod = -1, last_mod = -1;
    for (int i = 0; i < 2048; i++) {
        if (buf[WB_OFF + i] != FILL_BYTE) {
            modified++;
            if (first_mod < 0) first_mod = i;
            last_mod = i;
        }
    }

    printf("OK %4d bytes (offset 0x%x - 0x%x)", modified, first_mod, last_mod);

    /* Show first 16 bytes */
    printf("  first16:");
    for (int i = 0; i < 16; i++) printf(" %02x", buf[WB_OFF + i]);

    printf("\n");
    return modified;
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== WB Write Size Measurement ===\n\n");

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
    printf("[+] ready (fill=0x%02x, write RGBA=0x%02x 0x%02x 0x%02x 0x%02x)\n\n",
           FILL_BYTE, WRITE_BYTE_R, WRITE_BYTE_G, WRITE_BYTE_B, WRITE_BYTE_A);

    /* RGBA8888 (4 BPP) - baseline */
    printf("--- RGBA8888 (4 BPP, fmt=0x03) ---\n");
    test_wb(buf, 16, 16, 0x03, "16x16 RGBA8888");
    test_wb(buf,  8,  8, 0x03, " 8x8  RGBA8888");
    test_wb(buf,  4,  4, 0x03, " 4x4  RGBA8888");
    test_wb(buf,  2,  2, 0x03, " 2x2  RGBA8888");
    test_wb(buf,  1,  1, 0x03, " 1x1  RGBA8888");

    /* RGB565 (2 BPP) - test if it works */
    printf("\n--- RGB565 (2 BPP, fmt=0x02) ---\n");
    test_wb(buf, 16, 16, 0x02, "16x16 RGB565");
    test_wb(buf,  1,  1, 0x02, " 1x1  RGB565");

    /* A8 (1 BPP) - test if it works (format 0x01?) */
    printf("\n--- A8 (1 BPP, fmt=0x01) ---\n");
    test_wb(buf, 16, 16, 0x01, "16x16 A8(fmt=1)");

    /* Try other format values */
    printf("\n--- Other format values (16x16) ---\n");
    uint32_t fmts[] = { 0x00, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x12, 0x13, 0x15, 0x16, 0x17, 0x18, 0x19 };
    const char *fnames[] = { "0x00", "0x04", "0x05", "0x06", "0x07", "0x08", "0x0B", "0x0C", "0x0E", "0x12", "0x13", "0x15", "0x16", "0x17", "0x18", "0x19" };
    for (int i = 0; i < 16; i++) {
        char label[32];
        snprintf(label, sizeof(label), "16x16 fmt=%s", fnames[i]);
        test_wb(buf, 16, 16, fmts[i], label);
    }

    munmap(buf, BUF_SIZE);
    close(fd);
    printf("\n=== done ===\n");
    return 0;
}
