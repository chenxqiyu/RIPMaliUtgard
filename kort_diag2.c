/*
 * kort_diag2.c - GPU 执行失败定位 (UNKNOWN_ERR)
 *
 * 已确认: job 入队成功, 是 GPU 硬件执行失败 (无 MMU fault 日志)
 * 本程序矩阵测试:
 *   T1: 纯 clear (WB 全零)          -> 验证 PLB/RSW/frame_regs 基本通路
 *   T2: clear + WB0 (原 kort 配置)  -> WB 路径
 *   T3: T2 + cacheflush dcache      -> cache 一致性
 *   T4: T2 + num_cores=2 (M450 双核)
 * 每个测试带执行时间 (软件路径 <1ms, GPU 路径 >5ms)
 *
 * 修复: sigaction 无 SA_RESTART (alarm 能真正中断阻塞 ioctl)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define MALI_IOC_MEM_ALLOC  0xC0288300
#define MALI_IOC_PP_START_JOB       0xC1988400
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202

typedef struct {
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t vsize;
    uint32_t psize;
    uint32_t flags;
    uint64_t backend_handle;
    int32_t  secure_shared_fd;
} alloc_mem_s;

typedef struct { uint32_t points[3]; int32_t sync_fd; } mali_uk_fence_t;

typedef struct {
    uint64_t ctx;
    uint64_t user_job_ptr;
    uint32_t priority;
    uint32_t frame_registers[23];
    uint32_t frame_registers_addr_frame[7];
    uint32_t frame_registers_addr_stack[7];
    uint32_t wb0_registers[12];
    uint32_t wb1_registers[12];
    uint32_t wb2_registers[12];
    uint32_t dlbu_registers[4];
    uint32_t num_cores;
    uint32_t perf_counter_flag;
    uint32_t perf_counter_src0;
    uint32_t perf_counter_src1;
    uint32_t frame_builder_id;
    uint32_t flush_id;
    uint32_t flags;
    uint32_t tilesx;
    uint32_t tilesy;
    uint32_t heatmap_mem;
    uint32_t num_memory_cookies;
    uint64_t memory_cookies;
    mali_uk_fence_t fence;
    uint64_t timeline_point_ptr;
} pp_start_job_s;

typedef struct {
    uint64_t ctx;
    uint32_t type;
    uint32_t _pad;
    uint8_t  data[88];
} wait_for_notification_s;

#define FR_PLBU_ARRAY_ADDR   0
#define FR_RENDER_ADDR       1
#define FR_FLAGS             3
#define FR_CLEAR_DEPTH       4
#define FR_CLEAR_STENCIL     5
#define FR_CLEAR_COLOR_0     6
#define FR_CLEAR_COLOR_1     7
#define FR_CLEAR_COLOR_2     8
#define FR_CLEAR_COLOR_3     9
#define FR_WIDTH            10
#define FR_HEIGHT           11
#define FR_FRAG_STACK_ADDR  12
#define FR_FRAG_STACK_SIZE  13
#define FR_DUBYA            18
#define FR_BLOCKING         20
#define FR_SCALE            21
#define FR_FOUREIGHT        22

#define WB_TYPE           0
#define WB_ADDRESS        1
#define WB_PIXEL_FORMAT   2
#define WB_DOWNSAMPLE     3
#define WB_PIXEL_LAYOUT   4
#define WB_PITCH          5
#define WB_MRT_BITS       6

#define _MALI_NOTIFICATION_PP_FINISHED ((2 << 16) | 0x10)

#define GPU_VA_DATA  0x40000000u
#define BUF_SIZE     0x4000

static const uint32_t fragment_shader[] = {
    0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
};

static volatile int g_to = 0;
static void alh(int s) { g_to = 1; }

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int tio(int fd, unsigned int cmd, void *buf, int t) {
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno;
    alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

static const char *status_str(uint32_t s) {
    if (s & (1<<16)) return "SUCCESS";
    if (s & (1<<23)) return "UNKNOWN_ERR";
    if (s & (1<<21)) return "SEG_FAULT";
    if (s & (1<<22)) return "ILLEGAL_JOB";
    if (s & (1<<20)) return "HANG";
    if (s) return "OTHER";
    return "ZERO";
}

static void dump_buf(const char *tag, volatile uint32_t *p, int n) {
    printf("    %s:", tag);
    for (int i = 0; i < n; i++) printf(" %08x", p[i]);
    printf("\n");
}

/* mode: 0=pure clear, 1=clear+WB, 2=+cacheflush, 3=num_cores=2 */
static int run_test(int fd, uint32_t *buf, int mode, uint32_t value,
                    const char *name)
{
    printf("\n[=== %s (mode=%d) ===]\n", name, mode);

    const uint32_t OFF_PLB = 0x000, OFF_SHADER = 0x080, OFF_RSW = 0x100,
                   OFF_TILEBLK = 0x200, OFF_STACK = 0x1000;

    memset(buf, 0, 0x4000);

    uint32_t gpu_plb       = GPU_VA_DATA + OFF_PLB;
    uint32_t gpu_shader    = GPU_VA_DATA + OFF_SHADER;
    uint32_t gpu_rsw       = GPU_VA_DATA + OFF_RSW;
    uint32_t gpu_tileblock = GPU_VA_DATA + OFF_TILEBLK;
    uint32_t gpu_stack     = GPU_VA_DATA + OFF_STACK;

    memcpy((uint8_t*)buf + OFF_SHADER, fragment_shader, sizeof(fragment_shader));

    uint32_t *rsw = (uint32_t*)((uint8_t*)buf + OFF_RSW);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = gpu_shader | 5;
    rsw[0x0D] = 0x00000100;

    uint32_t *plb = (uint32_t*)buf;
    plb[0] = 0x00000000;
    plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | ((gpu_tileblock >> 3) & ~0xE0000003u);
    plb[3] = 0xB0000000;
    plb[4] = 0x00000000;
    plb[5] = 0xBC000000;

    pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0x11110000 + mode;
    job.priority = 0;
    job.num_cores = (mode == 3) ? 2 : 1;

    job.frame_registers[FR_PLBU_ARRAY_ADDR] = gpu_plb;
    job.frame_registers[FR_RENDER_ADDR]     = gpu_rsw;
    job.frame_registers[FR_FLAGS]           = 0x01;
    job.frame_registers[FR_CLEAR_DEPTH]     = 0x00FFFFFF;
    job.frame_registers[FR_CLEAR_STENCIL]   = 0;
    job.frame_registers[FR_CLEAR_COLOR_0]   = value;
    job.frame_registers[FR_CLEAR_COLOR_1]   = value;
    job.frame_registers[FR_CLEAR_COLOR_2]   = value;
    job.frame_registers[FR_CLEAR_COLOR_3]   = value;
    job.frame_registers[FR_WIDTH]           = 0x100;
    job.frame_registers[FR_HEIGHT]          = 0x100;
    job.frame_registers[FR_FRAG_STACK_ADDR] = gpu_stack;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0;
    job.frame_registers[FR_DUBYA]           = 0x77;
    job.frame_registers[FR_BLOCKING]        = 0;
    job.frame_registers[FR_SCALE]           = 0x0C;
    job.frame_registers[FR_FOUREIGHT]       = 0x8888;

    if (mode >= 1) {
        job.wb0_registers[WB_TYPE]         = 0x02;
        job.wb0_registers[WB_ADDRESS]      = GPU_VA_DATA + 0x3000;
        job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
        job.wb0_registers[WB_DOWNSAMPLE]   = 0;
        job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
        job.wb0_registers[WB_PITCH]        = (16 * 4) / 8;
        job.wb0_registers[WB_MRT_BITS]     = 4;
    }

    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    if (mode == 2)
        syscall(0x0f0002, buf, (char*)buf + 0x4000, 0);  /* __ARM_NR_cacheflush */
    else
        __builtin___clear_cache((char*)buf, (char*)buf + 0x4000);

    double t0 = now_ms();
    int r = tio(fd, MALI_IOC_PP_START_JOB, &job, 5);
    double t1 = now_ms();
    if (r == -999) { printf("  [-] START TIMEOUT\n"); return -999; }
    if (r != 0) { printf("  [-] START err=%d (%s)\n", -r, strerror(-r)); return r; }

    wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    r = tio(fd, MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    double t2 = now_ms();
    if (r == -999) { printf("  [-] WAIT TIMEOUT\n"); return -999; }
    if (r != 0) { printf("  [-] WAIT err=%d\n", -r); return r; }

    printf("  [*] start=%.2fms wait=%.2fms total=%.2fms type=0x%08x\n",
           t1 - t0, t2 - t1, t2 - t0, notif.type);
    printf("  [*] timeline_point=%u\n", tl);

    if (notif.type == _MALI_NOTIFICATION_PP_FINISHED) {
        uint64_t ujp; uint32_t status;
        memcpy(&ujp, notif.data, 8);
        memcpy(&status, notif.data + 8, 4);
        printf("  [*] status=0x%08x (%s) user_job_ptr=0x%llx\n",
               status, status_str(status), (unsigned long long)ujp);
        return (status & (1<<16)) ? 0 : -1;
    }
    return -2;
}

int main(void) {
    /* 关键修复: 无 SA_RESTART, alarm 才能中断阻塞的 ioctl */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_diag2 - GPU exec failure isolation\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    int r = tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3);
    if (r != 0) { printf("[-] ALLOC err=%d\n", -r); return 1; }

    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap: %s\n", strerror(errno)); return 1; }
    printf("[+] alloc+mmap OK backend=0x%llx\n",
           (unsigned long long)alloc.backend_handle);

    volatile uint32_t *verify = (volatile uint32_t *)((uint8_t*)buf + 0x3000);

    int results[4] = {-9,-9,-9,-9};
    results[0] = run_test(fd, (uint32_t*)buf, 0, 0xC0DE0001, "T1 pure-clear");
    results[1] = run_test(fd, (uint32_t*)buf, 1, 0xC0DE0002, "T2 clear+WB");
    printf("  [*] WB target after T2: %08x (expect c0de0002)\n", *verify);
    results[2] = run_test(fd, (uint32_t*)buf, 2, 0xC0DE0003, "T3 +cacheflush");
    printf("  [*] WB target after T3: %08x (expect c0de0003)\n", *verify);
    results[3] = run_test(fd, (uint32_t*)buf, 3, 0xC0DE0004, "T4 num_cores=2");
    printf("  [*] WB target after T4: %08x (expect c0de0004)\n", *verify);

    printf("\n[summary] T1=%d T2=%d T3=%d T4=%d  (0=SUCCESS)\n",
           results[0], results[1], results[2], results[3]);
    printf("[note] total<1ms => 软件路径(job 没上 GPU); >5ms => GPU 真的执行了\n");
    munmap(buf, BUF_SIZE);
    close(fd);
    return 0;
}
