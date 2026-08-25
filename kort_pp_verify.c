/*
 * kort_pp_verify.c - 验证 Mali PP job 写入原语 (Mi Box S / MIBOX4)
 *
 * 流程:
 *   1. ALLOC_MEM 分配 GPU 内存 (0x40000000, 16KB)
 *   2. mmap 获得 CPU 访问
 *   3. 构造 PP job: WB0 把 clear_color 写到 GPU_VA+0x3000
 *   4. PP_START_JOB + WAIT_FOR_NOTIFICATION
 *   5. 读回验证 GPU 内存是否被写入
 *
 * ioctl 命令值 (从 mali.ko 逆向确认):
 *   MEM_ALLOC 0xC0288300, PP_START_JOB 0xC1988400,
 *   WAIT_FOR_NOTIFICATION 0xC0688202
 *
 * 编译: armv7a-linux-androideabi24-clang kort_pp_verify.c -o kort_pp_verify -static
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

#define MALI_IOC_MEM_ALLOC 0xC0288300
#define MALI_IOC_MEM_FREE  0xC0108301
#define MALI_IOC_PP_START_JOB 0xC1988400
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202

#define PAGE_SIZE 4096

/* ---- 结构体 (32 位用户态布局, 与 mali.ko 驱动匹配) ---- */
typedef struct {
    uint64_t ctx;            /* 0-7  */
    uint32_t gpu_vaddr;      /* 8-11 (输入!) */
    uint32_t vsize;          /* 12-15 */
    uint32_t psize;          /* 16-19 */
    uint32_t flags;          /* 20-23 */
    uint64_t backend_handle; /* 24-31 (输出) */
    int32_t  secure_shared_fd; /* 32-35 */
} alloc_mem_s;               /* 40 bytes */

typedef struct {
    uint64_t ctx;            /* 0-7  */
    uint32_t gpu_vaddr;      /* 8-11 */
    uint32_t free_pages_nr;  /* 12-15 */
} free_mem_s;                /* 16 bytes */

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
    uint64_t ctx;                              /* 0-7 */
    uint64_t user_job_ptr;                     /* 8-15 */
    uint32_t priority;                         /* 16-19 */
    uint32_t frame_registers[23];              /* 20-111 */
    uint32_t frame_registers_addr_frame[7];    /* 112-139 */
    uint32_t frame_registers_addr_stack[7];    /* 140-167 */
    uint32_t wb0_registers[12];                /* 168-215 */
    uint32_t wb1_registers[12];                /* 216-263 */
    uint32_t wb2_registers[12];                /* 264-311 */
    uint32_t dlbu_registers[4];                /* 312-327 */
    uint32_t num_cores;                        /* 328-331 */
    uint32_t perf_counter_flag;                /* 332-335 */
    uint32_t perf_counter_src0;                /* 336-339 */
    uint32_t perf_counter_src1;                /* 340-343 */
    uint32_t frame_builder_id;                 /* 344-347 */
    uint32_t flush_id;                         /* 348-351 */
    uint32_t flags;                            /* 352-355 */
    uint32_t tilesx;                           /* 356-359 */
    uint32_t tilesy;                           /* 360-363 */
    uint32_t heatmap_mem;                      /* 364-367 */
    uint32_t num_memory_cookies;               /* 368-371 */
    uint64_t memory_cookies;                   /* 372-379 */
    mali_uk_fence_t fence;                     /* 380-395 */
    uint64_t timeline_point_ptr;               /* 396-403 */
} pp_start_job_s;                              /* 404 -> 对齐 408 */

typedef struct {
    uint64_t ctx;              /* 0-7 */
    uint32_t type;             /* 8-11 (输出) */
    uint32_t _pad;             /* 12-15 */
    uint8_t  data[88];         /* 16-103 */
} wait_for_notification_s;     /* 104 bytes */

/* ---- PP 硬件寄存器索引 ---- */
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
    if (s & (1<<19)) return "TIMEOUT";
    if (s & (1<<20)) return "HANG";
    if (s & (1<<21)) return "SEG_FAULT";
    if (s & (1<<22)) return "ILLEGAL_JOB";
    if (s & (1<<23)) return "UNKNOWN_ERR";
    return "???";
}

/* 构造并提交一个 PP job: 写 value 到 gpu_target (GPU VA) */
static int submit_wb_job(int fd, uint32_t *buf /*mmap 的 job 数据区*/,
                         uint32_t gpu_data_va, uint32_t gpu_target, uint32_t value,
                         uint32_t *timeline_out)
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
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

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

    /* WB0: 写 value 到 gpu_target */
    job.wb0_registers[WB_TYPE]         = 0x02;       /* color source */
    job.wb0_registers[WB_ADDRESS]      = gpu_target;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;       /* RGBA8888 */
    job.wb0_registers[WB_DOWNSAMPLE]   = 0;
    job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
    job.wb0_registers[WB_PITCH]        = (16 * 4) / 8;
    job.wb0_registers[WB_MRT_BITS]     = 4;

    /* flags bit0=1 (驱动 mali_pp_job_create+0x1f0 检查) */
    job.flags = 0x01;

    job.fence.sync_fd = -1;
    *timeline_out = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)timeline_out;

    /* flush CPU cache -> GPU 可见 */
    msync(buf, 0x4000, MS_SYNC);
    __builtin___clear_cache((char*)buf, (char*)buf + 0x4000);

    /* 提交 */
    int r = tio(fd, MALI_IOC_PP_START_JOB, &job, 5);
    if (r == -999) return -999;
    if (r != 0) {
        printf("  [-] PP_START_JOB err=%d (%s)\n", -r, strerror(-r));
        return r;
    }

    /* 等待完成 */
    wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    r = tio(fd, MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    if (r == -999) return -999;
    if (r != 0) {
        printf("  [-] WAIT err=%d (%s)\n", -r, strerror(-r));
        return r;
    }
    printf("  [*] notif.type=0x%08x\n", notif.type);
    if (notif.type == _MALI_NOTIFICATION_PP_FINISHED) {
        uint32_t *st = (uint32_t *)(notif.data);
        /* pp_job_finished: user_job_ptr(8) + status(4) */
        uint32_t status = st[2]; /* offset 8 in data */
        printf("  [+] PP_FINISHED status=0x%08x (%s)\n", status, status_str(status));
        return (status & (1<<16)) ? 0 : -1;
    }
    printf("  [?] unexpected notification type\n");
    return -2;
}

int main() {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_pp_verify - PP job write primitive test\n");
    printf("[*] sizeof(pp_start_job_s)=%d, sizeof(wait_notif)=%d\n",
           (int)sizeof(pp_start_job_s), (int)sizeof(wait_for_notification_s));

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("[-] open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n", fd);

    /* ALLOC_MEM: gpu_vaddr 是输入 */
    const uint32_t GPU_VA_DATA = 0x40000000;
    const uint32_t BUF_SIZE = 0x4000;
    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    int r = tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3);
    if (r == -999) { printf("[-] TIMEOUT\n"); close(fd); return 1; }
    if (r != 0) {
        printf("[-] ALLOC_MEM failed err=%d (%s)\n", -r, strerror(-r));
        close(fd); return 1;
    }
    printf("[+] ALLOC_MEM OK: gpu_vaddr=0x%08x backend=0x%llx\n",
           alloc.gpu_vaddr, (unsigned long long)alloc.backend_handle);

    /* mmap */
    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap: %s\n", strerror(errno)); close(fd); return 1; }
    printf("[+] mmap OK at %p\n", buf);

    /* 验证区 = GPU_VA_DATA + 0x3000 (job 数据 0x2000 之后) */
    uint32_t verify_gpu = GPU_VA_DATA + 0x3000;
    volatile uint32_t *verify = (volatile uint32_t *)((uint8_t*)buf + 0x3000);
    *verify = 0;

    printf("\n[1] PP job: write 0xDEADBEEF -> GPU 0x%08x\n", verify_gpu);
    uint32_t tl = 0;
    r = submit_wb_job(fd, (uint32_t*)buf, GPU_VA_DATA, verify_gpu, 0xDEADBEEF, &tl);
    if (r == -999) { printf("[-] TIMEOUT - driver hung!\n"); }
    else if (r == 0) {
        printf("[+] job done, timeline=%u\n", tl);
        printf("[+] verify memory at +0x3000: 0x%08x (expect 0xDEADBEEF)\n", *verify);
        if (*verify == 0xDEADBEEF) {
            printf("\n[+] ==========================================\n");
            printf("[+] PP WRITE PRIMITIVE VERIFIED! ^_^\n");
            printf("[+] ==========================================\n");
        } else {
            printf("[-] write did not land (mismatch)\n");
        }
    } else {
        printf("[-] job failed\n");
    }

    /* 再测一次: 写 0x12345678 */
    printf("\n[2] PP job: write 0x12345678 -> GPU 0x%08x\n", verify_gpu + 4);
    r = submit_wb_job(fd, (uint32_t*)buf, GPU_VA_DATA, verify_gpu + 4, 0x12345678, &tl);
    if (r == 0) {
        printf("[+] verify memory at +0x3004: 0x%08x (expect 0x12345678)\n",
               *(volatile uint32_t*)((uint8_t*)buf + 0x3004));
    }

    munmap(buf, BUF_SIZE);
    free_mem_s mfree;
    memset(&mfree, 0, sizeof(mfree));
    mfree.gpu_vaddr = GPU_VA_DATA;
    ioctl(fd, MALI_IOC_MEM_FREE, &mfree);
    close(fd);
    printf("\n[*] done\n");
    return 0;
}
