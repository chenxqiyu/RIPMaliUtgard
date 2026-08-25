/*
 * kort_dump.c - WB 写入窗口形状分析
 * 写 magic 到自己 GPU 内存, dump 前后 2KB 看实际写入范围/模式
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
    int e = errno;
    alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

static int run_wb(int fd, uint32_t *buf, uint32_t wb_addr,
                  uint32_t value, uint32_t pitch)
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
    job.wb0_registers[WB_PITCH]        = pitch;
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
    return 0;
}

static void dump_region(const char *tag, volatile uint32_t *p, int words)
{
    printf("%s:\n", tag);
    for (int i = 0; i < words; i += 8) {
        printf("  +%04x:", i * 4);
        for (int j = 0; j < 8 && i + j < words; j++) printf(" %08x", p[i + j]);
        printf("\n");
    }
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_dump - WB write window analysis\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    if (tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) { printf("[-] alloc\n"); return 1; }

    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap\n"); return 1; }

    /* 目标区 +0x4000, 预填 0xAA */
    memset((char*)buf + 0x4000, 0xAA, 0x1000);
    __builtin___clear_cache((char*)buf, (char*)buf + BUF_SIZE);

    printf("[1] WB -> 0x40004000, value=0xC0DEC0DE, pitch=8 (64B/row)\n");
    run_wb(fd, (uint32_t*)buf, GPU_VA_DATA + 0x4000, 0xC0DEC0DE, 8);
    dump_region("after job (region 0x4000-0x4600)",
                (volatile uint32_t*)((char*)buf + 0x3F00), 0x700 / 4);

    munmap(buf, BUF_SIZE);
    close(fd);
    return 0;
}
