/*
 * kort_probe10.c - ALLOC 页宽区写回几何测绘 (mmap 全可观测)
 *
 * 在与 uts 测试完全相同的参数下 (H=0x20) 写 ALLOC 页,
 * 然后 mmap dump 宽区, 确定写回是连续还是散射、精确窗口大小
 *
 * T1: 'A' @ +0x2000 (H=0x20) -> dump [0x1F00, 0x2300)
 * T2: 'B' @ +0x3000 (H=0x20) -> dump [0x2F00, 0x3300)
 * T3: 'C' @ +0x2000 (H=0x4)  -> dump 看小窗口
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

static void dump_region(const char *tag, volatile uint8_t *base, int len) {
    printf("%s:\n", tag);
    for (int i = 0; i < len; i += 16) {
        printf("  +%04x:", i);
        for (int j = 0; j < 16 && i+j < len; j++) printf(" %02x", base[i+j]);
        printf("\n");
    }
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_probe10 - ALLOC wide-region writeback geometry\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE; alloc.psize = BUF_SIZE;
    if (tio(fd, MALI_IOC_MEM_ALLOC, &alloc, 3) != 0) { printf("[-] alloc\n"); return 1; }
    void *buf = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap\n"); return 1; }

    /* T1: 'A' @ +0x2000, H=0x20 */
    memset((char*)buf + 0x1F00, 0, 0x400);
    __builtin___clear_cache((char*)buf, (char*)buf + BUF_SIZE);
    printf("\n[T1] 'A' @ +0x2000 (W=0x10 H=0x20)\n");
    wb_write_wh(fd, (uint32_t*)buf, GPU_VA_DATA + 0x2000, 0x41414141, 0x10, 0x20);
    dump_region("  [0x1F00,0x2300)", (volatile uint8_t*)buf + 0x1F00, 0x400);

    /* T2: 'B' @ +0x3000, H=0x20 */
    memset((char*)buf + 0x2F00, 0, 0x400);
    __builtin___clear_cache((char*)buf, (char*)buf + BUF_SIZE);
    printf("\n[T2] 'B' @ +0x3000 (W=0x10 H=0x20)\n");
    wb_write_wh(fd, (uint32_t*)buf, GPU_VA_DATA + 0x3000, 0x42424242, 0x10, 0x20);
    dump_region("  [0x2F00,0x3300)", (volatile uint8_t*)buf + 0x2F00, 0x400);

    munmap(buf, BUF_SIZE);
    close(fd);
    return 0;
}
