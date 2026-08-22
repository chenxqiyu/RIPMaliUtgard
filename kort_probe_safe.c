/*
 * kort_probe_safe.c  —— 安全探针，不碰任意物理 BIND，避免把盒子卡死。
 * 只验证两件事：
 *   1) /dev/mali 能否 open
 *   2) MALI_IOC_MEM_ALLOC 是否能成功（成功说明我们的 ioctl 号/结构体布局
 *      与该驱动匹配；失败（如 ENOTTY）说明驱动接口不同，需要另查）
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#define MALI_IOC_BASE 0x82
#define _MALI_UK_MEMORY_SUBSYSTEM 1
#define MALI_IOC_MEMORY_BASE (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE)
#define _MALI_UK_ALLOC_MEM 0
#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

typedef struct {
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t vsize;
    uint32_t psize;
    uint32_t flags;
    uint64_t backend_handle;
} mali_uk_alloc_mem_s;

#define MALI_IOC_MEM_ALLOC \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, mali_uk_alloc_mem_s)

#define PAGE_SIZE 4096

int main() {
    printf("[*] safe probe /dev/mali (MIBOX4)\n");
    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        printf("[-] open /dev/mali: %s\n", strerror(errno));
        return 1;
    }
    printf("[+] opened /dev/mali fd=%d\n", fd);

    mali_uk_alloc_mem_s alloc = {0};
    alloc.gpu_vaddr = 0x40000000;
    alloc.psize = PAGE_SIZE * 4;
    alloc.vsize = PAGE_SIZE * 4;
    int r = ioctl(fd, MALI_IOC_MEM_ALLOC, &alloc);
    if (r == 0) {
        printf("[+] ALLOC OK  backend_handle=0x%llx  (ioctl layout matches driver)\n",
               (unsigned long long)alloc.backend_handle);
    } else {
        printf("[-] ALLOC failed ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
        if (errno == ENOTTY)
            printf("    ENOTTY => ioctl number/struct mismatch, driver interface differs\n");
    }
    close(fd);
    printf("[*] safe probe done, device should stay alive.\n");
    return 0;
}
