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

/*
 * Get PP core info and test basic memory operations.
 * Also test MEM_WRITE_SAFE as an alternative to mmap writes.
 */

#define MALI_IOC_BASE 0x82
#define MALI_IOC_PP_BASE (2 + MALI_IOC_BASE)  /* 0x84 */
#define MALI_IOC_MEMORY_BASE (1 + MALI_IOC_BASE) /* 0x83 */

#define _MALI_UK_GET_PP_NUMBER_OF_CORES 1
#define _MALI_UK_GET_PP_CORE_VERSION 2
#define _MALI_UK_ALLOC_MEM 0
#define _MALI_UK_MEM_WRITE_SAFE 10

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))
#define _IOR(type, nr, size) \
    (((2) << 30) | ((size) << 16) | ((type) << 8) | (nr))

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

int main() {
    signal(SIGALRM, alh);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] PP core info + basic tests\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    printf("[+] fd=%d\n\n", fd);

    /* 1. Get PP number of cores */
    printf("=== PP number of cores ===\n");
    {
        struct { uint64_t ctx; uint32_t num_cores; } args;
        memset(&args, 0, sizeof(args));
        int r = tio(fd, _IOR(MALI_IOC_PP_BASE, _MALI_UK_GET_PP_NUMBER_OF_CORES, 12), &args, 2);
        printf("  result: %s, num_cores=%u\n",
               r == 0 ? "OK" : (r == -999 ? "TIMEOUT" : strerror(-r)),
               args.num_cores);
    }

    /* 2. Get PP core version */
    printf("\n=== PP core version ===\n");
    {
        struct { uint64_t ctx; uint32_t version; } args;
        memset(&args, 0, sizeof(args));
        int r = tio(fd, _IOR(MALI_IOC_PP_BASE, _MALI_UK_GET_PP_CORE_VERSION, 12), &args, 2);
        printf("  result: %s, version=0x%08x\n",
               r == 0 ? "OK" : (r == -999 ? "TIMEOUT" : strerror(-r)),
               args.version);
        /* Decode: product_id = (version >> 16) & 0xFFFF */
        printf("  product_id=0x%04x (Mali450=0xCF07, Mali400=0xCD07)\n",
               (args.version >> 16) & 0xFFFF);
    }

    /* 3. Allocate memory and test mmap */
    printf("\n=== ALLOC_MEM + mmap test ===\n");
    {
        struct {
            uint64_t ctx;
            uint32_t gpu_vaddr;
            uint32_t vsize;
            uint32_t psize;
            uint32_t flags;
            uint64_t backend_handle;
            int32_t secure_shared_fd;
        } alloc;
        memset(&alloc, 0, sizeof(alloc));
        alloc.gpu_vaddr = 0x50000000;
        alloc.vsize = 0x4000;
        alloc.psize = 0x4000;

        int r = tio(fd, _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, 36), &alloc, 3);
        /* Try size 40 too */
        if (r != 0) {
            printf("  size=36 failed, trying size=40...\n");
            memset(&alloc, 0, sizeof(alloc));
            alloc.gpu_vaddr = 0x50000000;
            alloc.vsize = 0x4000;
            alloc.psize = 0x4000;
            r = tio(fd, _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, 40), &alloc, 3);
        }
        printf("  ALLOC: %s\n", r == 0 ? "OK" : (r == -999 ? "TIMEOUT" : strerror(-r)));
        if (r == 0) {
            printf("  gpu_vaddr=0x%08x, backend_handle=0x%016llx\n",
                   alloc.gpu_vaddr, (unsigned long long)alloc.backend_handle);
        }

        if (r == 0) {
            void *p = mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0x50000000);
            if (p != MAP_FAILED) {
                printf("  mmap OK: %p\n", p);
                memset(p, 0x42, 0x4000);
                printf("  wrote 0x42 pattern, first word = 0x%08x\n", *(uint32_t *)p);
                munmap(p, 0x4000);
            } else {
                printf("  mmap failed: %s\n", strerror(errno));
            }
        }
    }

    /* 4. Test MEM_WRITE_SAFE */
    printf("\n=== MEM_WRITE_SAFE test ===\n");
    {
        uint32_t src_data[8] = {0x11223344, 0x55667788, 0xAABBCCDD, 0xEEFF0011,
                                 0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x87654321};

        struct {
            uint64_t ctx;
            uint64_t src;
            uint64_t dest;
            uint32_t size;
        } ws;
        memset(&ws, 0, sizeof(ws));
        ws.src = (uintptr_t)src_data;
        ws.dest = 0x50000100;  /* offset 0x100 in the allocated buffer */
        ws.size = 32;

        int r = tio(fd, _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_MEM_WRITE_SAFE, 24), &ws, 3);
        printf("  WRITE_SAFE (size=24): %s, written=%u\n",
               r == 0 ? "OK" : (r == -999 ? "TIMEOUT" : strerror(-r)),
               ws.size);

        /* Read back via mmap to verify */
        void *p = mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0x50000000);
        if (p != MAP_FAILED) {
            uint32_t *data = (uint32_t *)((uint8_t *)p + 0x100);
            printf("  read back @0x100: ");
            for (int i = 0; i < 8; i++) printf("0x%08x ", data[i]);
            printf("\n");
            munmap(p, 0x4000);
        }
    }

    close(fd);
    printf("\ndone\n");
    return 0;
}
