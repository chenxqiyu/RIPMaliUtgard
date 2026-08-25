#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/*
 * ION allocation test for Mi Box S.
 * ION is world-writable - perfect for testing GPU write primitive.
 *
 * Classic ION ioctls (pre-4.12):
 *   ION_IOC_ALLOC = _IOWR('I', 0, struct ion_allocation_data)
 *   ION_IOC_FREE  = _IOWR('I', 1, struct ion_handle_data)
 *   ION_IOC_MAP   = _IOWR('I', 2, struct ion_fd_data) — get dma-buf fd
 *   ION_IOC_PHYS  = _IOWR('I', 4, struct ion_phys_data) — get phys addr
 */

#define ION_IOC_MAGIC 'I'

struct ion_allocation_data {
    uint64_t len;
    uint32_t align;
    uint32_t heap_id_mask;
    uint32_t flags;
    uint32_t handle; /* out */
};

struct ion_handle_data {
    uint32_t handle;
};

struct ion_fd_data {
    uint32_t handle;
    int32_t fd; /* out */
};

struct ion_phys_data {
    uint32_t handle;
    uint32_t padding;
    uint64_t phys_addr; /* out */
};

#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE  _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP   _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_PHYS  _IOWR(ION_IOC_MAGIC, 4, struct ion_phys_data)

/* Heap IDs (classic ION) */
#define ION_HEAP_SYSTEM_MASK   (1 << 0)
#define ION_HEAP_SYSTEM_CONTIG_MASK (1 << 1)
#define ION_HEAP_CARVEOUT_MASK (1 << 2)
#define ION_HEAP_CHUNK_MASK    (1 << 3)

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] ION allocation test\n\n");

    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) { perror("open /dev/ion"); return 1; }
    printf("[+] opened /dev/ion fd=%d\n\n", fd);

    /* Try different heap masks to find one that works */
    int heap_masks[] = {
        ION_HEAP_SYSTEM_MASK,
        ION_HEAP_SYSTEM_CONTIG_MASK,
        ION_HEAP_CARVEOUT_MASK,
        ION_HEAP_CHUNK_MASK,
        ION_HEAP_SYSTEM_MASK | ION_HEAP_SYSTEM_CONTIG_MASK,
        0x100, /* might be a custom heap */
        0x1000,
        0x10000,
    };

    uint32_t success_handle = 0;
    uint64_t success_phys = 0;
    int success_heap = -1;

    for (int i = 0; i < 8; i++) {
        struct ion_allocation_data alloc;
        memset(&alloc, 0, sizeof(alloc));
        alloc.len = 4096;
        alloc.align = 4096;
        alloc.heap_id_mask = heap_masks[i];
        alloc.flags = 0;

        int r = ioctl(fd, ION_IOC_ALLOC, &alloc);
        printf("  heap_mask=0x%08x: ret=%d err=%s handle=0x%x\n",
               heap_masks[i], r, r < 0 ? strerror(errno) : "OK", alloc.handle);

        if (r == 0 && alloc.handle != 0) {
            /* Try to get physical address */
            struct ion_phys_data phys;
            memset(&phys, 0, sizeof(phys));
            phys.handle = alloc.handle;

            int pr = ioctl(fd, ION_IOC_PHYS, &phys);
            printf("    PHYS: ret=%d err=%s phys=0x%llx\n",
                   pr, pr < 0 ? strerror(errno) : "OK",
                   (unsigned long long)phys.phys_addr);

            /* Try to mmap */
            struct ion_fd_data fdd;
            memset(&fdd, 0, sizeof(fdd));
            fdd.handle = alloc.handle;

            int mr = ioctl(fd, ION_IOC_MAP, &fdd);
            printf("    MAP fd: ret=%d err=%s fd=%d\n",
                   mr, mr < 0 ? strerror(errno) : "OK", fdd.fd);

            if (mr == 0 && fdd.fd >= 0) {
                void *map = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fdd.fd, 0);
                if (map != MAP_FAILED) {
                    printf("    MMAP: SUCCESS at %p\n", map);
                    memset(map, 0x42, 4096);
                    printf("    Wrote 'B' pattern, first byte: 0x%02x\n", *(uint8_t*)map);
                    munmap(map, 4096);
                } else {
                    printf("    MMAP: FAILED (%s)\n", strerror(errno));
                }
                close(fdd.fd);
            }

            if (pr == 0) {
                success_handle = alloc.handle;
                success_phys = phys.phys_addr;
                success_heap = heap_masks[i];
            }

            /* Don't free yet if success, we want to test more */
            if (success_phys == 0) {
                struct ion_handle_data hd;
                hd.handle = alloc.handle;
                ioctl(fd, ION_IOC_FREE, &hd);
            }
        }
    }

    if (success_phys != 0) {
        printf("\n[+] SUCCESS! heap=0x%08x phys=0x%llx handle=0x%x\n",
               success_heap, (unsigned long long)success_phys, success_handle);
        /* Keep it allocated for next steps */
        printf("[+] (keeping allocation for GPU test)\n");
        printf("[+] Sleeping 30s - run GPU test now\n");
        sleep(30);

        /* Cleanup */
        struct ion_handle_data hd;
        hd.handle = success_handle;
        ioctl(fd, ION_IOC_FREE, &hd);
        printf("[*] freed\n");
    } else {
        printf("\n[-] No heap with phys addr support found\n");
    }

    close(fd);
    return 0;
}
