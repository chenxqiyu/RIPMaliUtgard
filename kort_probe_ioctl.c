#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

/*
 * Brute-force probe for Mali Utgard ioctl numbers
 * Test various ioctl bases and sizes to find the correct ones
 */

static int test_ioctl(int fd, unsigned int cmd, void *arg, const char *name) {
    int ret = ioctl(fd, cmd, arg);
    int err = errno;
    if (ret == 0) {
        printf("  [SUCCESS] %s = 0x%08x -> ret=0\n", name, cmd);
        return 1;
    } else if (err == ENOTTY) {
        /* Not a valid ioctl - skip */
        return 0;
    } else {
        /* Other error means the ioctl exists but failed for other reasons */
        printf("  [EXISTS ] %s = 0x%08x -> ret=%d errno=%d (%s)\n",
               name, cmd, ret, err, strerror(err));
        return 1;
    }
}

int main() {
    printf("[*] Mali ioctl probe starting\n");
    printf("[*] Testing multiple ioctl base types...\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        perror("open /dev/mali");
        return 1;
    }
    printf("[+] opened /dev/mali fd=%d\n\n", fd);

    /* Allocate a large buffer for ioctl arguments */
    void *buf = calloc(1, 4096);
    if (!buf) { perror("calloc"); return 1; }

    /*
     * Known Mali Utgard ioctl type values to try:
     * 0x82 - standard ARM Mali
     * 0x6d - 'm' for Mali
     * 0x83 - another common variant
     * 0x00 - sometimes zero
     */
    unsigned char types[] = {0x82, 0x83, 0x6d, 0x62, 0x4d, 0x00};
    const char *type_names[] = {"0x82", "0x83", "0x6d('m')", "0x62", "0x4d('M')", "0x00"};

    /*
     * Test ioctl group 0 (MEMORY group):
     * ALLOC_MEM = 0
     * FREE_MEM = 1
     * BIND_MEM = 2
     * UNBIND_MEM = 3
     *
     * With different sizes (mali_uk_alloc_mem_s structure size varies)
     */
    int mem_nrs[] = {0, 1, 2, 3};
    const char *mem_names[] = {"ALLOC_MEM(0)", "FREE_MEM(1)", "BIND_MEM(2)", "UNBIND_MEM(3)"};
    int sizes[] = {24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64};

    for (int t = 0; t < sizeof(types)/sizeof(types[0]); t++) {
        printf("=== Testing type %s ===\n", type_names[t]);
        int found = 0;

        for (int n = 0; n < 4; n++) {
            for (int s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++) {
                /* _IOWR(direction=3=RW, type, nr, size) */
                unsigned int cmd = (sizes[s] << 16) | (3 << 14) | (types[t] << 8) | mem_nrs[n];
                char name[64];
                snprintf(name, sizeof(name), "%s size=%d", mem_names[n], sizes[s]);
                if (test_ioctl(fd, cmd, buf, name)) {
                    found++;
                }
            }
        }

        if (found == 0) {
            printf("  (none found)\n");
        }
        printf("\n");
    }

    /* Also try the BASE group (ioctl base type) */
    printf("=== Testing BASE group (nr 0-5) with type 0x82 ===\n");
    for (int nr = 0; nr < 10; nr++) {
        for (int s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++) {
            unsigned int cmd = (sizes[s] << 16) | (3 << 14) | (0x82 << 8) | nr;
            char name[64];
            snprintf(name, sizeof(name), "BASE nr=%d size=%d", nr, sizes[s]);
            test_ioctl(fd, cmd, buf, name);
        }
    }

    free(buf);
    close(fd);
    printf("\n[*] probe done\n");
    return 0;
}
