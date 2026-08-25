#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>

/*
 * PP_START_JOB size probe.
 * We test with ctx=0 (invalid). If size is wrong -> ENOTTY.
 * If size is right but ctx=0 -> some other error (EINVAL).
 * This is safe because invalid ctx should just return error, not hang.
 */

#define MALI_IOC_BASE 0x82
#define _MALI_UK_PP_SUBSYSTEM 2
#define MALI_IOC_PP_BASE (_MALI_UK_PP_SUBSYSTEM + MALI_IOC_BASE)
#define _MALI_UK_PP_START_JOB 0

#define _IOWR(type, nr, size) \
    (((3) << 30) | ((size) << 16) | ((type) << 8) | (nr))

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

    printf("[*] PP_START_JOB size probe\n");
    printf("[*] (ctx=0, should get EINVAL not ENOTTY if size is correct)\n\n");

    int fd = open("/dev/mali", O_RDWR);
    if (fd < 0) { perror("open /dev/mali"); return 1; }
    printf("[+] opened /dev/mali fd=%d\n\n", fd);

    /* Reference: soyus_xs11 PP_START_JOB = ~396 bytes (calculated)
     * Our device has larger structs. Scan a range.
     */

    printf("%-6s  %-10s  %-8s  %s\n", "SIZE", "IOC_NR", "STATUS", "NOTES");
    printf("--------------------------------------------------------\n");

    int candidates[100];
    int n_candidates = 0;

    /* First pass: coarse scan, step 16 bytes */
    printf("--- Coarse scan (step 16) ---\n");
    for (int sz = 256; sz <= 640; sz += 16) {
        uint8_t buf[1024];
        memset(buf, 0, sizeof(buf));
        /* ctx = 0 (invalid) at offset 0 (uint64_t) */

        unsigned int cmd = _IOWR(MALI_IOC_PP_BASE, _MALI_UK_PP_START_JOB, sz);
        int r = tio(fd, cmd, buf, 3);

        const char *status = "?";
        if (r == -999) status = "TIMEOUT";
        else if (r == 0) status = "SUCCESS";
        else if (r == -ENOTTY) status = "ENOTTY";
        else if (r == -EINVAL) status = "EINVAL";
        else if (r == -EPERM) status = "EPERM";
        else status = "OTHER";

        int is_candidate = (r != -ENOTTY && r != -999);
        if (is_candidate) {
            printf("  %4d  0x%08x  %-8s  err=%d  <-- candidate\n", sz, cmd, status, -r);
            candidates[n_candidates++] = sz;
        }

        if (r == -999) {
            printf("\n[!] TIMEOUT at size=%d\n", sz);
            close(fd);
            return 1;
        }
    }

    printf("\n--- Fine scan around candidates ---\n");
    for (int ci = 0; ci < n_candidates; ci++) {
        int base = candidates[ci] - 16;
        for (int sz = base; sz < base + 32; sz += 4) {
            if (sz <= 0) continue;
            uint8_t buf[1024];
            memset(buf, 0, sizeof(buf));

            unsigned int cmd = _IOWR(MALI_IOC_PP_BASE, _MALI_UK_PP_START_JOB, sz);
            int r = tio(fd, cmd, buf, 3);

            const char *status = "?";
            if (r == -999) status = "TIMEOUT";
            else if (r == 0) status = "SUCCESS";
            else if (r == -ENOTTY) status = "ENOTTY";
            else if (r == -EINVAL) status = "EINVAL";
            else status = "OTHER";

            if (r != -ENOTTY) {
                printf("  %4d  0x%08x  %-8s  err=%d\n", sz, cmd, status, -r);
            }

            if (r == -999) {
                close(fd);
                return 1;
            }
        }
    }

    /* Also check a few specific sizes based on known patterns */
    printf("\n--- Specific guesses ---\n");
    /* soyus_xs11 original ~396, our device might be larger */
    int guesses[] = {396, 400, 404, 408, 412, 416, 420, 424, 432, 440, 448, 456, 464, 480, 496, 512};
    for (int i = 0; i < 16; i++) {
        int sz = guesses[i];
        uint8_t buf[1024];
        memset(buf, 0, sizeof(buf));

        unsigned int cmd = _IOWR(MALI_IOC_PP_BASE, _MALI_UK_PP_START_JOB, sz);
        int r = tio(fd, cmd, buf, 3);

        const char *status = "?";
        if (r == -999) status = "TIMEOUT";
        else if (r == 0) status = "SUCCESS";
        else if (r == -ENOTTY) status = "ENOTTY";
        else if (r == -EINVAL) status = "EINVAL";
        else status = "OTHER";

        printf("  %4d  0x%08x  %-8s  err=%d\n", sz, cmd, status, -r);

        if (r == -999) break;
    }

    close(fd);
    printf("\n[*] done\n");
    return 0;
}
