#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

int main() {
    /* Output immediately - no buffering */
    printf("STEP 1: start\n");
    fflush(stdout);

    int fd = open("/dev/mali", O_RDWR);
    printf("STEP 2: open returned %d (errno=%d)\n", fd, errno);
    fflush(stdout);

    if (fd < 0) {
        printf("FAILED to open /dev/mali\n");
        return 1;
    }

    printf("STEP 3: calling ALLOC_MEM...\n");
    fflush(stdout);

    /* ALLOC_MEM: _IOWR(0x83, 0, 40) = 0xc0288300 */
    unsigned int cmd = 0xc0288300;
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    *(unsigned int *)(buf + 16) = 0x1000;  /* try psize at offset 16 */
    *(unsigned int *)(buf + 12) = 0x1000;  /* try vsize at offset 12 */

    int ret = ioctl(fd, cmd, buf);
    int err = errno;
    printf("STEP 4: ioctl returned %d (errno=%d)\n", ret, err);
    fflush(stdout);

    if (ret == 0) {
        printf("SUCCESS! Dumping first 40 bytes:\n");
        for (int i = 0; i < 40; i++) {
            if (i % 16 == 0) printf("  %02x: ", i);
            printf("%02x ", buf[i]);
            if (i % 16 == 15) printf("\n");
        }
        printf("\n");
    }

    close(fd);
    printf("STEP 5: done\n");
    fflush(stdout);
    return 0;
}
