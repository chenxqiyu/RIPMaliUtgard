img文件在F:\down\player6\update_miboxs_a12
设备信息在I:\云盘缓存\down\miboxs\RIPMaliUtgard\miboxs.txt

---

# Mi Box S 4 (MIBOX4 / oneday) 提权适配说明

源码仓库 RIPMaliUtgard（Mali Utgard GPU 提权利用集合）已新增针对本机的 `kort_miboxs.c`。
bug 类型：把任意物理内存（含内核页）映射到 GPU，再用 PP write-back job 当作写原语，
覆盖一个 `file_operations` 指针，最后从用户态触发执行（ret2usr）拿到 root。

## 目标设备（来自 miboxs.txt）

| 项 | 值 |
| - | - |
| 型号 | MIBOX4 / oneday（Mi Box S 4） |
| SoC | Amlogic AMLS905X（Mali-450 MP，Utgard 架构） |
| 内核 | 4.9.269-ab4536 |
| Android | 12（SDK 31） |
| ABI | 仅 armeabi-v7a → 判定为 **32 位内核** |
| SELinux | Enforcing |

## 编译命令（NDK，32 位 armeabi-v7a）

本机只有 32 位 ABI，故用 `armv7a-linux-androideabi` 工具链，静态链接。

Linux / Git-Bash（NDK 在 WSL 或 linux 下）：
```bash
# 替换成你本地的 NDK 路径与版本
NDK=$HOME/android-ndk-r21e
CLANG=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi24-clang

$CLANG kort_miboxs.c -o kort_miboxs -static
```

Windows（PowerShell / CMD，NDK 在 Windows 下）：
```bat
set NDK=I:\down\android-ndk-r21e
set CLANG=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang.exe
%CLANG% kort_miboxs.c -o kort_miboxs -static
```

> API 级别用 24（Android 7）即可，本机是 12，静态二进制不受影响。
> 若本地是 NDK r25+，把上面的 `r21e` / `24` 换成对应版本号即可。

## 推送并运行

```bash
adb push kort_miboxs /data/local/tmp/
adb shell chmod 755 /data/local/tmp/kort_miboxs
adb shell /data/local/tmp/kort_miboxs
```

## 运行前必须填的“设备相关常量”（kort_miboxs.c 顶部 CONFIG 段）

`TARGET_PHYS_ADDR` / `TARGET_KERNEL_VA` / `TARGET_PAGE_OFFSET` /
`PREPARE_KERNEL_CRED_ADDR` / `COMMIT_CREDS_ADDR` / `SELINUX_ENFORCING_ADDR` /
`VICTIM_PROC_FILE_PATH` 都还是占位值，二进制会拒绝运行直到你填好。

推导方法：

1. **内核符号**（prepare_kernel_cred / commit_creds / selinux_enforcing）
   ```bash
   adb shell su -c "cat /proc/kallsyms" | grep -E "prepare_kernel_cred|commit_creds|selinux_enforcing"
   ```
   若 `/proc/kallsyms` 被 `kptr_restrict` 屏蔽（地址全是 0），则要用本利用的
   物理映射原语自己泄露，或临时 `echo 0 > /proc/sys/kernel/kptr_restrict`。

2. **TARGET 物理页 + 偏移**
   - `TARGET_KERNEL_VA`：挑一个 `/proc` 项的 `proc_dir_entry` 里 `proc_fops`
     指针（建议偏移 > 0x400，避开没有 r1 的 `->open`）。
   - `TARGET_PHYS_ADDR`：该 VA 所在页的对齐物理地址。32 位内核通常
     `phys = va - 0xc0000000`（即 PAGE_OFFSET），或读 `/proc/kallsyms` +
     物理扫描确认。
   - `TARGET_PAGE_OFFSET`：指针在该页内的字节偏移。

3. **VICTIM_PROC_FILE_PATH（触发用的 /proc 项）**
   Amlogic 没有 Mediatek 的 `wmt_aee` / `wmt_dbg`。需要自己找一个：
   打开它会走到被覆盖的那个 fop（读/写/打开均可）。常见做法是在 `/proc`
   下逐个项确认其 `proc_dir_entry` 落在可被映射的内核页上，选一个稳定存在的。

## 4.9 / S905X 上的已知坑

- **PAN / PXN**：4.9 内核在 S905X 上大概率开了 PAN，内核不能执行用户态的
  `get_root_shell()`（ret2usr 被挡）。拿不到 root 时，需要改成内核内存里的
  JOP 链（和其它 kort 在带 PXN 机型上的做法一致）。
- **驱动兼容性**：本利用依赖**开源 Utgard 驱动**暴露带外部物理内存的
  `_MALI_UK_BIND_MEM`。若 Amlogic 用的是闭源 `mali.ko` blob，ioctl 号/结构体
  不同，BIND 步骤会被拒绝——先确认 `/dev/mali` 和该 ioctl 路径存在。
- **SELinux**：`get_root_shell()` 里已把 `selinux_enforcing` 置 0 绕过，
  但该地址同样需要从 kallsyms 拿。

## 其它参考

- 同仓库其它 kort 模板：`kort_huawei_t3_7.c`（Mali-450，含 SELinux 绕过）、
  `kort_t11_translator.c`、`kort_soyes_xs11.c`。
- 思路博客见 `README.md` 顶部链接。



手动

rem 编译（NDK 21.4，32 位 armeabi-v7a，静态链接）
set NDK=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529
set CLANG=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang
%CLANG% kort_miboxs.c -o kort_miboxs -static
%CLANG% kort_probe_miboxs.c -o kort_probe_miboxs -static

rem 上传
adb push kort_miboxs /data/local/tmp/
adb push kort_probe_miboxs /data/local/tmp/

rem 运行
adb shell chmod 755 /data/local/tmp/kort_probe_miboxs /data/local/tmp/kort_miboxs
adb shell /data/local/tmp/kort_probe_miboxs
