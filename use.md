设备信息
I:\云盘缓存\down\miboxs\RIPMaliUtgard\miboxs.txt

# Mi Box S Root via Mali Utgard - 工作进展记录

## 目标
Root 小米盒子 S (设备代号: oneday)，利用 Mali Utgard GPU 漏洞进行内核提权。

## 设备信息
- **设备**: Mi Box S (oneday)
- **Android 版本**: Android 12
- **内核版本**: Linux 4.9.269
- **架构**: 32位用户态 (ARMv7a) + 64位内核 (ARM64)
- **GPU**: Mali Utgard (Mali-450 系列)
- **SELinux**: Enforcing
- **kptr_restrict**: 开启（无法直接读取 /proc/kallsyms）

## 关键目录
img文件在F:\down\player6\update_miboxs_a12
反编译目录C:\Users\Administrator\.trae-cn\work\6a8ce0f8af1aabae7665faa3
相似源码目录I:\云盘缓存\down\shennong-ota_full-OS3.0.307.0.WNBCNXM-user-16.0-5bcfc9ad5d\MiBox_Kernel_OpenSource-once-o-oss

### 主工作目录
`I:\云盘缓存\down\miboxs\RIPMaliUtgard\`

- `kort_miboxs.c` - 主 exploit 文件（基于原版本修改，尚未完全适配）
- `kort_probe_miboxs.c` - Mali GPU 功能探测（早期版本，已废弃）
- `kort_bind_probe.c` - BIND_MEM ioctl 结构体大小探测
- `kort_pp_probe.c` - PP subsystem ioctl 粗粒度探测
- `kort_pp_fine.c` - PP subsystem ioctl 细粒度探测
- `kort_core_probe.c` - CORE subsystem ioctl 探测
- `kort_core_analyze.c` - CORE ioctl 返回数据分析
- `kort_alloc_probe.c` - ALLOC_MEM 字段布局探测
- `kort_ion_test.c` - ION 内存分配测试
- `build.ps1` - 编译脚本（早期）

### 参考 exploit 目录
`I:\云盘缓存\down\shennong-ota_full-OS3.0.307.0.WNBCNXM-user-16.0-5bcfc9ad5d\output\duchamp-root\`
- `bian.ps1` - 原始编译脚本（参考用）
- `bian_mibos.ps1` - 为 Mi Box S 修改的编译脚本

### 内核源码目录
`I:\云盘缓存\down\shennong-ota_full-OS3.0.307.0.WNBCNXM-user-16.0-5bcfc9ad5d\MiBox_Kernel_OpenSource-once-o-oss`
- Mi Box S 官方内核开源代码（参考 Mali 驱动用）

### 固件提取目录
`F:\down\player6\update_miboxs_a12\`
- 解包的 Mi Box S Android 12 固件
- `vendor/vendor/lib/egl/libGLES_mali.so` - Mali 用户态驱动库

### NDK 路径
`C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529`
- 使用 armv7a-linux-androideabi24-clang 编译 32 位 ARM 二进制

## 已确认的技术发现

### 1. 漏洞验证：BIND_MEM 外部物理内存绑定 ✅
- **漏洞编号**: CVE-2024-31317 (Mali Utgard forever-day)
- **验证状态**: 已确认漏洞存在
- **关键参数**:
  - BIND_MEM 结构体大小 = 40 字节
  - `_MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY` flag = (1 << 11) = 0x800
  - 可以绑定任意物理地址到 GPU 虚拟地址空间

### 2. PP (Pixel Processor) subsystem ✅
- PP_START_JOB 结构体大小 = 408 字节
- 调用 ioctl 不崩溃但返回非零（需要有效 context）

### 3. CORE subsystem ✅
找到以下有效 ioctl：
| NR | 大小 | 说明 |
|----|------|------|
| 3 | 16字节 | 返回 0x03840384（可能是版本号/API 版本） |
| 4 | 16字节 | 成功但全零返回 |
| 8 | 16字节 | 返回 EINVAL（需要特定输入） |
| 9 | 32字节 | 末尾返回 0x00000001 |
| 10 | 32字节 | 偏移24返回 0xffffffff |
| 13 | 8字节 | 成功但全零返回 |

**注意**: 尚未找到 CREATE_CONTEXT ioctl。nr=13 返回全零，可能不是 context 创建。

### 4. ALLOC_MEM
- 结构体大小 = 40 字节
- 单字段填入 0x1000 全部返回 ENOTTY (err=25)
- 可能需要多个字段同时正确设置

### 5. ION 内存分配 ❌
- 标准 ION ioctl 返回 "Not a typewriter" (ENOTTY)
- 厂商可能修改了 ION 接口
- **结论**: 不依赖 ION，改用其他方式获取物理内存

### 6. KASLR / 信息泄露
- `/proc/kallsyms` 不可读（Permission denied）
- `/proc/modules` 地址全零（已被隐藏）
- kptr_restrict 开启
- 设备树 bootargs 不可读
- **需要寻找 KASLR 泄露方法**

## 重大进展 (2026-08-25)

### A. ioctl 编号修正 (从 mali.ko 逆向确认)
从固件提取 `mali.ko` (561816 字节, 未剥离符号, Amlogic 开源 Utgard 驱动 r9p0 系) 逆向确认:

| ioctl | 命令值 | 说明 |
|-------|--------|------|
| MEM_ALLOC | 0xC0288300 (type=0x83, nr=0, size=40) | **之前探测代码错用 nr=5 → 全 ENOTTY!** |
| MEM_FREE | 0xC0108301 (type=0x83, nr=1, size=16) | |
| MEM_BIND | 0xC0288302 (type=0x83, nr=2, size=40) | 已验证: 绑定任意物理页到 GPU VA ✓ |
| MEM_UNBIND | 0xC0108303 (type=0x83, nr=3, size=16) | |
| PP_START_JOB | 0xC1988400 (type=0x84, nr=0, size=408) | 408 字节与探测一致 ✓ |
| WAIT_FOR_NOTIFICATION | 0xC0088202 (type=0x82, nr=2, size=8) | |
| CORE nr=13 | 0xC008820D (DUMP_STATE, 8字节) | **不是 CREATE_CONTEXT!** |

- subsystem: CORE=0x82, MEMORY=0x83, PP=0x84, GP=0x85
- **不需要 CREATE_CONTEXT / 不需要 context!** kort 路线直接 BIND + PP job。
- 驱动没有 compat 转换层,直接 `__arch_copy_from_user(job, user_args, 408)` 拷贝 32 位用户结构。

### B. 结构体布局确认 (mali_pp_job_create 反汇编)
- ALLOC_MEM 40 字节: ctx(u64@0) + **gpu_vaddr(u32@8, 输入!)** + vsize@12 + psize@16 + flags@20 + backend_handle(u64@24, 输出) + secure_shared_fd@32
- **gpu_vaddr 是输入字段** → ALLOC 时必须指定 GPU 地址 (如 0x40000000)
- PP_START_JOB 408 字节: kort_miboxs.c 布局正确, 驱动读取 num_cores@328 / flags@352 匹配
- BIND_MEM 40 字节: ctx(u64) + vaddr@8 + size@12 + flags@16 + union{phys_addr@20, rights@24, flags@28} + pad@32 + fd@36

### C. physmem 读取测试结论 (kort_phys_read, 实测)
- ALLOC_MEM (nr=0) 返回 0 不再 ENOTTY ✓ (ioctl 编号修正生效)
- BIND_MEM 绑定内核物理页 0x01080000 → GPU VA 0x40200000 成功 ✓
- **mmap 绑定页失败 (EFAULT)** → 不能 CPU 直接读 → **必须 PP job (GPU DMA) 写入**

### D. 物理地址提权方案 (无需 KASLR!)
从 boot.img 确认 **KernelAddr = 0x01080000** (text_offset, 无物理 KASLR)。
用 vmlinux-to-elf 从 split_img/kernel 提取符号, 基址 0xffffff8009080000 (已验证: Image 文件 0x175f960 处 = "/sbin/modprobe" 字符串, 与 modprobe_path 符号偏移吻合):

| 目标 | 虚拟地址 | 物理地址 | 页内偏移 |
|------|---------|---------|---------|
| modprobe_path | 0xffffff800a7df960 | **0x027df960** | 0xf960 |
| selinux_enforcing | 0xffffff800aa394ec | **0x02a394ec** | 0x4ec (.bss) |
| init_cred | 0xffffff800a7e0f70 | 0x027e0f70 | |
| prepare_kernel_cred | 0xffffff80090d7f28 | | |
| commit_creds | 0xffffff80090d7988 | | |

物理地址公式: PA = 0x01080000 + (VA - 0xffffff8009080000)

### 下一步
1. 构造 PP job 验证写入 (先写 GPU 自己内存, 读回验证)
2. 成功后 BIND modprobe_path 物理页 0x027df000 → PP job 多次写字符串
3. 触发 modprobe → root (uid=0)

## 待解决的关键问题

### 高优先级 (旧, 部分已解决)
1. ~~找到 CREATE_CONTEXT ioctl~~ - **已确认不需要 context** (kort 路线直接 BIND + PP)
2. ~~搞清楚 ALLOC_MEM 的字段布局~~ - **已确认: gpu_vaddr 是输入字段**
3. **验证 PP job 写入原语** - 核心漏洞利用能力 (进行中)
4. ~~KASLR 泄露~~ - **已绕过: 用物理地址方案 (PA = 0x01080000 + VA偏移)**

### 中优先级
5. **PAN 保护绕过** - ARM64 内核有 PAN，需要用 ROP/JOP
6. **SELinux 关闭** - 提权后需要关闭 SELinux

## 下一步计划

### 阶段 1：完善 GPU 原语
1. 继续探测 CORE ioctl，找到 CREATE_CONTEXT
   - 尝试不同的输入值（不仅仅是全零）
   - 查看内核源码中的 `mali_ukk_core.h` 确认 ioctl 编号

2. 逆向 ALLOC_MEM 字段布局
   - 从内核源码获取结构体定义
   - 或通过多字段组合测试推断

3. 用 Mali 自己分配的内存验证 PP 写入
   - 分配两块内存：一块放 PP job 描述符，一块做目标
   - 提交 PP job 后读取目标内存看是否被修改

### 阶段 2：信息泄露
1. 寻找 KASLR 泄露点
   - /proc/slabinfo？
   - 驱动 bug 导致的信息泄露？
   - GPU 侧信道？

### 阶段 3：提权链
1. 找到可覆写的内核目标（如 `selinux_enforcing`、`task_struct->cred` 等）
2. 构造 ROP 链（如果需要执行代码）
3. 完成完整 exploit

## 编译命令模板

```powershell
$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529"
$clang = "$ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang.cmd"
& $clang source.c -o output -static
adb push output /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/output && /data/local/tmp/output"
```

## 注意事项

1. **架构**: 必须编译为 32 位 ARM (armv7a)，因为用户态是 32 位
   - 64 位 so 会报错: "is 64-bit instead of 32-bit"

2. **驱动挂起**: 某些错误的 ioctl 调用可能导致 GPU 驱动挂起
   - 表现: 命令卡住无输出
   - 恢复: 重启设备
   - 防护: 所有探测代码都应使用 alarm() 设置超时

3. **SELinux**: 当前是 Enforcing 模式，很多 /proc / /sys 路径不可读
   - 提权后需要 `setenforce 0`

4. **文件传输**: adb push 后的文件需要 chmod 755 才能执行
   - 如果文件执行报 syntax error，可能是文件传输损坏，用 sha256 校验

## 相关 CVE
- CVE-2024-31317 - Mali Utgard GPU 越界写/外部内存绑定漏洞
