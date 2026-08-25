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
- `kort_alloc_probe.c` - ALLOC_MEM 字段布局探测（旧, ioctl 编号已废弃）
- `kort_ion_test.c` - ION 内存分配测试
- `kort_phys_read.c` - physmem 读取验证（2026-08-25 新增）
- `kort_pp_verify.c` - PP job 写入原语验证（2026-08-25 新增）
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

### A. mali.ko 驱动逆向 (r10p1!)
从固件提取 `mali.ko` (561816 字节, **未剥离符号**) 确认:
- **驱动版本: r10p1** (源码路径暴露: `/vendor/amlogic/common/gpu/utgard/r10p1/common/mali_pp_job.c`)
- 支持 Mali-400 MP / Mali-450 MP
- 与 LineageOS Amlogic (GXL/GXM/G12A) 用的同一驱动

**完整 ioctl 表 (从 mali_ioctl 反汇编解码, 已验证):**

| ioctl | 命令值 | 说明 |
|-------|--------|------|
| MEM_ALLOC | 0xC0288300 (type=0x83, nr=0, size=40) | **之前探测代码错用 nr=5 → 全 ENOTTY!** |
| MEM_FREE | 0xC0108301 (type=0x83, nr=1, size=16) | |
| MEM_BIND | 0xC0288302 (type=0x83, nr=2, size=40) | 已验证: 绑定任意物理页到 GPU VA ✓ |
| MEM_UNBIND | 0xC0108303 (type=0x83, nr=3, size=16) | |
| PP_START_JOB | 0xC1988400 (type=0x84, nr=0, size=408) | 408 字节与探测一致 ✓ |
| WAIT_FOR_NOTIFICATION | **0xC0688202** (type=0x82, nr=2, size=104) | 注意: size=104 不是 8! |
| CREATE_CONTEXT | **0xC0108203** (CORE nr=3, size=16) | 返回 version=0x03840384 |
| TERMINATE_CONTEXT | 0xC0108204 (CORE nr=4, size=16) | |
| CORE nr=13 | 0xC008820D (DUMP_STATE, 8字节) | 不是 CREATE_CONTEXT |

- subsystem: CORE=0x82, MEMORY=0x83, PP=0x84, GP=0x85
- 驱动无 compat 转换层, `_mali_ukk_pp_start_job` 直接 `__arch_copy_from_user(job, user_args, 408)` 拷贝 32 位用户结构
- `_mali_ukk_wait_for_notification`: 内核直接写 args[8]=type, memcpy 数据到 args+16

### B. 结构体布局确认 (mali_pp_job_create / mem_allocate 反汇编)
- ALLOC_MEM 40 字节: ctx(u64@0) + **gpu_vaddr(u32@8, 输入!)** + vsize@12 + psize@16 + flags@20 + backend_handle(u64@24, 输出) + secure_shared_fd@32
- **gpu_vaddr 是输入字段** → ALLOC 时必须指定 GPU 地址 (如 0x40000000)
- PP_START_JOB 408 字节: kort_miboxs.c 布局正确 (驱动读取 num_cores@328 / flags@352 匹配; 结构含 u64 → 对齐后 408)
- BIND_MEM 40 字节: ctx(u64) + vaddr@8 + size@12 + flags@16 + union{phys_addr@20, rights@24, flags@28} + pad@32 + fd@36
- CREATE_CONTEXT 16 字节: version(u32@0) + pad + ctx(u64@8)

### C. physmem 读取测试结论 (kort_phys_read, 实测)
- ALLOC_MEM (nr=0) 返回 0 不再 ENOTTY ✓ (ioctl 编号修正生效)
- BIND_MEM 绑定内核物理页 0x01080000 → GPU VA 0x40200000 成功 ✓
- **mmap 绑定页失败 (EFAULT)** → 不能 CPU 直接读 → **必须 PP job (GPU DMA) 写入**



### E. PP job 测试现状 (kort_pp_verify, 实测 2026-08-25 15:20)
- sizeof(pp_start_job_s)=408, sizeof(wait_notif)=104 ✓ (与驱动期望一致)
- ALLOC_MEM (gpu_vaddr=0x40000000 输入) 成功 + mmap 成功 ✓
- **PP_START_JOB 提交成功, WAIT 收到 notif.type=0x00020010 (PP_FINISHED)**
- **但 status = 0x00800000 = UNKNOWN_ERR** (bit 23) — GPU 执行失败, 写入未落地
- 换 clear_color=0x12345678 再测 → 同样 UNKNOWN_ERR

**驱动挂起教训 (重要!):**
- `msync()` 对 /dev/mali 的 mmap → **永久挂起** (不要用!)
- CREATE_CONTEXT + flags=1 + `__builtin___clear_cache` 组合 → PP_START_JOB **永久挂起** (alarm 无效 = 不可中断睡眠, 需重启设备或等超时)
- 每次挂起后进程被杀, 设备本身存活

**UNKNOWN_ERR 可能原因 (待排查):**
1. **GPU 读不到 job 数据** — CPU 写 cache 未 flush 到 GPU 可见 (r10p1 无 write-combining? 需检查驱动 cache 策略)
2. **context 未真正创建** — CREATE_CONTEXT 返回 ctx=0x03840384 可疑 (与 version 同值, 可能只是回显)
3. **PLB/RSW 格式** — kort 的配置来自 Mali-400 老驱动, r10p1 可能不同
4. shader 魔数 0x00020425/0x01e007cf 已在 libGLES_mali.so 中确认存在 → shader 格式应该兼容

### UNKNOWN_ERR 根因已用源码定位 (2026-08-26 02:00) — 重要更新!
源码仓库: `F:\down\player6\android_hardware_amlogic_kernel-modules_mali-driver-7a135203700d4f42af934f89f03efcb09953db77\...\utgard\r10p0\` (设备 r10p1 同源)。

**根因链 (反汇编 + 源码双确认)**:
```
PP_INT_RAWSTAT & MASK_USED
  ├─ 精确 == END_OF_FRAME(0x1) → SUCCESS (唯一成功路径)
  └─ 任何其他位 → ERROR
        → mali_pp_job_mark_sub_job_completed(job, FALSE)
        → sub_job_errors++
        → mali_pp_job_was_success = FALSE
        → status = 0x800000 UNKNOWN_ERR (驱动合成, 非硬件直读)
```
错误位候选: WRITE_BOUNDARY_ERROR(bit8=0x100) / BUS_ERROR(bit4=0x10) / INVALID_PLIST_COMMAND(bit9=0x200) / CALL_STACK_OVERFLOW(bit11=0x800)。

**WB 寄存器布局错位 (核心嫌疑)**:
r10p1 硬件 WB 布局: [0]SourceSelect [1]TargetAddr [2]PixelFormat [3]AAFormat [4]Layout [5]ScanlineLength [6]TargetFlags [7]MRTEnable [8]MRTOffset...
**kort 原版的 WB_MRT_BITS=4 实际写进 TargetFlags[6]** (Mali-400 忽略, Mali-450 可能严格执行报错); MRT Enable[7]=0 未设。

**判别实验已内置** (kort_miboxs.c 新 --diag 模式, 写 GPU 自有内存无需 BIND):
```
adb shell /data/local/tmp/kort_miboxs_new --diag
# cfg0: WB 禁用(渲染-only)   cfg1: WB on flags=0
# cfg2: WB on legacy MRT=4   cfg3: WB on MRT=4+Enable=4
# cfg4: WB on flags=0 stack=0x400
```
同时抓 dmesg: `adb shell "dmesg | grep -iE 'mali|pp|mmu' | tail -80"` 看 rawstat 实际错误位。

### 下一步
1. 跑 --diag 判别 + 抓 dmesg, 定位具体错误位
2. 修正 WB 配置 (TargetFlags=0, 正确 Source Select/MRT Enable)
3. 成功后 BIND modprobe_path 物理页 0x027df000 → PP job 多次写字符串
4. 触发 modprobe → root (uid=0)

## 待解决的关键问题

### 高优先级 (2026-08-25 更新)
1. **解决 PP job UNKNOWN_ERR** - 核心瓶颈 (GPU 执行失败)
   - 排查方向: cache flush 方式 / context 创建 / PLB-RSW 格式
2. ~~找到 CREATE_CONTEXT ioctl~~ - **已找到: 0xC0108203**, 但 ctx 输出可疑 (0x03840384 与 version 同值), 需对照 libGLES_mali.so 确认正确调用
3. ~~搞清楚 ALLOC_MEM 的字段布局~~ - **已确认: gpu_vaddr 是输入字段**
4. ~~KASLR 泄露~~ - **已绕过: 用物理地址方案 (PA = 0x01080000 + VA偏移)**

### 中优先级
5. **PAN 保护绕过** - ARM64 内核有 PAN，需要用 ROP/JOP
6. **SELinux 关闭** - 提权后需要关闭 SELinux

## 下一步计划 (2026-08-25 更新)

### 阶段 1: 解决 PP job UNKNOWN_ERR (当前瓶颈)
1. 回到基线配置 (无 CREATE_CONTEXT/flags/clear_cache), 确认仍 UNKNOWN_ERR
2. 逐个变量测试: cacheflush() syscall / flags bit0 / num_cores
3. 对照 libGLES_mali.so 反汇编确认: CREATE_CONTEXT 调用方式 + PP job 寄存器真实配置
4. 参考 Lima (Mesa) 的 Mali-450 PP job 构造 (开源已验证)

### 阶段 2: 物理写入
1. BIND modprobe_path 物理页 0x027df000 → GPU VA
2. PP job 多次 WB 写 "/data/local/tmp/x" 字符串
3. 触发 modprobe → root (uid=0)

### 阶段 3: 备用提权链
1. selinux_enforcing 物理 0x02a394ec 写 0 (一次 job) → 降级 SELinux
2. 若 PP job 不可行, 考虑 frels UAF 路线 (64 位内核适配复杂, 备选)

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



① 开 /dev/mali（无权限）	暴露面	设备节点对普通 app 可达（必要条件，但不是 bug 本身）
② BIND 目标内核物理页	🔴 漏洞触发点	驱动接受了你给的物理地址（内核页），没校验它不属于你，直接给 GPU 建页表 → 你拿到该物理页的读写窗
③ GPU DMA 读内核内存	利用原语	泄露基址
④ GPU DMA 写 cred/modprobe_path/selinux	利用原语	覆写
⑤ uid 0 + 满 cap + SELinux 放行	利用结果	root


缺三样：

离线 RVA 表没提取完（卡点）：kernel.bin 的 kallsyms 配对还没跑通，syms_rva.json 没生成 → exploit 的 CONFIG 块（各符号偏移）填不进去。
写原语没实测通过：PP job 帧尺寸 bug 已定位（W=H=0x10），但还没跑出 PP_FINISHED: SUCCESS 证明 GPU 能真正 DMA 写内核页。
运行时泄露代码没写：物理 RAM 扫描拿 phys_base 的逻辑清楚，但还没落到 kort_miboxs.c 里实跑。
第 1 样是关键阻塞——它产出的 RVA 是 2 和 3 的前提。先把 kallsyms 配对跑通，其余才有坐标可填。