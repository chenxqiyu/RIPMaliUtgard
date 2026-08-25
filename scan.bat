rem 编译
set NDK=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529
set CLANG=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang
@REM %CLANG% kort_leak_scan.c -o kort_leak_scan -static
%CLANG% kort_write_probe.c -o kort_write_probe -static
@REM adb push kort_leak_scan /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/kort_leak_scan
adb push kort_write_probe /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/kort_write_probe

rem 扫描默认窗口找内核基址
adb shell /data/local/tmp/kort_leak_scan
adb shell /data/local/tmp/kort_write_probe
rem 或自定义范围
adb shell /data/local/tmp/kort_leak_scan -s 0x00800000 0x02000000
rem 已知候选物理页时 dump 校验
adb shell /data/local/tmp/kort_leak_scan -p 0x01080000 -d
