%CLANG% kort_leak_scan.c -o kort_leak_scan -static
adb push kort_leak_scan /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/kort_leak_scan
rem 默认窗口(已知 RAM), 直接扫
adb shell /data/local/tmp/kort_leak_scan
rem 或单页校验已知基址
adb shell /data/local/tmp/kort_leak_scan -p 0x01080000 -d
