set CLANG=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang
@REM %CLANG% trigger_modprobe2.c -o trigger_modprobe2 -static


@REM adb push trigger_modprobe2 /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/trigger_modprobe2
@REM adb shell /data/local/tmp/trigger_modprobe2



%CLANG% b_probe.c -o b_probe -static
adb push b_probe /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/b_probe
