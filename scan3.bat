set CLANG=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang
%CLANG% kort_write_probe2.c -o kort_write_probe2 -static
adb push kort_write_probe2 /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/kort_write_probe2
adb shell /data/local/tmp/kort_write_probe2
