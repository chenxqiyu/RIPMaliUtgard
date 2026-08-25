Set-Location $PSScriptRoot

$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529"
$clang = "$ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang.cmd"

Write-Host "Building kort_probe_miboxs (armeabi-v7a, static)..." -ForegroundColor Cyan

& $clang kort_probe_miboxs.c -o kort_probe_miboxs -static

if ($LASTEXITCODE -ne 0) {
  Write-Host "BUILD FAILED" -ForegroundColor Red
  exit 1
}

Write-Host "BUILD OK" -ForegroundColor Green

# Verify binary
$file = Get-Item kort_probe_miboxs
Write-Host "  Size: $($file.Length) bytes"

# Push to device
Write-Host ""
Write-Host "Pushing to device..." -ForegroundColor Cyan
adb push kort_probe_miboxs /data/local/tmp/
adb shell chmod 755 /data/local/tmp/kort_probe_miboxs

Write-Host ""
Write-Host "Running probe..." -ForegroundColor Cyan
Write-Host "--- output ---"
adb shell /data/local/tmp/kort_probe_miboxs
Write-Host "--- end ---"
