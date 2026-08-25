Set-Location $PSScriptRoot

$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529"
$clang = "$ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang.cmd"

Write-Host "Building kort_probe_alloc (armeabi-v7a, static)..." -ForegroundColor Cyan

& $clang kort_probe_alloc.c -o kort_probe_alloc -static

if ($LASTEXITCODE -ne 0) {
  Write-Host "BUILD FAILED" -ForegroundColor Red
  exit 1
}

Write-Host "BUILD OK" -ForegroundColor Green
adb push kort_probe_alloc /data/local/tmp/ | Out-Null
adb shell chmod 755 /data/local/tmp/kort_probe_alloc | Out-Null

Write-Host "Running ALLOC_MEM size probe..." -ForegroundColor Yellow
Write-Host ""
adb shell /data/local/tmp/kort_probe_alloc
