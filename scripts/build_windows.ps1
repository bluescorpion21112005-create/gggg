# Windows release build: PyInstaller one-folder → Inno Setup installer, Authenticode-signed when a
# certificate is configured.
#   pwsh scripts/build_windows.ps1
#   $env:SIGN_CERT_PFX = "C:\certs\cybrix.pfx"; $env:SIGN_CERT_PASSWORD = "…"   (optional)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$version = & $py -c "import yaml;print(yaml.safe_load(open('config/settings.yaml'))['app']['version'])"
& $py -m PyInstaller --noconfirm --clean cybrix_ai.spec
if ($LASTEXITCODE) { throw "PyInstaller failed" }

function Sign($file) {
  if (-not $env:SIGN_CERT_PFX) { Write-Host "[build] unsigned (no SIGN_CERT_PFX): $file"; return }
  & signtool sign /f $env:SIGN_CERT_PFX /p $env:SIGN_CERT_PASSWORD /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $file
  if ($LASTEXITCODE) { throw "signtool failed for $file" }
}
Sign "dist\cybrix-ai\cybrix-ai.exe"

$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
& $iscc "/DAppVersion=$version" scripts\cybrix.iss
if ($LASTEXITCODE) { throw "Inno Setup failed" }
$installer = "dist\Cybrix-Setup-$version.exe"
Sign $installer
(Get-FileHash $installer -Algorithm SHA256).Hash.ToLower() + "  " + (Split-Path $installer -Leaf) | Out-File -Encoding ascii dist\SHA256SUMS-windows
Write-Host "[build] $installer"
