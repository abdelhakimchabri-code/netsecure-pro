param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

if ($Clean) {
    if (Test-Path .\build) { Remove-Item -LiteralPath .\build -Recurse -Force }
    if (Test-Path .\dist) { Remove-Item -LiteralPath .\dist -Recurse -Force }
}

python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt
pyinstaller .\netsecure_pro.spec --noconfirm --clean

Write-Host "Build completed. Output folder: dist\NetSecure Pro"
