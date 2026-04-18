$ErrorActionPreference = "Stop"

$repo = "AhirTech1/zero-trust-hive"
$installDir = "$env:LOCALAPPDATA\ZeroTrustHive"

Write-Host "==> Fetching latest release from $repo..." -ForegroundColor Cyan

try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
    $version = $release.tag_name
} catch {
    Write-Host "✗ Error: Failed to fetch the latest release from GitHub API." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

Write-Host "==> Found version: $version" -ForegroundColor Green

$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -eq "AMD64") {
    $archName = "amd64"
} elseif ($arch -eq "ARM64") {
    $archName = "arm64"
} else {
    Write-Host "✗ Error: Unsupported architecture: $arch" -ForegroundColor Red
    exit 1
}

$versionNoV = $version.TrimStart('v')
$zipFile = "zero-trust-hive_$versionNoV`_windows_$archName.zip"
$downloadUrl = "https://github.com/$repo/releases/download/$version/$zipFile"
$tempZip = Join-Path $env:TEMP $zipFile

Write-Host "==> Downloading $zipFile..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip
} catch {
    Write-Host "✗ Error: Download failed for URL: $downloadUrl" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

Write-Host "==> Extracting to $installDir..." -ForegroundColor Cyan

if (-Not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
}

try {
    Expand-Archive -Path $tempZip -DestinationPath $installDir -Force
} catch {
    Write-Host "✗ Error: Extraction failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Remove-Item $tempZip -Force
    exit 1
}

Remove-Item $tempZip -Force

# Rename cli.exe to hive.exe if GoReleaser kept the directory name
$cliExe = Join-Path $installDir "cli.exe"
$hiveExe = Join-Path $installDir "hive.exe"
if (Test-Path $cliExe) {
    Rename-Item -Path $cliExe -NewName "hive.exe" -Force
}

# Add to PATH
Write-Host "==> Adding $installDir to User PATH..." -ForegroundColor Cyan
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")

if ($userPath -notlike "*$installDir*") {
    $newPath = "$userPath;$installDir"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    $env:PATH = "$env:PATH;$installDir"
    Write-Host "==> ✓ Added to PATH successfully." -ForegroundColor Green
} else {
    Write-Host "==> Directory is already in your PATH." -ForegroundColor Green
}

Write-Host "==> ✓ Installation complete! Type 'hive' to start." -ForegroundColor Green
