<#
    fetch-vendor.ps1  -  ONE-TIME, run on the Windows build machine WITH internet.

    Downloads the ClamAV engine + the full virus-signature database into
    vendor\ClamAV\. After this, build\build.ps1 bundles them and the resulting
    USBVirusScannerSetup.exe is FULLY OFFLINE  -  employees need no internet.

    Usage:
        powershell -ExecutionPolicy Bypass -File build\fetch-vendor.ps1
        # optionally pin a version:
        powershell -ExecutionPolicy Bypass -File build\fetch-vendor.ps1 -Version 1.4.2

    You only re-run this to refresh the bundled virus signatures.
#>

param(
    [string]$Version = "1.4.2"   # ClamAV Windows portable release to bundle
)

$ErrorActionPreference = "Stop"
$Root   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Vendor = Join-Path $Root "vendor\ClamAV"
$DbDir  = Join-Path $Vendor "database"
$Tmp    = Join-Path $env:TEMP "clamav_dl"

Write-Host "== Fetching ClamAV $Version + signatures into vendor\ClamAV ==" -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path $Vendor, $DbDir, $Tmp | Out-Null

# 1. Download the official ClamAV Windows x64 portable ZIP.
$zipName = "clamav-$Version.win.x64.zip"
$url = "https://www.clamav.net/downloads/production/$zipName"
$zip = Join-Path $Tmp $zipName
Write-Host "[1/4] Downloading $url" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
} catch {
    throw "Download failed. Check the version, or grab the portable ZIP manually from https://www.clamav.net/downloads and extract it into $Vendor"
}

# 2. Extract the ZIP flat into vendor\ClamAV (the zip has a top-level folder).
Write-Host "[2/4] Extracting engine..." -ForegroundColor Yellow
$exDir = Join-Path $Tmp "ex"
if (Test-Path $exDir) { Remove-Item -Recurse -Force $exDir }
Expand-Archive -Path $zip -DestinationPath $exDir -Force
$inner = Get-ChildItem -Directory $exDir | Select-Object -First 1
$srcDir = if ($inner) { $inner.FullName } else { $exDir }
Copy-Item -Path (Join-Path $srcDir "*") -Destination $Vendor -Recurse -Force

if (-not (Test-Path (Join-Path $Vendor "clamscan.exe"))) {
    throw "clamscan.exe not found after extract. Inspect $Vendor and place the ClamAV binaries there."
}

# 3. Create a minimal freshclam.conf so we can pull the database.
Write-Host "[3/4] Preparing freshclam config..." -ForegroundColor Yellow
$sampleFc = Join-Path $Vendor "conf_examples\freshclam.conf.sample"
$fcConf   = Join-Path $Vendor "freshclam.conf"
if ((Test-Path $sampleFc) -and (-not (Test-Path $fcConf))) {
    (Get-Content $sampleFc) -replace '^Example', '#Example' | Set-Content $fcConf
} elseif (-not (Test-Path $fcConf)) {
    "DatabaseMirror database.clamav.net`nDatabaseDirectory $DbDir" | Set-Content $fcConf
}

# 4. Download the virus signature database into vendor\ClamAV\database.
Write-Host "[4/4] Downloading virus signature database (this is the big part)..." -ForegroundColor Yellow
& (Join-Path $Vendor "freshclam.exe") --config-file="$fcConf" --datadir="$DbDir"

$cvd = Get-ChildItem $DbDir -Include *.cvd,*.cld -Recurse -ErrorAction SilentlyContinue
if (-not $cvd) {
    Write-Warning "No .cvd/.cld signature files landed in $DbDir. Run freshclam again, or copy main.cvd/daily.cvd/bytecode.cvd there manually."
} else {
    Write-Host "`nDONE. Bundled engine + $($cvd.Count) signature file(s)." -ForegroundColor Green
    Write-Host "Now run:  powershell -ExecutionPolicy Bypass -File build\build.ps1" -ForegroundColor Green
    Write-Host "The installer it produces will be FULLY OFFLINE." -ForegroundColor Green
}

Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
