# KingMoat release build script (Windows / PowerShell 5.1+)
# Usage: .\scripts\build.ps1 [-Version v0.1.0] [-OutputDir dist]
# Produces: dist/kingmoatwaf_<ver>/kingmoatwaf_<ver>_<os>_<arch>.{zip,tar.gz} + checksums.txt
# Targets: windows/amd64, linux/amd64, linux/arm64 (CGO disabled, pure static)
[CmdletBinding()]
param(
    [string]$Version = "dev",
    [string]$OutputDir = "dist"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

# Locate go.exe: PATH first, then common portable/standard install paths.
$goCmd = Get-Command go -ErrorAction SilentlyContinue
if (-not $goCmd) {
    foreach ($cand in @(
        (Join-Path $env:USERPROFILE "go-sdk\go\bin\go.exe"),
        "$env:ProgramFiles\Go\bin\go.exe",
        "C:\Go\bin\go.exe"
    )) {
        if (Test-Path $cand) { $env:PATH = "$(Split-Path $cand);$env:PATH"; break }
    }
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Pop-Location; throw "go toolchain not found in PATH or standard install locations"
}
Write-Host "go: $((Get-Command go).Source)"

$platforms = @(
    @{ os = "windows"; arch = "amd64" },
    @{ os = "linux";   arch = "amd64" },
    @{ os = "linux";   arch = "arm64" }
)

$outRoot = Join-Path $root "$OutputDir\kingmoatwaf_$Version"
if (Test-Path $outRoot) { Remove-Item -Recurse -Force $outRoot }
New-Item -ItemType Directory -Force $outRoot | Out-Null

$corazaVer = go list -m -f '{{.Version}}' github.com/corazawaf/coraza/v3
$crsVer = go list -m -f '{{.Version}}' github.com/corazawaf/coraza-coreruleset/v4
$ldflags = "-s -w -X main.version=$Version -X github.com/kingmoat/kingmoat/internal/api.engineCorazaVersion=$corazaVer -X github.com/kingmoat/kingmoat/internal/api.engineCRSVersion=$crsVer"
# Optional release signing public key: a build that embeds it refuses an
# unsigned upgrade package (see internal/upgrade/signature.go).
if ($env:KMWAF_RELEASE_PUBKEY) {
    $ldflags = "$ldflags -X github.com/kingmoat/kingmoat/internal/upgrade.releasePublicKey=$($env:KMWAF_RELEASE_PUBKEY)"
    Write-Host "==> embedded upgrade signing public key"
}
$env:CGO_ENABLED = "0"

# Frontend console (Vue 3 + Vite): build if node is available and any console
# input is newer than the embedded bundle; otherwise reuse the committed dist.
# The input set is not just src/: editing vite.config.js, index.html or the
# dependency lockfile changes the bundle without touching src.
$webSrc = Join-Path $root "web\console"
$webDist = Join-Path $root "internal\webui\dist"
$needBuild = -not (Test-Path (Join-Path $webDist "index.html"))
if (-not $needBuild) {
    $inputs = @()
    $inputs += Get-ChildItem (Join-Path $webSrc "src") -Recurse -File
    foreach ($f in @("index.html", "vite.config.js", "vite.config.ts", "package.json", "package-lock.json")) {
        $p = Join-Path $webSrc $f
        if (Test-Path $p) { $inputs += Get-Item $p }
    }
    $newestSrc = ($inputs | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
    $newestDist = (Get-Item (Join-Path $webDist "index.html")).LastWriteTime
    $needBuild = $newestSrc -gt $newestDist
}
if ($needBuild) {
    Write-Host "==> building frontend console"
    $node = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $node) { Pop-Location; throw "frontend rebuild needed but npm not found in PATH" }
    Push-Location $webSrc
    if (-not (Test-Path node_modules)) { npm install --registry=https://registry.npmmirror.com --no-audit --no-fund; if ($LASTEXITCODE -ne 0) { Pop-Location; throw "npm install failed" } }
    npm run build; if ($LASTEXITCODE -ne 0) { Pop-Location; throw "vite build failed" }
    Pop-Location
    robocopy (Join-Path $webSrc "dist") $webDist /MIR /NFL /NDL /NJH /NJS | Out-Null
    if ($LASTEXITCODE -gt 7) { Pop-Location; throw "copy frontend dist failed" }
    $global:LASTEXITCODE = 0
} else {
    Write-Host "==> frontend console up to date"
}

# Third-party license bundle for the release packages (ARCHITECTURE.md 搂12).
go run ./scripts/gen-licenses -out (Join-Path $outRoot "THIRD-PARTY-LICENSES")
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "gen-licenses failed" }

foreach ($p in $platforms) {
    $env:GOOS = $p.os
    $env:GOARCH = $p.arch
    $ext = ""
    if ($p.os -eq "windows") { $ext = ".exe" }

    $pkgName = "kingmoatwaf_${Version}_$($p.os)_$($p.arch)"
    $pkgDir = Join-Path $outRoot $pkgName
    New-Item -ItemType Directory -Force $pkgDir | Out-Null

    Write-Host "==> building $pkgName"
    # no_fs_access: coraza skips its /tmp writability probe at WAF build time.
    # Required for hardened systemd units (ProtectSystem=strict without /tmp in
    # ReadWritePaths) where the probe fails and cold start exits. All coraza
    # inputs are embedded (@include of the bundled CRS), so local FS access is
    # never needed. See deploy/install.sh for the unit layout.
    go build -trimpath -tags no_fs_access -ldflags $ldflags -o (Join-Path $pkgDir "kingmoatwaf$ext") ./cmd/kingmoatwaf
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "build kingmoatwaf failed for $($p.os)/$($p.arch)" }
    go build -trimpath -tags no_fs_access -ldflags $ldflags -o (Join-Path $pkgDir "kmwafctl$ext") ./cmd/kmwafctl
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "build kmwafctl failed for $($p.os)/$($p.arch)" }

    Copy-Item (Join-Path $root "LICENSE"), (Join-Path $root "NOTICE"), (Join-Path $root "README.md"), (Join-Path $root "config.example.json") $pkgDir
    Copy-Item (Join-Path $outRoot "THIRD-PARTY-LICENSES") $pkgDir
    go version -m (Join-Path $pkgDir "kingmoatwaf$ext") | Out-File -Encoding utf8 (Join-Path $pkgDir "SBOM.txt")
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "go version -m failed for $($p.os)/$($p.arch)" }
    Copy-Item (Join-Path $root "deploy\kingmoatwaf.service") $pkgDir
    if ($p.os -eq "windows") {
        Copy-Item (Join-Path $root "deploy\windows.md") $pkgDir
    }

    if ($p.os -eq "windows") {
        $zip = "$pkgDir.zip"
        Compress-Archive -Path $pkgDir -DestinationPath $zip -Force
    } else {
        $tgz = "$pkgDir.tar.gz"
        tar -czf $tgz -C $outRoot $pkgName
    }
    Remove-Item -Recurse -Force $pkgDir
}

Pop-Location

# checksums
$sumFile = Join-Path $outRoot "checksums.txt"
if (Test-Path $sumFile) { Remove-Item $sumFile }
Get-ChildItem $outRoot -File | Where-Object { $_.Name -ne "checksums.txt" } | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    Add-Content -Path $sumFile -Value "$h  $($_.Name)" -Encoding ascii
}

# Detached Ed25519 signature over checksums.txt; the console only enforces it
# when the binary embeds the matching public key (KMWAF_RELEASE_PUBKEY).
if ($env:KMWAF_RELEASE_SIGNING_KEY -and (Test-Path $env:KMWAF_RELEASE_SIGNING_KEY)) {
    # Build the signer to a real exe first: `go run` inside a UNC working
    # directory resolves its temp binary through %PATH% and fails. GOOS/GOARCH
    # are still pinned to the last cross-compiled target, so reset them to the
    # host or the tool comes out as a linux/arm64 binary.
    $signer = Join-Path $env:TEMP "kingmoat-sign-release.exe"
    $savedGoos, $savedGoarch = $env:GOOS, $env:GOARCH
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    Push-Location $root
    go build -o $signer ./scripts/sign-release
    Pop-Location
    $env:GOOS, $env:GOARCH = $savedGoos, $savedGoarch
    if ($LASTEXITCODE -ne 0) { throw "building the signing tool failed" }
    & $signer -key $env:KMWAF_RELEASE_SIGNING_KEY -in $sumFile
    if ($LASTEXITCODE -ne 0) { throw "signing checksums.txt failed" }
    Write-Host "==> checksums.txt.sig written"
} else {
    Write-Host "==> checksums.txt left unsigned (KMWAF_RELEASE_SIGNING_KEY not set)"
}

Write-Host "`n== artifacts =="
Get-ChildItem $outRoot | ForEach-Object { Write-Host $_.Name }
Write-Host "`ndone: $outRoot"
