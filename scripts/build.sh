#!/usr/bin/env bash
# KingMoat release build script (Linux / CI)
# Usage: ./scripts/build.sh [version]   (default: dev)
# Targets: windows/amd64, linux/amd64, linux/arm64 (CGO disabled, static)
set -euo pipefail

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTROOT="$ROOT/dist/kingmoatwaf_${VERSION}"

rm -rf "$OUTROOT"
mkdir -p "$OUTROOT"
cd "$ROOT"

# The console is embedded with go:embed from internal/webui/dist: a stale
# bundle ships a stale UI even when the Go code is current (CI runs this script
# and has no frontend step of its own). Rebuild it when the toolchain is here;
# otherwise refuse to package rather than silently shipping old pages.
WEB_SRC="$ROOT/web/console"
WEB_DIST="$ROOT/internal/webui/dist"
if [ -d "$WEB_SRC/src" ] && [ -f "$WEB_DIST/index.html" ]; then
    if command -v npm >/dev/null 2>&1; then
        echo "==> building console bundle (npm run build)"
        if [ ! -d "$WEB_SRC/node_modules" ]; then
            ( cd "$WEB_SRC" && npm ci --registry="${NPM_REGISTRY:-https://registry.npmmirror.com}" )
        fi
        ( cd "$WEB_SRC" && npm run build )
        rm -rf "$WEB_DIST"
        mkdir -p "$WEB_DIST"
        cp -a "$WEB_SRC/dist/." "$WEB_DIST/"
        echo "==> console bundle synced to internal/webui/dist"
    else
        # No npm: rely on the bundle committed next to the sources. mtime is
        # useless here (a fresh checkout stamps every file with the checkout
        # time, so src and dist compare arbitrarily), so ask git whether either
        # side diverged from HEAD.
        if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
            if ! git -C "$ROOT" diff --quiet HEAD -- web/console/src internal/webui/dist; then
                echo "ERROR: web/console/src or internal/webui/dist differs from HEAD." >&2
                echo "       Rebuild the console (npm run build + copy dist into internal/webui/dist)" >&2
                echo "       and commit both, or package with scripts/build.ps1 which builds it for you." >&2
                exit 1
            fi
        fi
        echo "==> console bundle matches HEAD (npm unavailable; reusing internal/webui/dist)"
    fi
fi

# Third-party license bundle for the release packages (ARCHITECTURE.md 搂12).
go run ./scripts/gen-licenses -out "$OUTROOT/THIRD-PARTY-LICENSES"

export CGO_ENABLED=0
LDFLAGS="-s -w -X main.version=${VERSION} -X github.com/kingmoat/kingmoat/internal/api.engineCorazaVersion=$(go list -m -f '{{.Version}}' github.com/corazawaf/coraza/v3) -X github.com/kingmoat/kingmoat/internal/api.engineCRSVersion=$(go list -m -f '{{.Version}}' github.com/corazawaf/coraza-coreruleset/v4)"
# Optional release signing public key: a build that embeds it refuses an
# unsigned upgrade package (see internal/upgrade/signature.go).
if [ -n "${KMWAF_RELEASE_PUBKEY:-}" ]; then
    LDFLAGS="$LDFLAGS -X github.com/kingmoat/kingmoat/internal/upgrade.releasePublicKey=${KMWAF_RELEASE_PUBKEY}"
    echo "==> embedded upgrade signing public key"
fi

build_pkg() {
    local os="$1" arch="$2" ext=""
    [ "$os" = "windows" ] && ext=".exe"
    local pkgName="kingmoatwaf_${VERSION}_${os}_${arch}"
    local pkgDir="$OUTROOT/$pkgName"
    mkdir -p "$pkgDir"

    echo "==> building $pkgName"
    # no_fs_access: coraza skips its /tmp writability probe at WAF build time
    # (hardened systemd units keep /tmp read-only). All coraza inputs are
    # embedded, so local FS access is never needed.
    GOOS="$os" GOARCH="$arch" go build -trimpath -tags no_fs_access -ldflags "$LDFLAGS" -o "$pkgDir/kingmoatwaf$ext" ./cmd/kingmoatwaf
    GOOS="$os" GOARCH="$arch" go build -trimpath -tags no_fs_access -ldflags "$LDFLAGS" -o "$pkgDir/kmwafctl$ext" ./cmd/kmwafctl

    cp LICENSE NOTICE README.md config.example.json "$pkgDir/"
    cp "$OUTROOT/THIRD-PARTY-LICENSES" "$pkgDir/"
    go version -m "$pkgDir/kingmoatwaf$ext" > "$pkgDir/SBOM.txt"
    cp deploy/kingmoatwaf.service "$pkgDir/"
    [ "$os" = "windows" ] && cp deploy/windows.md "$pkgDir/"

    if [ "$os" = "windows" ]; then
        (cd "$OUTROOT" && zip -qr "$pkgName.zip" "$pkgName")
    else
        tar -czf "$OUTROOT/$pkgName.tar.gz" -C "$OUTROOT" "$pkgName"
    fi
    rm -rf "$pkgDir"
}

build_pkg windows amd64
build_pkg linux amd64
build_pkg linux arm64

# checksums
cd "$OUTROOT"
: > checksums.txt
for f in *.zip *.tar.gz; do
    [ -e "$f" ] || continue
    sha256sum "$f" >> checksums.txt
done

# checksums.txt is published unsigned in this repository: the Ed25519 signing
# tool belongs to the internal release pipeline and is not shipped here. The
# binary still verifies a detached checksums.txt.sig when a public key is
# embedded at build time (internal/upgrade/signature.go).
echo "==> checksums.txt left unsigned (no signing key in this repository)"

echo
echo "== artifacts =="
ls -l
echo
echo "done: $OUTROOT"
