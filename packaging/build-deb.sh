#!/usr/bin/env bash
# Assemble an amd64 .deb from a pre-built pccs-rs binary.
# Prefer dpkg-deb when present; fall back to ar+tar so the script can be
# checked on macOS. The GitHub release job runs this on Linux.
set -euo pipefail

VERSION=""
BINARY=""
OUTPUT="dist"
ARCH="amd64"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  echo "usage: $0 --version VERSION --binary PATH [--output DIR]" >&2
  exit 2
}

# SysV / GNU ar. dpkg reads this; BSD ar on macOS does not emit it.
write_sysv_ar() {
  local out="$1"
  shift
  {
    printf '!<arch>\n'
    local f name size
    for f in "$@"; do
      name="$(basename "$f")"
      size="$(wc -c < "$f" | tr -d ' ')"
      printf '%-16s%-12s%-6s%-6s%-8s%-10s`\n' \
        "$name" 0 0 0 100644 "$size"
      cat "$f"
      if (( size % 2 == 1 )); then
        printf '\n'
      fi
    done
  } > "$out"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --binary) BINARY="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$VERSION" && -n "$BINARY" ]] || usage
[[ -f "$BINARY" ]] || { echo "binary not found: $BINARY" >&2; exit 1; }

PKG="pccs-rs_${VERSION}_${ARCH}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

DEB="$STAGE/deb"
mkdir -p \
  "$DEB/DEBIAN" \
  "$DEB/usr/bin" \
  "$DEB/etc/pccs-rs" \
  "$DEB/lib/systemd/system" \
  "$DEB/usr/share/doc/pccs-rs"

install -m 0755 "$BINARY" "$DEB/usr/bin/pccs-rs"
if [[ "$(uname -s)" == Linux ]] && command -v strip >/dev/null 2>&1; then
  strip "$DEB/usr/bin/pccs-rs"
fi
install -m 0644 "$ROOT/packaging/config.toml" "$DEB/etc/pccs-rs/config.toml"
install -m 0644 "$ROOT/packaging/pccs-rs.service" "$DEB/lib/systemd/system/pccs-rs.service"
install -m 0644 "$ROOT/LICENSE" "$DEB/usr/share/doc/pccs-rs/copyright"

SIZE_KB="$(du -sk "$DEB/usr" "$DEB/etc" "$DEB/lib" | awk '{s+=$1} END {print s+0}')"

cat > "$DEB/DEBIAN/control" <<EOF
Package: pccs-rs
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: libc6 (>= 2.31)
Installed-Size: ${SIZE_KB}
Maintainer: Leechael <yanleech@gmail.com>
Homepage: https://github.com/Leechael/pccs-rs
Description: Rust replacement for Intel PCCS
 Production Rust + Tokio Provisioning Certificate Caching Service
 with a RocksDB cache and a 1:1 Intel PCCS HTTP API.
EOF

printf '%s\n' /etc/pccs-rs/config.toml > "$DEB/DEBIAN/conffiles"

cat > "$DEB/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$DEB/DEBIAN/postinst"

cat > "$DEB/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop pccs-rs.service >/dev/null 2>&1 || true
  systemctl disable pccs-rs.service >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$DEB/DEBIAN/prerm"

cat > "$DEB/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
  rm -rf /var/lib/pccs-rs
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$DEB/DEBIAN/postrm"

mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
OUT_DEB="$OUTPUT/${PKG}.deb"

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --root-owner-group --build "$DEB" "$OUT_DEB"
else
  # BSD ar/ranlib on macOS cannot produce a dpkg-readable archive.
  # Write the SysV / GNU ar format that dpkg expects.
  export COPYFILE_DISABLE=1
  WORK="$STAGE/ar"
  mkdir -p "$WORK"
  printf '2.0\n' > "$WORK/debian-binary"
  (cd "$DEB/DEBIAN" && tar czf "$WORK/control.tar.gz" .)
  (cd "$DEB" && tar czf "$WORK/data.tar.gz" --exclude=DEBIAN usr etc lib)
  write_sysv_ar "$OUT_DEB" \
    "$WORK/debian-binary" "$WORK/control.tar.gz" "$WORK/data.tar.gz"
fi

echo "wrote $OUT_DEB"
