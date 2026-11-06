#!/usr/bin/env bash
# 把已编译好的 mailway 二进制装成 .flatpak bundle。
#
# 为什么不在沙箱里编译：flatpak-builder 沙箱默认断网，cargo 拉依赖需要
# 一整套 cargo-sources 生成工具链；「先在 runner 上编好、再装箱」简单可靠，
# 产物同样是标准 flatpak bundle（org.gnome.Platform 运行时，webkitgtk 由
# 运行时提供）。
#
# 用法：build-flatpak.sh <release-二进制> <输出 .flatpak>
set -euo pipefail

BIN=${1:?用法: build-flatpak.sh <binary> <out.flatpak>}
OUT=${2:?用法: build-flatpak.sh <binary> <out.flatpak>}
APP=org.mailway.app
RUNTIME_VER=${RUNTIME_VER:-48}   # org.gnome.Platform 版本（自带 webkitgtk-4.1）
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

command -v flatpak >/dev/null || { echo "需要 flatpak"; exit 1; }

flatpak remote-add --user --if-not-exists flathub \
  https://flathub.org/repo/flathub.flatpakrepo
flatpak install --user -y --noninteractive flathub \
  "org.gnome.Platform//$RUNTIME_VER" "org.gnome.Sdk//$RUNTIME_VER"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

flatpak build-init "$WORK/build" "$APP" org.gnome.Sdk org.gnome.Platform "$RUNTIME_VER"

# 直接把产物摆进 files/（不经沙箱编译）
install -Dm755 "$BIN" "$WORK/build/files/bin/mailway"
install -Dm644 "$ROOT/packaging/org.mailway.app.desktop" \
  "$WORK/build/files/share/applications/$APP.desktop"
for s in 32 128 256 512; do
  install -Dm644 "$ROOT/src-tauri/icons/${s}x${s}.png" \
    "$WORK/build/files/share/icons/hicolor/${s}x${s}/apps/$APP.png"
done

flatpak build-finish "$WORK/build" \
  --share=network --share=ipc \
  --socket=x11 --socket=wayland --socket=pulseaudio \
  --device=dri --filesystem=home \
  --talk-name=org.freedesktop.Notifications \
  --talk-name=org.kde.StatusNotifierWatcher \
  --own-name=org.kde.StatusNotifierItem.* \
  --env=GDK_BACKEND=wayland,x11

flatpak build-export "$WORK/repo" "$WORK/build"
flatpak build-bundle "$WORK/repo" "$OUT" "$APP"
echo "flatpak bundle: $OUT"
