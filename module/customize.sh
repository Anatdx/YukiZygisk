#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module install hook.
#
# License: Apache-2.0
#
# Author: Anatdx

ui_print "- Installing YukiZygisk"

ABI="$(getprop ro.product.cpu.abi 2>/dev/null)"
case "$ABI" in
arm64-v8a) ;;
*) abort "! Unsupported ABI for this package: $ABI" ;;
esac

[ -f "$MODPATH/yukizygisk.ko" ] || abort "! Missing yukizygisk.ko"
[ -f "$MODPATH/zygiskd" ] || abort "! Missing zygiskd"
for lib in libzygisk.so libyukilinker.so libyukizncore.so; do
	[ -f "$MODPATH/$lib" ] || abort "! Missing $lib"
done

chmod 0644 "$MODPATH/yukizygisk.ko"
chmod 0644 "$MODPATH"/lib*.so
chmod 0755 "$MODPATH/zygiskd" "$MODPATH/post-fs-data.sh" \
	"$MODPATH/boot-completed.sh"

BASE_DIR="/data/adb/yukizygisk"
mkdir -p "$BASE_DIR/lib"
chmod 0755 "$BASE_DIR" "$BASE_DIR/lib"

ui_print "- YukiZygisk installed"
