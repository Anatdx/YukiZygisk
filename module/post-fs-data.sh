#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module post-fs-data entry point.
#
# License: Apache-2.0
#
# Author: Anatdx

MODDIR="${0%/*}"
BASE_DIR="/data/adb/yukizygisk"
LIB_DIR="$BASE_DIR/lib"
RUN_DIR="$BASE_DIR/run"
LOG_FILE="$BASE_DIR/zygiskd.log"
CONFIG_FILE="$BASE_DIR/yzconfig.json"
MODULES_DIR="/data/adb/modules"

mkdir -p "$BASE_DIR" "$LIB_DIR" "$RUN_DIR"
chmod 0755 "$BASE_DIR" "$LIB_DIR" "$RUN_DIR"
touch "$LOG_FILE" 2>/dev/null || true

log() {
	echo "post-fs-data: $*" >>"$LOG_FILE"
}

random_cookie() {
	c="$(od -An -N8 -tx8 /dev/urandom 2>/dev/null | tr -d ' \n')"
	if [ -n "$c" ]; then
		echo "0x$c"
	else
		echo "0x$(date +%s)$$"
	fi
}

COOKIE="$(random_cookie)"

chmod 0755 "$MODDIR/zygiskd" 2>/dev/null || true

for lib in libzygisk.so libyukilinker.so libyukizncore.so; do
	if [ ! -f "$MODDIR/$lib" ]; then
		log "missing payload $lib"
		exit 0
	fi
	if ! cp "$MODDIR/$lib" "$LIB_DIR/$lib.tmp" 2>>"$LOG_FILE"; then
		log "copy $lib failed"
		exit 0
	fi
	mv "$LIB_DIR/$lib.tmp" "$LIB_DIR/$lib" 2>>"$LOG_FILE" || exit 0
	chmod 0644 "$LIB_DIR/$lib" 2>/dev/null || true
done

if grep -q '^yukizygisk ' /proc/modules 2>/dev/null; then
	log "yukizygisk.ko already loaded"
	exit 0
fi

INSMOD="$(command -v insmod 2>/dev/null || echo /system/bin/insmod)"
log "loading yukizygisk.ko cookie=$COOKIE"
if ! "$INSMOD" "$MODDIR/yukizygisk.ko" bootstrap_cookie_lo="$COOKIE" \
	>>"$LOG_FILE" 2>&1; then
	log "insmod failed"
	exit 0
fi

log "starting zygiskd"
YUKIZYGISK_BOOTSTRAP_COOKIE_LO="$COOKIE" \
YUKIZYGISK_CONFIG="$CONFIG_FILE" \
YUKIZYGISK_MODULES_DIR="$MODULES_DIR" \
"$MODDIR/zygiskd" \
	--bootstrap-cookie-lo "$COOKIE" \
	--config "$CONFIG_FILE" \
	--modules-dir "$MODULES_DIR" \
	>>"$LOG_FILE" 2>&1 &

exit 0
