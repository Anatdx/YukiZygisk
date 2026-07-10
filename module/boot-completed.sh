#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module boot-completed health check.
#
# License: Apache-2.0
#
# Author: Anatdx

MODDIR="${0%/*}"
BASE_DIR="/data/adb/yukizygisk"
LOG_FILE="$BASE_DIR/zygiskd.log"

mkdir -p "$BASE_DIR"
touch "$LOG_FILE" 2>/dev/null || true

log() {
	echo "boot-completed: $*" >>"$LOG_FILE"
}

if "$MODDIR/zygiskd" --check-status >>"$LOG_FILE" 2>&1; then
	log "zygiskd status ok"
	exit 0
fi

log "zygiskd status unavailable; unloading yukizygisk.ko"
if ! grep -q '^yukizygisk ' /proc/modules 2>/dev/null; then
	log "yukizygisk.ko already absent"
	exit 0
fi

RMMOD="$(command -v rmmod 2>/dev/null || true)"
[ -n "$RMMOD" ] || RMMOD="/system/bin/rmmod"

if "$RMMOD" yukizygisk >>"$LOG_FILE" 2>&1; then
	log "yukizygisk.ko unloaded"
else
	log "yukizygisk.ko unload failed"
fi

exit 0
