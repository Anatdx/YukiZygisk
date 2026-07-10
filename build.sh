#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk local build and module packager.
#
# License: Apache-2.0
#
# Author: Anatdx

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
OUT_DIR="$BUILD_DIR/out"
MODULE_TEMPLATE_DIR="$PROJECT_ROOT/module"
PACKAGE_DIR="$BUILD_DIR/package"

COMMAND="${1:-package}"
if [[ $# -gt 0 ]]; then
	shift
fi

ABI="arm64-v8a"
KMI="$(cat "$PROJECT_ROOT/.ddk-version" 2>/dev/null || echo android16-6.12)"
ANDROID_PLATFORM="android-29"
ANDROID_NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
SKIP_KERNEL=false
SKIP_DAEMON=false
SKIP_PAYLOADS=false
KEEP_BUILD=false
STRIP_ANDROID=true
VERBOSE=false

usage() {
	cat <<EOF
YukiZygisk local build and module packager.

Usage:
  ./build.sh [package|kernel|daemon|payloads|clean] [options]

Options:
  -k, --kmi KMI              DDK target for yukizygisk.ko (default: .ddk-version)
  -a, --abi ABI              Android ABI for userspace daemon (default: arm64-v8a)
      --android-platform API Android platform for daemon (default: android-29)
      --ndk PATH             Android NDK path
      --skip-kernel          Reuse build/out/yukizygisk.ko
      --skip-daemon          Reuse build/out/zygiskd
      --skip-payloads        Reuse build/out/lib*.so runtime payloads
      --keep-build           Keep intermediate build directories
      --no-strip             Keep debug info in Android artifacts
  -v, --verbose              Verbose CMake configure output
  -h, --help                 Show this help
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-k | --kmi)
		KMI="$2"
		shift 2
		;;
	-a | --abi)
		ABI="$2"
		shift 2
		;;
	--android-platform)
		ANDROID_PLATFORM="$2"
		shift 2
		;;
	--ndk)
		ANDROID_NDK="$2"
		shift 2
		;;
	--skip-kernel)
		SKIP_KERNEL=true
		shift
		;;
	--skip-daemon)
		SKIP_DAEMON=true
		shift
		;;
	--skip-payloads)
		SKIP_PAYLOADS=true
		shift
		;;
	--keep-build)
		KEEP_BUILD=true
		shift
		;;
	--no-strip)
		STRIP_ANDROID=false
		shift
		;;
	-v | --verbose)
		VERBOSE=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown option: $1" >&2
		usage >&2
		exit 1
		;;
	esac
done

info() {
	printf '>>> %s\n' "$*"
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

find_ndk() {
	if [[ -n "$ANDROID_NDK" && -d "$ANDROID_NDK" ]]; then
		return
	fi

	local bases=(
		"$HOME/Library/Android/sdk/ndk"
		"$HOME/Android/Sdk/ndk"
		"$HOME/android-sdk/ndk"
		"/opt/android-sdk/ndk"
	)
	local base latest
	for base in "${bases[@]}"; do
		if [[ -d "$base" ]]; then
			latest="$(find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1)"
			if [[ -n "$latest" && -d "$latest" ]]; then
				ANDROID_NDK="$latest"
				return
			fi
		fi
	done

	die "Android NDK not found; set ANDROID_NDK, ANDROID_NDK_HOME, or --ndk"
}

detect_ndk_host() {
	local prebuilt="$ANDROID_NDK/toolchains/llvm/prebuilt"
	local host
	for host in darwin-x86_64 darwin-arm64 linux-x86_64; do
		if [[ -d "$prebuilt/$host" ]]; then
			echo "$host"
			return
		fi
	done
	die "cannot detect NDK prebuilt toolchain under $prebuilt"
}

strip_android_file() {
	local mode="$1"
	local file="$2"
	[[ "$STRIP_ANDROID" == true ]] || return 0
	find_ndk
	local host strip
	host="$(detect_ndk_host)"
	strip="$ANDROID_NDK/toolchains/llvm/prebuilt/$host/bin/llvm-strip"
	[[ -x "$strip" ]] || die "missing llvm-strip: $strip"
	"$strip" "$mode" "$file"
}

check_common_deps() {
	need_cmd cmake
	need_cmd ninja
}

check_kernel_deps() {
	need_cmd ddk
}

check_package_deps() {
	need_cmd zip
}

compute_version() {
	local tag count
	tag="$(git -C "$PROJECT_ROOT" describe --tags --abbrev=0 2>/dev/null || echo "0.1.0")"
	tag="${tag#v}"
	[[ -n "$tag" ]] || tag="0.1.0"
	count="$(git -C "$PROJECT_ROOT" rev-list --count HEAD 2>/dev/null || echo "0")"
	VERSION_CODE=$((count + 10000))
	VERSION_NAME="v${tag}-${VERSION_CODE}"
	export VERSION_NAME VERSION_CODE
}

stamp_module_prop() {
	local prop="$PACKAGE_DIR/module.prop"
	[[ -f "$prop" ]] || die "missing $prop"
	if [[ "$(uname -s)" == "Darwin" ]]; then
		sed -i '' "s/^version=.*/version=$VERSION_NAME/" "$prop"
		sed -i '' "s/^versionCode=.*/versionCode=$VERSION_CODE/" "$prop"
	else
		sed -i "s/^version=.*/version=$VERSION_NAME/" "$prop"
		sed -i "s/^versionCode=.*/versionCode=$VERSION_CODE/" "$prop"
	fi
}

build_kernel() {
	if [[ "$SKIP_KERNEL" == true ]]; then
		[[ -f "$OUT_DIR/yukizygisk.ko" ]] ||
			die "--skip-kernel requested but build/out/yukizygisk.ko is missing"
		info "Skip kernel build"
		return
	fi

	check_kernel_deps
	info "Build yukizygisk.ko with DDK ($KMI)"
	ddk build --target "$KMI" -- W=1
	[[ -f "$PROJECT_ROOT/kernel/yukizygisk.ko" ]] ||
		die "DDK build completed but kernel/yukizygisk.ko is missing"

	mkdir -p "$OUT_DIR"
	cp "$PROJECT_ROOT/kernel/yukizygisk.ko" "$OUT_DIR/yukizygisk.ko"
	strip_android_file -d "$OUT_DIR/yukizygisk.ko"
	info "Kernel: $OUT_DIR/yukizygisk.ko"
}

build_daemon() {
	if [[ "$SKIP_DAEMON" == true ]]; then
		[[ -f "$OUT_DIR/zygiskd" ]] ||
			die "--skip-daemon requested but build/out/zygiskd is missing"
		info "Skip daemon build"
		return
	fi

	case "$ABI" in
	arm64-v8a) ;;
	*) die "unsupported module ABI for now: $ABI" ;;
	esac

	check_common_deps
	find_ndk
	[[ -f "$ANDROID_NDK/build/cmake/android.toolchain.cmake" ]] ||
		die "invalid Android NDK: $ANDROID_NDK"

	local subdir="$BUILD_DIR/$ABI"
	local cmake_args=(
		-S "$PROJECT_ROOT"
		-B "$subdir"
		-G Ninja
		-DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake"
		-DANDROID_ABI="$ABI"
		-DANDROID_PLATFORM="$ANDROID_PLATFORM"
		-DCMAKE_BUILD_TYPE=Release
	)
	if [[ "$VERBOSE" == true ]]; then
		cmake_args+=("--log-level=VERBOSE")
	fi

	info "Build zygiskd ($ABI, $ANDROID_PLATFORM)"
	cmake "${cmake_args[@]}"
	cmake --build "$subdir" --target zygiskd

	local bin="$subdir/userspace/zygisk/daemon/zygiskd"
	[[ -f "$bin" ]] || die "zygiskd output missing: $bin"
	mkdir -p "$OUT_DIR"
	cp "$bin" "$OUT_DIR/zygiskd"
	strip_android_file --strip-all "$OUT_DIR/zygiskd"
	chmod 0755 "$OUT_DIR/zygiskd"
	info "Daemon: $OUT_DIR/zygiskd"
}

build_payloads() {
	local lib
	if [[ "$SKIP_PAYLOADS" == true ]]; then
		for lib in libzygisk.so libyukilinker.so libyukizncore.so; do
			[[ -f "$OUT_DIR/$lib" ]] ||
				die "--skip-payloads requested but build/out/$lib is missing"
		done
		info "Skip runtime payload build"
		return
	fi

	case "$ABI" in
	arm64-v8a) ;;
	*) die "unsupported module ABI for now: $ABI" ;;
	esac

	check_common_deps
	find_ndk
	[[ -f "$ANDROID_NDK/build/cmake/android.toolchain.cmake" ]] ||
		die "invalid Android NDK: $ANDROID_NDK"

	local subdir="$BUILD_DIR/$ABI"
	local cmake_args=(
		-S "$PROJECT_ROOT"
		-B "$subdir"
		-G Ninja
		-DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake"
		-DANDROID_ABI="$ABI"
		-DANDROID_PLATFORM="$ANDROID_PLATFORM"
		-DCMAKE_BUILD_TYPE=Release
	)
	if [[ "$VERBOSE" == true ]]; then
		cmake_args+=("--log-level=VERBOSE")
	fi

	info "Build runtime payloads ($ABI, $ANDROID_PLATFORM)"
	cmake "${cmake_args[@]}"
	cmake --build "$subdir" --target zygisk yukilinker yukizncore

	mkdir -p "$OUT_DIR"
	for lib in libzygisk.so libyukilinker.so libyukizncore.so; do
		local src="$subdir/userspace/zygisk/core/$lib"
		[[ -f "$src" ]] || die "runtime payload output missing: $src"
		cp "$src" "$OUT_DIR/$lib"
		strip_android_file --strip-all "$OUT_DIR/$lib"
		chmod 0644 "$OUT_DIR/$lib"
		info "Runtime: $OUT_DIR/$lib"
	done
}

stage_payloads() {
	local lib
	for lib in libzygisk.so libyukilinker.so libyukizncore.so; do
		if [[ -f "$OUT_DIR/$lib" ]]; then
			cp "$OUT_DIR/$lib" "$PACKAGE_DIR/$lib"
		else
			die "missing runtime payload: build/out/$lib"
		fi
	done
}

package_module() {
	check_package_deps
	compute_version

	[[ -d "$MODULE_TEMPLATE_DIR" ]] || die "missing module template: $MODULE_TEMPLATE_DIR"
	[[ -f "$OUT_DIR/yukizygisk.ko" ]] || die "missing build/out/yukizygisk.ko"
	[[ -f "$OUT_DIR/zygiskd" ]] || die "missing build/out/zygiskd"

	info "Stage module"
	rm -rf "$PACKAGE_DIR"
	mkdir -p "$PACKAGE_DIR"
	cp -R "$MODULE_TEMPLATE_DIR/." "$PACKAGE_DIR/"
	stamp_module_prop
	cp "$PROJECT_ROOT/LICENSE" "$PACKAGE_DIR/LICENSE"
	cp "$PROJECT_ROOT/LICENSE-GPL-2.0" "$PACKAGE_DIR/LICENSE-GPL-2.0"
	cp "$PROJECT_ROOT/NOTICE" "$PACKAGE_DIR/NOTICE"
	cp "$PROJECT_ROOT/userspace/zygisk/third_party/lsplt/LICENSE" \
		"$PACKAGE_DIR/LICENSE-LSPLT"
	cp "$OUT_DIR/yukizygisk.ko" "$PACKAGE_DIR/yukizygisk.ko"
	cp "$OUT_DIR/zygiskd" "$PACKAGE_DIR/zygiskd"
	stage_payloads

	chmod 0644 "$PACKAGE_DIR/module.prop" "$PACKAGE_DIR/yukizygisk.ko" \
		"$PACKAGE_DIR"/lib*.so "$PACKAGE_DIR"/LICENSE* \
		"$PACKAGE_DIR/NOTICE"
	chmod 0755 "$PACKAGE_DIR/zygiskd" "$PACKAGE_DIR/post-fs-data.sh" \
		"$PACKAGE_DIR/boot-completed.sh" "$PACKAGE_DIR/customize.sh" \
		2>/dev/null || true

	local zip_name="YukiZygisk-${VERSION_NAME}-${KMI}-${ABI}.zip"
	local zip_path="$OUT_DIR/$zip_name"
	rm -f "$zip_path"
	info "Create module zip: $zip_path"
	(
		cd "$PACKAGE_DIR"
		zip -qr "$zip_path" .
	)
	info "Done: $zip_path"
}

clean() {
	rm -rf "$BUILD_DIR"
	ddk clean --target "$KMI" >/dev/null 2>&1 || true
	info "Cleaned"
}

case "$COMMAND" in
kernel)
	build_kernel
	;;
daemon)
	build_daemon
	;;
payloads)
	build_payloads
	;;
package)
	build_kernel
	build_daemon
	build_payloads
	package_module
	if [[ "$KEEP_BUILD" != true ]]; then
		rm -rf "${BUILD_DIR:?}/$ABI" "${PACKAGE_DIR:?}"
		ddk clean --target "$KMI" >/dev/null 2>&1 || true
	fi
	;;
clean)
	clean
	;;
-h | --help | help)
	usage
	;;
*)
	die "unknown command: $COMMAND"
	;;
esac
