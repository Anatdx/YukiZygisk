# YukiZygisk

A new kernel-level Zygisk implementation designed to explore better, cleaner, and more flexible ways of injecting.

## Kernel LKM Skeleton

The standalone kernel sources live in [kernel](kernel). A single test KMI can
be built through DDK:

```bash
./build.sh kernel -k android15-6.6
```

The output is KMI-tagged as
`build/out/lkm/android15-6.6_yukizygisk.ko`. Use `--all-kmis` to build all
supported GKI targets locally. CI builds the seven supported targets as a
matrix and assembles one release module package containing every KO.

This is a buildable extraction checkpoint, not a complete runtime replacement
for the YukiSU-integrated module yet. See the source inventory for the
remaining daemon/userspace control, payload staging, and host-backend runtime
validation work. The kernel-side setresuid tracepoint monitor, SELinux policy
adapter, and mount cleanup adapter are present in the standalone LKM, but still
need device-side validation before they can be treated as runtime parity.

The standalone control path no longer creates `/dev/yukizygisk`. The LKM arms a
one-shot `prctl` bootstrap when loaded with a per-boot cookie; `zygiskd` claims
an anonymous control fd immediately after startup and then reuses the
`YZ_IOCTL_*` command surface on that fd.

If zygiskd never claims the bootstrap fd, the kernel guard checks for zygote
service sockets after a short delay. Once service startup is visible, the guard
clears the bootstrap cookie, removes the temporary `prctl` hook, and requests a
best-effort self-unload through `toybox rmmod yukizygisk`.

The standalone design remains root-implementation agnostic at its internal
boundaries, but its current admission policy is deliberately narrow. Module
initialization accepts exactly one KernelSU/YukiSU backend (redirect or
non-redirect) or one KernelPatch/APatch backend with a readable denylist.
Magisk-only, multi-root, and no-root environments fail closed. Kernel code
outside the host adapter calls YukiZygisk-owned `yz_*` and `yz_host_*`
interfaces; detection and denylist routing reuse the Kasumi implementation.

The LSM interception point is now extracted into the standalone host layer:
`selinux_bprm_committed_creds` is patched through a versioned adapter that uses
the 6.12+ `static_calls_table` path or the older `security_hook_heads` path.

Standalone mount cleanup is also owned by YukiZygisk now. `YZ_IOCTL_UMOUNT_PID`
schedules target-context task work, scans that app's `/proc/self/mountinfo`,
and detaches KSU/Magisk/APatch/YukiZygisk tagged mounts plus `/data/adb` module
mounts itself. It must not depend on KSU's `kernel_umount` feature being
enabled.

The standalone control ABI is `YZ_IOCTL_*` with ioctl magic `'Y'` only. It does
not accept the integrated YukiSU/YukiZygisk `KSU_IOCTL_YZ_*`/`'K'` ABI.

The default package is a normal module containing `zygiskd`, `libzygisk.so`,
`libyukilinker.so`, `libyukizncore.so`, and a KMI-specific LKM directory. A
local test package may contain one `lkm/<kmi>_yukizygisk.ko`:

```bash
./build.sh package -k android15-6.6
```

A release package contains all supported KMIs and is produced with
`./build.sh package --all-kmis` (or by CI's parallel matrix). During install
and `post-fs-data`, the module derives the exact GKI KMI from `uname -r` and
loads only the matching KO. Unknown releases and missing matches fail closed.
The script then starts the daemon with the same bootstrap cookie. This gives
up early-native injection by default; that capability can remain a future
optional host backend rather than the baseline standalone path.

The packaged WebUI has three pages: device/injection status, configuration,
and about/credits. It does not own a separately configured denylist. The
preferred path asks the accepted KernelSU or KernelPatch backend through a
CFI-safe kernel callable. If that callable cannot be resolved, the kernel asks
zygiskd for a refresh over netlink: zygiskd uses KernelSU's userspace
ioctl/prctl policy API or parses APatch's `package_config`, then atomically
hands a bounded snapshot back through a sealed memfd on the authenticated
anonymous control fd. The WebUI only selects whether matching processes skip
injection or keep injection before mount cleanup.
