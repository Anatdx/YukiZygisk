# YukiZygisk Kernel LKM

This directory is the first standalone extraction point for the kernel-side
YukiZygisk code currently implemented inside YukiSU.

Current state:

- `feature/zygote_*.c` and matching headers are imported from YukiSU commit
  `754182ed55923beba83484fa6624250a8c78cf39`.
- `core/module.c` provides an independent module entry/exit path.
- `core/bootstrap.c` installs a one-shot `prctl` kprobe bootstrap. The module
  takes `bootstrap_cookie_lo` and optional `bootstrap_cookie_hi`; zygiskd calls
  `prctl(YZ_PRCTL_BOOTSTRAP_OPTION, YZ_PRCTL_BOOTSTRAP_MAGIC_YUKIHOOK,
  cookie_lo, cookie_hi, &fd)` and receives the control fd through the out
  pointer before returning to userspace. If nobody claims the fd, the
  `bootstrap_guard_delay_sec`/`bootstrap_guard_max_sec` guard watches for
  zygote service sockets, then removes the hook and requests a best-effort
  self-unload through `toybox rmmod yukizygisk`.
- `core/control.c` exposes the YukiZygisk `YZ_IOCTL_*` UAPI through that
  anonymous fd. There is no standalone `/dev/yukizygisk` misc device.
- `host/host.h` and `host/adapter.c` are the temporary host adapter. They
  preserve source-level build boundaries while the remaining SELinux,
  root-backend, and daemon integrations are extracted.
- `host/runtime.c` and `host/root_impl.c` reuse Kasumi's runtime symbol
  resolver and root implementation detector under YukiZygisk naming. Host init
  accepts one KernelSU or KernelPatch/APatch owner with a readable denylist and
  rejects Magisk-only, multi-root, and no-root environments.
- `YZ_IOCTL_GET_ROOT_STATUS` exposes the accepted owner and KernelSU redirect
  state; `YZ_IOCTL_UID_SHOULD_UMOUNT` routes full-UID policy queries through the
  YukiZygisk host boundary.
- `host/lsm.c` provides the versioned LSM hook backend for the AT_ENTRY
  interception point. It patches `static_calls_table` on 6.12+ and
  `security_hook_heads` on older kernels.
- `host/patch_text.c` provides the arm64 patch primitive used by the LSM
  backend.
- `feature/zygote_orch.c` monitors successful `setresuid` through syscall
  tracepoints and defers specialize notifications through a workqueue. Do not
  add a direct syscall-table fallback here; use a host backend if a target lacks
  usable syscall tracepoints.
- `host/mount.c` owns standalone `YZ_IOCTL_UMOUNT_PID` cleanup. It schedules
  target-context task work, scans the app's mount namespace, and detaches
  KSU/Magisk/APatch/YukiZygisk and `/data/adb` module mounts itself instead of
  depending on KSU `kernel_umount`.

This is not yet a complete replacement for the YukiSU-integrated module.
KernelSU and KernelPatch/APatch are modeled as host backends rather than core
owners; other root states are currently unsupported. The remaining hard
dependencies are documented in `docs/source-inventory.md`.

The standalone ioctl ABI uses only `YZ_IOCTL_*` with magic `'Y'`, but the ioctl
file is delivered by one-shot bootstrap instead of a public device node. Do not
add `KSU_IOCTL_YZ_*` or magic `'K'` here; that ABI remains with the integrated
YukiSU/YukiZygisk module.

The intended standalone package shape is a normal module: `post-fs-data.sh`
generates a per-boot cookie, loads `yukizygisk.ko`, starts `zygiskd`, and lets
zygiskd claim the anonymous control fd immediately through the bootstrap call.
This intentionally gives up the early-native snapshot path as the default mode.

Build shape:

```bash
ddk build -- W=1
```

The target is pinned by `.ddk-version`.
