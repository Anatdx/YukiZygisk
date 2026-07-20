/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - kernel-side zygote detection and AT_ENTRY injection.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef __YZ_H_ZYGOTE_PROBE
#define __YZ_H_ZYGOTE_PROBE

#include <linux/types.h>

struct yz_native_targets_cmd;
struct yz_safemode_status_cmd;
struct yz_zygote_variants_cmd;
struct cred;
struct file;

void yz_zygote_probe_init(void);
void yz_zygote_probe_exit(void);
void yz_zygote_probe_set_dlopen_off(u64 dlopen_off, u64 dlsym_off);
void yz_zygote_probe_set_yukilinker(bool enabled);
int yz_zygote_probe_set_native_targets(
    const struct yz_native_targets_cmd *cmd);
int yz_zygote_probe_restore_native_policy(pid_t tgid);
int yz_zygote_probe_allow_module_policy(pid_t tgid, struct file *dir,
					const struct cred *cred);
int yz_zygote_probe_get_safemode(struct yz_safemode_status_cmd *cmd);
int yz_zygote_probe_get_variants(struct yz_zygote_variants_cmd *cmd);

#endif // #ifndef __YZ_H_ZYGOTE_PROBE
