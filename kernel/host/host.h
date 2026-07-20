/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Host integration adapter declarations.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _YUKIZYGISK_HOST_H
#define _YUKIZYGISK_HOST_H

#include <linux/cred.h>
#include <linux/types.h>

#include "host/lsm.h"

struct file;

struct yz_file_load_policy {
	u32 src_type;
	u32 tgt_type;
	u32 tmpfs_type;
	u32 process_type;
	u16 target_class;
	u16 process_class;
	u16 dir_class;
	u16 reserved;
	u32 added_av;
	u32 tmpfs_added_av;
	u32 process_added_av;
	u32 dir_added_av;
};

struct yz_host_root_status {
	u32 owner;
	u32 mask;
	u32 flags;
};

int yz_host_init(void);
void yz_host_exit(void);

const struct cred *yz_host_override_creds(void);
void yz_host_revert_creds(const struct cred *old_cred);

bool yz_host_is_zygote(const struct cred *cred);
void yz_host_get_root_status(struct yz_host_root_status *status);
bool yz_host_policy_uses_fallback(void);
bool yz_host_policy_cache_ready(void);
int yz_host_uid_should_umount(uid_t uid, bool *should_umount);
int yz_host_install_policy_cache(struct file *file);
int yz_host_prepare_runtime_policy(void);

int yz_host_file_load_policy_allow_current(
	struct file *file, struct yz_file_load_policy *state);
int yz_host_file_load_policy_allow_cred(
	struct file *file, const struct cred *cred,
	struct yz_file_load_policy *state);
int yz_host_file_load_policy_allow_execmem_current(
	struct yz_file_load_policy *state);
int yz_host_file_load_policy_restore(const struct yz_file_load_policy *state);
int yz_host_umount_pid(pid_t pid);

#endif /* _YUKIZYGISK_HOST_H */
