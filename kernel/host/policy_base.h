/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - SELinux policy control base declarations.
 *
 * Derived from KernelSU/YukiSU SELinux policy helpers.
 *
 * License: GPL-2.0-only
 *
 * Author: KernelSU contributors and Anatdx
 */
#ifndef _YUKIZYGISK_HOST_POLICY_BASE_H
#define _YUKIZYGISK_HOST_POLICY_BASE_H

#include <linux/types.h>

struct cred;
struct file;

struct yz_policy_key {
	u32 src_type;
	u32 tgt_type;
	u16 tclass;
};

struct yz_policy_file_load_keys {
	struct yz_policy_key file;
	struct yz_policy_key dir;
	struct yz_policy_key tmpfs;
	u32 file_required_av;
	u32 dir_required_av;
	u32 tmpfs_required_av;
};

bool yz_policy_base_ready(void);
int yz_policy_base_lock(void);
void yz_policy_base_unlock(void);

int yz_policy_base_get_file_load_keys(
	struct file *file, const struct cred *cred, bool include_dir,
	bool include_tmpfs, struct yz_policy_file_load_keys *keys,
	char *src_name, size_t src_name_size, char *tgt_name,
	size_t tgt_name_size);
int yz_policy_base_get_execmem_key(struct yz_policy_key *key,
				   u32 *required_av, char *src_name,
				   size_t src_name_size);

u32 yz_policy_base_direct_allowed_av(const struct yz_policy_key *key);
int yz_policy_base_commit_allow_locked(
	const struct yz_policy_key *file_key, u32 file_av,
	const struct yz_policy_key *dir_key, u32 dir_av,
	const struct yz_policy_key *tmpfs_key, u32 tmpfs_av,
	const struct yz_policy_key *process_key, u32 process_av);
int yz_policy_base_commit_restore_locked(
	const struct yz_policy_key *file_key, u32 file_av,
	const struct yz_policy_key *dir_key, u32 dir_av,
	const struct yz_policy_key *tmpfs_key, u32 tmpfs_av,
	const struct yz_policy_key *process_key, u32 process_av);

#endif /* _YUKIZYGISK_HOST_POLICY_BASE_H */
