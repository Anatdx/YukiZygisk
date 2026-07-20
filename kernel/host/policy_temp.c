/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Temporary SELinux allowances for native injection.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "host/policy.h"
#include "host/policy_base.h"
#include "host/policy_temp.h"

#define YZ_POLICY_TEMP_RULE_MAX 64
#define YZ_POLICY_PERM_BITS 32
#define YZ_POLICY_TYPE_NAME_MAX 64

struct yz_policy_temp_rule {
	bool used;
	struct yz_policy_key key;
	u16 refs[YZ_POLICY_PERM_BITS];
};

static struct yz_policy_temp_rule
	yz_policy_temp_rules[YZ_POLICY_TEMP_RULE_MAX];

void yz_policy_temp_reset(void)
{
	int ret;

	ret = yz_policy_base_lock();
	if (ret) {
		memset(yz_policy_temp_rules, 0, sizeof(yz_policy_temp_rules));
		return;
	}

	memset(yz_policy_temp_rules, 0, sizeof(yz_policy_temp_rules));
	yz_policy_base_unlock();
}

static bool yz_policy_temp_key_eq(const struct yz_policy_key *a,
				  const struct yz_policy_key *b)
{
	return a->src_type == b->src_type && a->tgt_type == b->tgt_type &&
	       a->tclass == b->tclass;
}

static struct yz_policy_temp_rule *
yz_policy_temp_find_locked(const struct yz_policy_key *key)
{
	int i;

	for (i = 0; i < YZ_POLICY_TEMP_RULE_MAX; i++) {
		if (yz_policy_temp_rules[i].used &&
		    yz_policy_temp_key_eq(&yz_policy_temp_rules[i].key, key))
			return &yz_policy_temp_rules[i];
	}

	return NULL;
}

static struct yz_policy_temp_rule *yz_policy_temp_find_free_locked(void)
{
	int i;

	for (i = 0; i < YZ_POLICY_TEMP_RULE_MAX; i++) {
		if (!yz_policy_temp_rules[i].used)
			return &yz_policy_temp_rules[i];
	}

	return NULL;
}

static u32 yz_policy_temp_mask_locked(const struct yz_policy_key *key)
{
	struct yz_policy_temp_rule *rule;
	u32 mask = 0;
	int i;

	rule = yz_policy_temp_find_locked(key);
	if (!rule)
		return 0;

	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (rule->refs[i])
			mask |= 1U << i;
	}

	return mask;
}

static int yz_policy_temp_validate_add_locked(const struct yz_policy_key *key,
					      u32 av)
{
	struct yz_policy_temp_rule *rule;
	int i;

	if (!av)
		return 0;

	rule = yz_policy_temp_find_locked(key);
	if (!rule && !yz_policy_temp_find_free_locked())
		return -ENOSPC;

	if (rule) {
		for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
			if ((av & (1U << i)) && rule->refs[i] == U16_MAX)
				return -EOVERFLOW;
		}
	}

	return 0;
}

static void yz_policy_temp_add_locked(const struct yz_policy_key *key, u32 av)
{
	struct yz_policy_temp_rule *rule;
	int i;

	if (!av)
		return;

	rule = yz_policy_temp_find_locked(key);
	if (!rule) {
		rule = yz_policy_temp_find_free_locked();
		if (!rule)
			return;
		memset(rule, 0, sizeof(*rule));
		rule->used = true;
		rule->key = *key;
	}

	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (av & (1U << i))
			rule->refs[i]++;
	}
}

static u32 yz_policy_temp_plan_release_locked(const struct yz_policy_key *key,
					      u32 av)
{
	struct yz_policy_temp_rule *rule;
	u32 clear_av = 0;
	int i;

	if (!av)
		return 0;

	rule = yz_policy_temp_find_locked(key);
	if (!rule)
		return av;

	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (!(av & (1U << i)))
			continue;
		if (rule->refs[i] <= 1)
			clear_av |= 1U << i;
	}

	return clear_av;
}

static void yz_policy_temp_release_locked(const struct yz_policy_key *key,
					  u32 av)
{
	struct yz_policy_temp_rule *rule;
	bool any = false;
	int i;

	if (!av)
		return;

	rule = yz_policy_temp_find_locked(key);
	if (!rule)
		return;

	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (!(av & (1U << i)))
			continue;
		if (rule->refs[i])
			rule->refs[i]--;
	}

	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (rule->refs[i]) {
			any = true;
			break;
		}
	}
	if (!any)
		memset(rule, 0, sizeof(*rule));
}

static int yz_policy_temp_plan_allow_locked(const struct yz_policy_key *key,
					    u32 required_av, u32 *state_av,
					    u32 *commit_av)
{
	u32 direct_av;
	u32 owned_av;
	u32 request_av;
	int ret;

	if (state_av)
		*state_av = 0;
	if (commit_av)
		*commit_av = 0;
	if (!required_av)
		return -ENOENT;

	direct_av = yz_policy_base_direct_allowed_av(key);
	owned_av = yz_policy_temp_mask_locked(key);
	request_av = required_av & (~direct_av | owned_av);
	if (!request_av)
		return 0;

	ret = yz_policy_temp_validate_add_locked(key, request_av);
	if (ret)
		return ret;

	if (state_av)
		*state_av = request_av;
	if (commit_av)
		*commit_av = request_av & ~owned_av;
	return 0;
}

static int yz_host_policy_allow_file(
	struct file *file, const struct cred *cred, bool include_dir,
	bool include_tmpfs, struct yz_file_load_policy *state)
{
	struct yz_policy_file_load_keys keys = {};
	u32 file_commit_av = 0;
	u32 dir_commit_av = 0;
	u32 tmpfs_commit_av = 0;
	char src_name[YZ_POLICY_TYPE_NAME_MAX];
	char tgt_name[YZ_POLICY_TYPE_NAME_MAX];
	int ret;

	if (!file || !cred || !state)
		return -EINVAL;
	memset(state, 0, sizeof(*state));

	ret = yz_policy_base_lock();
	if (ret)
		return ret;

	ret = yz_policy_base_get_file_load_keys(
		file, cred, include_dir, include_tmpfs, &keys, src_name,
		sizeof(src_name), tgt_name, sizeof(tgt_name));
	if (ret)
		goto out_unlock;

	ret = yz_policy_temp_plan_allow_locked(&keys.file,
					       keys.file_required_av,
					       &state->added_av,
					       &file_commit_av);
	if (ret)
		goto out_unlock;

	if (keys.dir_required_av) {
		ret = yz_policy_temp_plan_allow_locked(
			&keys.dir, keys.dir_required_av, &state->dir_added_av,
			&dir_commit_av);
		if (ret)
			goto out_clear_state;
	}

	if (keys.tmpfs_required_av) {
		ret = yz_policy_temp_plan_allow_locked(
			&keys.tmpfs, keys.tmpfs_required_av,
			&state->tmpfs_added_av, &tmpfs_commit_av);
		if (ret)
			goto out_clear_state;
	}

	state->src_type = keys.file.src_type;
	state->tgt_type = keys.file.tgt_type;
	state->tmpfs_type = keys.tmpfs.tgt_type;
	state->target_class = keys.file.tclass;
	state->dir_class = keys.dir.tclass;

	ret = yz_policy_base_commit_allow_locked(
		&keys.file, file_commit_av, &keys.dir, dir_commit_av,
		&keys.tmpfs, tmpfs_commit_av, NULL, 0);
	if (ret)
		goto out_clear_state;

	yz_policy_temp_add_locked(&keys.file, state->added_av);
	yz_policy_temp_add_locked(&keys.dir, state->dir_added_av);
	yz_policy_temp_add_locked(&keys.tmpfs, state->tmpfs_added_av);

	if (state->added_av || state->dir_added_av ||
	    state->tmpfs_added_av)
		pr_info("yukizygisk: policy allow src=%s tgt=%s file=0x%x dir=0x%x tmpfs=0x%x\n",
			src_name, tgt_name, state->added_av,
			state->dir_added_av,
			state->tmpfs_added_av);
	goto out_unlock;

out_clear_state:
	memset(state, 0, sizeof(*state));

out_unlock:
	yz_policy_base_unlock();
	return ret;
}

int yz_host_policy_allow_file_current(struct file *file,
				      struct yz_file_load_policy *state)
{
	return yz_host_policy_allow_file(file, current_cred(), false, true,
					 state);
}

int yz_host_policy_allow_file_cred(struct file *file, const struct cred *cred,
				   struct yz_file_load_policy *state)
{
	return yz_host_policy_allow_file(file, cred, true, false, state);
}

int yz_host_policy_allow_execmem_current(struct yz_file_load_policy *state)
{
	struct yz_policy_key key = {};
	u32 required_av = 0;
	u32 commit_av = 0;
	char src_name[YZ_POLICY_TYPE_NAME_MAX];
	int ret;

	if (!state)
		return -EINVAL;
	if (state->process_added_av)
		return 0;

	ret = yz_policy_base_lock();
	if (ret)
		return ret;

	ret = yz_policy_base_get_execmem_key(&key, &required_av, src_name,
					     sizeof(src_name));
	if (ret)
		goto out_unlock;

	ret = yz_policy_temp_plan_allow_locked(&key, required_av,
					       &state->process_added_av,
					       &commit_av);
	if (ret)
		goto out_unlock;

	state->process_type = key.src_type;
	state->process_class = key.tclass;

	ret = yz_policy_base_commit_allow_locked(NULL, 0, NULL, 0, NULL, 0,
						 &key, commit_av);
	if (ret) {
		state->process_type = 0;
		state->process_class = 0;
		state->process_added_av = 0;
		goto out_unlock;
	}

	yz_policy_temp_add_locked(&key, state->process_added_av);

	if (state->process_added_av)
		pr_info("yukizygisk: policy allow src=%s process=0x%x\n",
			src_name, state->process_added_av);

out_unlock:
	yz_policy_base_unlock();
	return ret;
}

int yz_host_policy_restore(const struct yz_file_load_policy *state)
{
	struct yz_policy_key file_key = {};
	struct yz_policy_key dir_key = {};
	struct yz_policy_key tmpfs_key = {};
	struct yz_policy_key process_key = {};
	u32 file_clear_av = 0;
	u32 dir_clear_av = 0;
	u32 tmpfs_clear_av = 0;
	u32 process_clear_av = 0;
	int ret;

	if (!state || (!state->added_av && !state->tmpfs_added_av &&
		       !state->process_added_av && !state->dir_added_av))
		return 0;

	file_key.src_type = state->src_type;
	file_key.tgt_type = state->tgt_type;
	file_key.tclass = state->target_class;
	dir_key.src_type = state->src_type;
	dir_key.tgt_type = state->tgt_type;
	dir_key.tclass = state->dir_class;
	tmpfs_key.src_type = state->src_type;
	tmpfs_key.tgt_type = state->tmpfs_type;
	tmpfs_key.tclass = state->target_class;
	process_key.src_type = state->process_type;
	process_key.tgt_type = state->process_type;
	process_key.tclass = state->process_class;

	ret = yz_policy_base_lock();
	if (ret)
		return ret;

	if (state->added_av)
		file_clear_av = yz_policy_temp_plan_release_locked(
			&file_key, state->added_av);
	if (state->dir_added_av)
		dir_clear_av = yz_policy_temp_plan_release_locked(
			&dir_key, state->dir_added_av);
	if (state->tmpfs_added_av)
		tmpfs_clear_av = yz_policy_temp_plan_release_locked(
			&tmpfs_key, state->tmpfs_added_av);
	if (state->process_added_av)
		process_clear_av = yz_policy_temp_plan_release_locked(
			&process_key, state->process_added_av);

	ret = yz_policy_base_commit_restore_locked(
		&file_key, file_clear_av, &dir_key, dir_clear_av, &tmpfs_key,
		tmpfs_clear_av, &process_key, process_clear_av);
	if (!ret) {
		yz_policy_temp_release_locked(&file_key, state->added_av);
		yz_policy_temp_release_locked(&dir_key, state->dir_added_av);
		yz_policy_temp_release_locked(&tmpfs_key,
					      state->tmpfs_added_av);
		yz_policy_temp_release_locked(&process_key,
					      state->process_added_av);
		pr_info("yukizygisk: policy restore file=0x%x dir=0x%x tmpfs=0x%x process=0x%x\n",
			file_clear_av, dir_clear_av, tmpfs_clear_av,
			process_clear_av);
	}

	yz_policy_base_unlock();
	return ret;
}
