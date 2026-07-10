/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - Versioned LSM hook adapter.
 *
 * Derived from KernelSU hook/lsm_hook.c.
 *
 * License: GPL-2.0-only
 *
 * Author: KernelSU contributors and Anatdx
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/static_call.h>
#endif

#include "host/lsm.h"
#include "host/patch_text.h"
#include "host/runtime.h"

struct yz_lsm_hook_entry {
	struct yz_host_lsm_hook *hook;
};

static DEFINE_MUTEX(yz_lsm_hook_lock);
static struct yz_lsm_hook_entry yz_lsm_hook_entries[16];
static int yz_lsm_hook_count;

static bool yz_lsm_hook_is_tracked(struct yz_host_lsm_hook *hook)
{
	int i;

	for (i = 0; i < yz_lsm_hook_count; i++) {
		if (yz_lsm_hook_entries[i].hook == hook)
			return true;
	}

	return false;
}

static int yz_lsm_hook_track(struct yz_host_lsm_hook *hook)
{
	if (yz_lsm_hook_is_tracked(hook))
		return 0;

	if (yz_lsm_hook_count >= ARRAY_SIZE(yz_lsm_hook_entries)) {
		pr_err("yukizygisk: lsm_hook tracking table full for %s\n",
		       hook->head_name ?: "unknown");
		return -ENOSPC;
	}

	yz_lsm_hook_entries[yz_lsm_hook_count++].hook = hook;
	return 0;
}

static void yz_lsm_hook_untrack(struct yz_host_lsm_hook *hook)
{
	int i;

	for (i = 0; i < yz_lsm_hook_count; i++) {
		if (yz_lsm_hook_entries[i].hook != hook)
			continue;

		yz_lsm_hook_entries[i] =
			yz_lsm_hook_entries[--yz_lsm_hook_count];
		return;
	}
}

static int yz_lsm_hook_patch_slot(void **slot, void *value)
{
	void *patched = value;
	int ret;

	ret = yz_patch_text(slot, &patched, sizeof(patched),
			    YZ_PATCH_TEXT_FLUSH_DCACHE);
	if (!ret)
		smp_wmb();

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static int yz_lsm_hook_update_scall(struct lsm_static_call *scall, void *value)
{
	__static_call_update(scall->key, scall->trampoline, value);
	smp_wmb();
	return 0;
}
#endif

static int yz_lsm_hook_apply(struct yz_host_lsm_hook *hook)
{
	int ret = 0;
	struct security_hook_list *entry;
	void *target;
	const char *target_name;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	static unsigned long scalls_addr;
	struct lsm_static_call *scalls = NULL;
	static size_t scalls_count;
	static u32 lsm_max_cnt = 5;
	struct security_hook_list *selected_entry = NULL;
	struct lsm_static_call *selected_scall = NULL;
	void **selected_slot = NULL;
	void *selected_origin = NULL;
	size_t i;
#else
	unsigned long heads_addr;
	struct hlist_head *head;
	struct security_hook_list *selected_entry = NULL;
	void **selected_slot = NULL;
	void *selected_origin = NULL;
#endif

	if (!hook || !hook->replacement)
		return -EINVAL;

	mutex_lock(&yz_lsm_hook_lock);

	if (hook->entry) {
		ret = -EALREADY;
		goto out_unlock;
	}

	target_name = hook->target_name;
	if (!target_name) {
		pr_err("yukizygisk: lsm_hook %s target_name is required\n",
		       hook->head_name ?: "unknown");
		ret = -EINVAL;
		goto out_unlock;
	}

	target = hook->original;
	if (!target)
		target = (void *)yz_lookup_callable(target_name);
	if (!target) {
		pr_err("yukizygisk: lsm_hook failed to resolve target for %s\n",
		       hook->head_name ?: "unknown");
		ret = -ENOENT;
		goto out_unlock;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	if (!scalls_addr)
		scalls_addr = yz_lookup_name("static_calls_table");
	if (!scalls_addr) {
		pr_err("yukizygisk: lsm_hook failed to resolve static_calls_table\n");
		ret = -ENOSYS;
		goto out_unlock;
	}

	if (scalls_count == 0) {
		unsigned long sym_size = sizeof(struct lsm_static_calls_table);
		u32 lsm_active_cnt = 5;
		unsigned long addr;

		if (!yz_lookup_size_offset(scalls_addr, &sym_size, NULL))
			pr_warn("yukizygisk: lsm_hook failed to get static_calls_table size\n");

		addr = yz_lookup_name("lsm_active_cnt");
		if (!addr) {
			pr_warn("yukizygisk: lsm_hook failed to get lsm_active_cnt\n");
		} else {
			lsm_active_cnt = *(u32 *)addr;
		}

		if (lsm_active_cnt == 0 || lsm_active_cnt > 20) {
			pr_warn("yukizygisk: lsm_hook invalid lsm_active_cnt=%u\n",
				lsm_active_cnt);
		} else {
			lsm_max_cnt = lsm_active_cnt;
			if (sym_size % (lsm_active_cnt *
					sizeof(struct lsm_static_call)) != 0)
				pr_warn("yukizygisk: lsm_hook static call table size is not aligned\n");
			scalls_count = sym_size / sizeof(struct lsm_static_call);
			pr_info("yukizygisk: lsm_hook scalls_count=%zu active=%u\n",
				scalls_count, lsm_active_cnt);
		}
	}

	if (scalls_count == 0) {
		pr_err("yukizygisk: lsm_hook no static call table entries\n");
		ret = -ENOSYS;
		goto out_unlock;
	}

	scalls = (struct lsm_static_call *)scalls_addr;
	for (i = 0; i < scalls_count; i++) {
		struct lsm_static_call *scall = &scalls[i];
		void **slot;
		void *current_origin;
		int j;

		entry = READ_ONCE(scall->hl);
		if (!entry)
			continue;

		slot = (void **)((char *)entry + hook->hook_offset);
		current_origin = READ_ONCE(*slot);

		for (j = 0; j < yz_lsm_hook_count; j++) {
			if (yz_lsm_hook_entries[j].hook->replacement ==
			    current_origin) {
				current_origin =
					yz_lsm_hook_entries[j].hook->original;
				break;
			}
		}

		if (current_origin == hook->replacement) {
			ret = -EALREADY;
			goto out_unlock;
		}

		if (current_origin != target)
			continue;

		if (!hook->offset) {
			selected_entry = entry;
			selected_scall = scall;
			selected_slot = slot;
			selected_origin = current_origin;
		} else {
			size_t hook_idx =
				(i / lsm_max_cnt + hook->offset) * lsm_max_cnt;

			if (hook_idx >= scalls_count) {
				pr_err("yukizygisk: lsm_hook offset exceeds table\n");
				ret = -EINVAL;
				goto out_unlock;
			}

			scall = &scalls[hook_idx];
			entry = READ_ONCE(scall->hl);
			if (entry) {
				slot = (void **)((char *)entry +
						 hook->hook_offset);
				current_origin = READ_ONCE(*slot);
			} else {
				slot = NULL;
				current_origin = NULL;
			}

			if (current_origin == hook->replacement) {
				ret = -EALREADY;
				goto out_unlock;
			}
			selected_entry = entry;
			selected_scall = scall;
			selected_slot = slot;
			selected_origin = current_origin;
		}
		break;
	}

	if (!selected_scall || !selected_slot) {
		pr_err("yukizygisk: lsm_hook target %s not found in head %s\n",
		       target_name, hook->head_name ?: "unknown");
		ret = -ENOENT;
		goto out_unlock;
	}

	ret = yz_lsm_hook_track(hook);
	if (ret)
		goto out_unlock;

	if (yz_lsm_hook_patch_slot(selected_slot, hook->replacement)) {
		pr_err("yukizygisk: lsm_hook failed to patch %s\n",
		       hook->head_name ?: "unknown");
		ret = -EFAULT;
		goto out_untrack;
	}

	if (yz_lsm_hook_update_scall(selected_scall, hook->replacement)) {
		if (yz_lsm_hook_patch_slot(selected_slot, selected_origin))
			pr_err("yukizygisk: lsm_hook rollback failed for %s\n",
			       hook->head_name ?: "unknown");
		ret = -EFAULT;
		goto out_untrack;
	}

	if (!selected_origin)
		static_branch_enable(selected_scall->active);

	hook->entry = selected_entry;
	hook->scall = selected_scall;
	hook->original = selected_origin;
	pr_info("yukizygisk: lsm_hook patched %s slot %px from %px to %px\n",
		hook->head_name ?: "unknown", selected_slot, selected_origin,
		hook->replacement);
#else
	heads_addr = yz_lookup_name("security_hook_heads");
	if (!heads_addr) {
		pr_err("yukizygisk: lsm_hook failed to resolve security_hook_heads\n");
		ret = -ENOENT;
		goto out_unlock;
	}

	{
		unsigned long heads_size = sizeof(struct security_hook_heads);
		struct hlist_head *head_end;

		head = (struct hlist_head *)heads_addr;
		head_end = (struct hlist_head *)(heads_addr + heads_size);
		head = (struct hlist_head *)(heads_addr + hook->head_offset);
		if (head < (struct hlist_head *)heads_addr || head >= head_end) {
			pr_err("yukizygisk: lsm_hook head %s offset out of range\n",
			       hook->head_name ?: "unknown");
			ret = -EINVAL;
			goto out_unlock;
		}

		hlist_for_each_entry(entry, head, list) {
			void **slot = (void **)((char *)entry +
						hook->hook_offset);
			void *current_origin = READ_ONCE(*slot);
			int j;

			for (j = 0; j < yz_lsm_hook_count; j++) {
				if (yz_lsm_hook_entries[j].hook->replacement ==
				    current_origin) {
					current_origin =
						yz_lsm_hook_entries[j]
							.hook->original;
					break;
				}
			}

			if (current_origin == hook->replacement) {
				ret = -EALREADY;
				goto out_unlock;
			}
			if (current_origin == target) {
				selected_entry = entry;
				selected_slot = slot;
				selected_origin = current_origin;
				break;
			}
		}

		if (selected_entry && hook->offset) {
			head += hook->offset;
			if (head < (struct hlist_head *)heads_addr ||
			    head >= head_end) {
				ret = -EINVAL;
				goto out_unlock;
			}

			if (!head->first) {
				ret = -ENOENT;
				goto out_unlock;
			}

			selected_entry = hlist_entry(head->first,
						    struct security_hook_list,
						    list);
			selected_slot = (void **)((char *)selected_entry +
						  hook->hook_offset);
			selected_origin = *selected_slot;
		}
	}

	if (!selected_entry) {
		pr_err("yukizygisk: lsm_hook target %s not found in head %s\n",
		       target_name, hook->head_name ?: "unknown");
		ret = -ENOENT;
		goto out_unlock;
	}

	ret = yz_lsm_hook_track(hook);
	if (ret)
		goto out_unlock;

	ret = yz_lsm_hook_patch_slot(selected_slot, hook->replacement);
	if (ret) {
		pr_err("yukizygisk: lsm_hook failed to patch %s\n",
		       hook->head_name ?: "unknown");
		ret = -EFAULT;
		goto out_untrack;
	}

	hook->entry = selected_entry;
	hook->original = selected_origin;
	pr_info("yukizygisk: lsm_hook patched %s slot %px from %px to %px\n",
		hook->head_name ?: "unknown", selected_slot, selected_origin,
		hook->replacement);
#endif
	goto out_unlock;

out_untrack:
	yz_lsm_hook_untrack(hook);

out_unlock:
	mutex_unlock(&yz_lsm_hook_lock);
	return ret;
}

static void yz_lsm_hook_remove(struct yz_host_lsm_hook *hook)
{
	void **slot;

	mutex_lock(&yz_lsm_hook_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	if (!hook->entry || !hook->scall) {
#else
	if (!hook->entry) {
#endif
		mutex_unlock(&yz_lsm_hook_lock);
		return;
	}

	slot = (void **)((char *)hook->entry + hook->hook_offset);
	if (yz_lsm_hook_patch_slot(slot, hook->original)) {
		pr_err("yukizygisk: lsm_hook failed to restore %s\n",
		       hook->head_name ?: "unknown");
		mutex_unlock(&yz_lsm_hook_lock);
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	if (yz_lsm_hook_update_scall(hook->scall, hook->original)) {
		if (yz_lsm_hook_patch_slot(slot, hook->replacement))
			pr_err("yukizygisk: lsm_hook reapply failed for %s\n",
			       hook->head_name ?: "unknown");
		mutex_unlock(&yz_lsm_hook_lock);
		return;
	}
#endif

	synchronize_rcu();
	pr_info("yukizygisk: lsm_hook restored %s slot %px to %px\n",
		hook->head_name ?: "unknown", slot, hook->original);
	yz_lsm_hook_untrack(hook);
	hook->entry = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	hook->scall = NULL;
#endif
	mutex_unlock(&yz_lsm_hook_lock);
}

void yz_host_lsm_init(void)
{
	pr_info("yukizygisk: lsm_hook init, tracked hooks=%d\n",
		READ_ONCE(yz_lsm_hook_count));
}

void yz_host_lsm_exit(void)
{
	struct yz_host_lsm_hook *hooks[ARRAY_SIZE(yz_lsm_hook_entries)];
	int count;
	int i;

	mutex_lock(&yz_lsm_hook_lock);
	count = yz_lsm_hook_count;
	for (i = 0; i < count; i++)
		hooks[i] = yz_lsm_hook_entries[i].hook;
	mutex_unlock(&yz_lsm_hook_lock);

	for (i = count - 1; i >= 0; i--)
		yz_lsm_hook_remove(hooks[i]);
}

int yz_host_register_lsm_hook(struct yz_host_lsm_hook *hook)
{
	return yz_lsm_hook_apply(hook);
}

void yz_host_unregister_lsm_hook(struct yz_host_lsm_hook *hook)
{
	yz_lsm_hook_remove(hook);
}
