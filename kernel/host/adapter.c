/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Root-implementation agnostic host adapter.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "host/host.h"
#include "host/policy.h"
#include "host/root_impl.h"
#include "host/runtime.h"

static struct cred *yz_priv_cred;

int yz_host_init(void)
{
	int ret;

	pr_info("yukizygisk: host step runtime\n");
	ret = yz_host_runtime_init();
	if (ret) {
		pr_err("yukizygisk: host runtime init failed: %d\n", ret);
		return ret;
	}
	pr_info("yukizygisk: host step runtime done\n");

	pr_info("yukizygisk: host step policy\n");
	ret = yz_host_policy_init();
	if (ret) {
		pr_err("yukizygisk: host policy init failed: %d\n", ret);
		yz_host_runtime_exit();
		return ret;
	}
	pr_info("yukizygisk: host step policy done\n");

	pr_info("yukizygisk: host step privileged creds\n");
	yz_priv_cred = yz_prepare_creds();
	if (!yz_priv_cred) {
		pr_err("yukizygisk: prepare privileged creds failed\n");
		yz_host_policy_exit();
		yz_host_runtime_exit();
		return -ENOMEM;
	}
	pr_info("yukizygisk: host step privileged creds done\n");

	pr_info("yukizygisk: host root=%s mask=0x%x policy=%s\n",
		yz_host_root_name(), yz_root_mask,
		yz_host_root_allows_policy() ? "available" : "unavailable");
	return 0;
}

void yz_host_exit(void)
{
	if (yz_priv_cred) {
		yz_abort_creds(yz_priv_cred);
		yz_priv_cred = NULL;
	}
	yz_host_policy_exit();
	yz_host_runtime_exit();
}

const struct cred *yz_host_override_creds(void)
{
	return yz_priv_cred ? yz_override_creds(yz_priv_cred) : NULL;
}

void yz_host_revert_creds(const struct cred *old_cred)
{
	if (old_cred)
		yz_revert_creds(old_cred);
}

bool yz_host_is_zygote(const struct cred *cred)
{
	return yz_host_policy_cred_has_type(cred, "zygote");
}

void yz_host_get_root_status(struct yz_host_root_status *status)
{
	if (!status)
		return;
	status->owner = (u32)READ_ONCE(yz_root_owner);
	status->mask = (u32)READ_ONCE(yz_root_mask);
	status->flags = yz_host_root_flags();
}

int yz_host_prepare_runtime_policy(void)
{
	return yz_host_policy_prepare_runtime_current();
}

int yz_host_file_load_policy_allow_current(
	struct file *file, struct yz_file_load_policy *state)
{
	return yz_host_policy_allow_file_current(file, state);
}

int yz_host_file_load_policy_allow_cred(
	struct file *file, const struct cred *cred,
	struct yz_file_load_policy *state)
{
	return yz_host_policy_allow_file_cred(file, cred, state);
}

int yz_host_file_load_policy_allow_execmem_current(
	struct yz_file_load_policy *state)
{
	return yz_host_policy_allow_execmem_current(state);
}

int yz_host_file_load_policy_restore(const struct yz_file_load_policy *state)
{
	return yz_host_policy_restore(state);
}
