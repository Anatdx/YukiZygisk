/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - One-shot prctl bootstrap for the anonymous control fd.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>

#include "core/bootstrap.h"
#include "core/control.h"
#include "core/lifecycle.h"
#include "host/runtime.h"
#include "uapi/yukizygisk.h"

enum yz_prctl_abi {
	YZ_PRCTL_ABI_ARM64_WRAPPER,
	YZ_PRCTL_ABI_DIRECT,
};

struct yz_bootstrap_args {
	unsigned long option;
	unsigned long magic1;
	unsigned long cookie_lo;
	unsigned long cookie_hi;
	unsigned long out_fd;
};

struct yz_bootstrap_state {
	struct callback_head twork;
	void __user *out_fd;
	pid_t pid;
};

static unsigned long long yz_bootstrap_cookie_lo;
static unsigned long long yz_bootstrap_cookie_hi;
module_param_named(bootstrap_cookie_lo, yz_bootstrap_cookie_lo, ullong, 0400);
MODULE_PARM_DESC(bootstrap_cookie_lo, "Low 64 bits of the one-shot bootstrap cookie");
module_param_named(bootstrap_cookie_hi, yz_bootstrap_cookie_hi, ullong, 0400);
MODULE_PARM_DESC(bootstrap_cookie_hi, "High 64 bits of the one-shot bootstrap cookie");
static unsigned int yz_bootstrap_guard_delay_sec = 5;
module_param_named(bootstrap_guard_delay_sec, yz_bootstrap_guard_delay_sec,
		   uint, 0644);
MODULE_PARM_DESC(bootstrap_guard_delay_sec, "Seconds between bootstrap guard checks");
static unsigned int yz_bootstrap_guard_max_sec = 30;
module_param_named(bootstrap_guard_max_sec, yz_bootstrap_guard_max_sec, uint,
		   0644);
MODULE_PARM_DESC(bootstrap_guard_max_sec, "Maximum seconds before bootstrap guard fails closed");

static struct yz_bootstrap_state yz_bootstrap_state;
static atomic_t yz_bootstrap_claimed = ATOMIC_INIT(0);
static struct kprobe yz_bootstrap_kp;
static enum yz_prctl_abi yz_bootstrap_abi;
static bool yz_bootstrap_registered;
static unsigned long yz_bootstrap_guard_deadline;
static DEFINE_MUTEX(yz_bootstrap_kprobe_lock);

static void yz_bootstrap_unregister_work_fn(struct work_struct *work);
static DECLARE_WORK(yz_bootstrap_unregister_work,
		    yz_bootstrap_unregister_work_fn);
static void yz_bootstrap_guard_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(yz_bootstrap_guard_work,
			    yz_bootstrap_guard_work_fn);

static void yz_bootstrap_close_fd(unsigned int fd)
{
	yz_close_fd(fd);
}

static void yz_bootstrap_clear_cookie(void)
{
	WRITE_ONCE(yz_bootstrap_cookie_lo, 0);
	WRITE_ONCE(yz_bootstrap_cookie_hi, 0);
}

static void yz_bootstrap_unregister_kprobe(void)
{
	mutex_lock(&yz_bootstrap_kprobe_lock);
	if (yz_bootstrap_registered) {
		unregister_kprobe(&yz_bootstrap_kp);
		yz_bootstrap_registered = false;
		pr_info("yukizygisk: prctl bootstrap hook removed\n");
	}
	mutex_unlock(&yz_bootstrap_kprobe_lock);
}

static void yz_bootstrap_unregister_work_fn(struct work_struct *work)
{
	(void)work;
	yz_bootstrap_unregister_kprobe();
}

static bool yz_bootstrap_path_exists(const char *path)
{
	struct path p;
	int ret;

	ret = yz_kern_path(path, 0, &p);
	if (ret)
		return false;
	path_put(&p);
	return true;
}

static bool yz_bootstrap_services_or_later(void)
{
	return yz_bootstrap_path_exists("/dev/socket/zygote") ||
	       yz_bootstrap_path_exists("/dev/socket/zygote64");
}

static void yz_bootstrap_guard_work_fn(struct work_struct *work)
{
	unsigned long delay;

	(void)work;

	if (atomic_read(&yz_bootstrap_claimed))
		return;
	if (!yz_bootstrap_services_or_later() &&
	    time_before(jiffies, yz_bootstrap_guard_deadline)) {
		delay = msecs_to_jiffies(max_t(unsigned int, 1,
					       yz_bootstrap_guard_delay_sec) *
					 1000);
		schedule_delayed_work(&yz_bootstrap_guard_work, delay);
		return;
	}

	if (atomic_cmpxchg(&yz_bootstrap_claimed, 0, 1))
		return;

	yz_bootstrap_clear_cookie();
	yz_bootstrap_unregister_kprobe();
	pr_warn("yukizygisk: zygiskd did not claim bootstrap before services; disabling hooks\n");
	yukizygisk_bootstrap_fail_closed();
	pr_warn("yukizygisk: bootstrap failed closed; waiting for external module unload\n");
}

static void yz_bootstrap_task_work(struct callback_head *head)
{
	struct yz_bootstrap_state *state =
		container_of(head, struct yz_bootstrap_state, twork);
	int fd;

	fd = yukizygisk_control_install_fd();
	if (fd >= 0 && state->out_fd &&
	    copy_to_user(state->out_fd, &fd, sizeof(fd))) {
		yz_bootstrap_close_fd((unsigned int)fd);
		fd = -EFAULT;
	}

	if (fd < 0)
		pr_warn("yukizygisk: bootstrap fd install failed pid=%d ret=%d\n",
			state->pid, fd);
	else
		pr_info("yukizygisk: bootstrap fd delivered pid=%d fd=%d\n",
			state->pid, fd);

	module_put(THIS_MODULE);
}

static bool yz_bootstrap_read_prctl_args(struct pt_regs *regs,
					 struct yz_bootstrap_args *args)
{
#if defined(CONFIG_ARM64)
	struct pt_regs *sysregs;

	if (!regs || !args)
		return false;

	if (yz_bootstrap_abi == YZ_PRCTL_ABI_ARM64_WRAPPER) {
		struct pt_regs syscall_regs;

		sysregs = (struct pt_regs *)regs->regs[0];
		if (sysregs && !copy_from_kernel_nofault(
				       &syscall_regs, sysregs,
				       sizeof(syscall_regs))) {
			args->option = syscall_regs.regs[0];
			args->magic1 = syscall_regs.regs[1];
			args->cookie_lo = syscall_regs.regs[2];
			args->cookie_hi = syscall_regs.regs[3];
			args->out_fd = syscall_regs.regs[4];
			return true;
		}
	}

	args->option = regs->regs[0];
	args->magic1 = regs->regs[1];
	args->cookie_lo = regs->regs[2];
	args->cookie_hi = regs->regs[3];
	args->out_fd = regs->regs[4];
	return true;
#else
	(void)regs;
	(void)args;
	return false;
#endif
}

static int yz_bootstrap_prctl_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct yz_bootstrap_args args;
	unsigned long long cookie_lo;
	unsigned long long cookie_hi;
	int ret;

	(void)kp;

	if (!yz_bootstrap_read_prctl_args(regs, &args))
		return 0;
	if ((u32)args.option != YZ_PRCTL_BOOTSTRAP_OPTION ||
	    args.magic1 != YZ_PRCTL_BOOTSTRAP_MAGIC_YUKIHOOK)
		return 0;

	cookie_lo = READ_ONCE(yz_bootstrap_cookie_lo);
	cookie_hi = READ_ONCE(yz_bootstrap_cookie_hi);
	if ((!cookie_lo && !cookie_hi) || args.cookie_lo != cookie_lo ||
	    args.cookie_hi != cookie_hi || !args.out_fd)
		return 0;
	if (!uid_eq(current_euid(), GLOBAL_ROOT_UID) || !current->mm)
		return 0;
	if (atomic_cmpxchg(&yz_bootstrap_claimed, 0, 1))
		return 0;
	if (!try_module_get(THIS_MODULE)) {
		atomic_set(&yz_bootstrap_claimed, 0);
		return 0;
	}

	yz_bootstrap_state.out_fd = (void __user *)args.out_fd;
	yz_bootstrap_state.pid = current->pid;
	init_task_work(&yz_bootstrap_state.twork, yz_bootstrap_task_work);
	ret = yz_task_work_add(current, &yz_bootstrap_state.twork, TWA_RESUME);
	if (ret) {
		yz_bootstrap_state.out_fd = NULL;
		atomic_set(&yz_bootstrap_claimed, 0);
		module_put(THIS_MODULE);
		return 0;
	}

	yz_bootstrap_clear_cookie();
	cancel_delayed_work(&yz_bootstrap_guard_work);
	schedule_work(&yz_bootstrap_unregister_work);
	return 0;
}

struct yz_prctl_candidate {
	const char *symbol;
	enum yz_prctl_abi abi;
};

static int yz_bootstrap_register_prctl_hook(void)
{
#if defined(CONFIG_ARM64)
	static const struct yz_prctl_candidate candidates[] = {
		{ "__se_sys_prctl", YZ_PRCTL_ABI_DIRECT },
		{ "__arm64_sys_prctl", YZ_PRCTL_ABI_ARM64_WRAPPER },
	};
	int ret = -ENOENT;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(candidates); i++) {
		memset(&yz_bootstrap_kp, 0, sizeof(yz_bootstrap_kp));
		yz_bootstrap_kp.symbol_name = candidates[i].symbol;
		yz_bootstrap_kp.pre_handler = yz_bootstrap_prctl_pre;
		yz_bootstrap_abi = candidates[i].abi;
		ret = register_kprobe(&yz_bootstrap_kp);
		if (!ret) {
			yz_bootstrap_registered = true;
			pr_info("yukizygisk: prctl bootstrap hook armed on %s\n",
				candidates[i].symbol);
			return 0;
		}
	}

	return ret;
#else
	return -EOPNOTSUPP;
#endif
}

int yukizygisk_bootstrap_init(void)
{
	int ret;

	if (!READ_ONCE(yz_bootstrap_cookie_lo) &&
	    !READ_ONCE(yz_bootstrap_cookie_hi)) {
		pr_warn("yukizygisk: bootstrap cookie missing; control bootstrap disabled\n");
		return 0;
	}

	mutex_lock(&yz_bootstrap_kprobe_lock);
	ret = yz_bootstrap_register_prctl_hook();
	mutex_unlock(&yz_bootstrap_kprobe_lock);
	if (ret)
		pr_err("yukizygisk: prctl bootstrap hook failed: %d\n", ret);
	else {
		unsigned long delay;

		delay = msecs_to_jiffies(max_t(unsigned int, 1,
					       yz_bootstrap_guard_delay_sec) *
					 1000);
		yz_bootstrap_guard_deadline =
			jiffies + msecs_to_jiffies(max_t(unsigned int, 1,
							 yz_bootstrap_guard_max_sec) *
						   1000);
		schedule_delayed_work(&yz_bootstrap_guard_work, delay);
	}
	return ret;
}

void yukizygisk_bootstrap_exit(void)
{
	cancel_delayed_work_sync(&yz_bootstrap_guard_work);
	cancel_work_sync(&yz_bootstrap_unregister_work);
	yz_bootstrap_unregister_kprobe();
	yz_bootstrap_clear_cookie();
}
