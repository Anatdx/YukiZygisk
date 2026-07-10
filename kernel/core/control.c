/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Anonymous ioctl control file.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/cred.h>
#include <linux/anon_inodes.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>

#include "core/control.h"
#include "feature/zygote_ctl.h"
#include "feature/zygote_nl.h"
#include "feature/zygote_probe.h"
#include "host/host.h"
#include "host/runtime.h"
#include "uapi/yukizygisk.h"

#define YZ_PER_USER_RANGE 100000

static bool yz_is_appuid(uid_t uid)
{
	return uid % YZ_PER_USER_RANGE >= 10000;
}

static int yz_ioctl_set_dlopen(void __user *arg)
{
	struct yz_dlopen_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	yz_zygote_probe_set_dlopen_off(cmd.dlopen_offset, cmd.dlsym_offset);
	return 0;
}

static int yz_ioctl_set_yukilinker(void __user *arg)
{
	struct yz_yukilinker_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	yz_zygote_probe_set_yukilinker(cmd.enabled != 0);
	return 0;
}

static int yz_ioctl_set_native_targets(void __user *arg)
{
	struct yz_native_targets_cmd *cmd;
	int ret;

	cmd = memdup_user(arg, sizeof(*cmd));
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);
	ret = yz_zygote_probe_set_native_targets(cmd);
	kfree(cmd);
	return ret;
}

static int yz_ioctl_restore_native_load_policy(void __user *arg)
{
	struct yz_native_load_policy_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	return yz_zygote_probe_restore_native_policy((pid_t)cmd.pid);
}

static int yz_ioctl_get_safemode(void __user *arg)
{
	struct yz_safemode_status_cmd cmd;
	int ret;

	ret = yz_zygote_probe_get_safemode(&cmd);
	if (ret)
		return ret;
	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static int yz_ioctl_get_root_status(void __user *arg)
{
	struct yz_host_root_status status = { 0 };
	struct yz_root_status_cmd cmd = { 0 };

	yz_host_get_root_status(&status);
	cmd.owner = status.owner;
	cmd.mask = status.mask;
	cmd.flags = status.flags;

	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static int yz_ioctl_uid_should_umount(void __user *arg)
{
	struct yz_uid_policy_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	cmd.should_umount = yz_host_uid_should_umount((uid_t)cmd.uid) ? 1 : 0;
	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static int yz_ioctl_umount_pid(void __user *arg)
{
	struct yz_umount_pid_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	return yz_host_umount_pid((pid_t)cmd.pid);
}

struct yz_unmap_tw {
	struct callback_head cb;
	unsigned long addr[YZ_MAX_UNMAP_SEGS];
	unsigned long size[YZ_MAX_UNMAP_SEGS];
	unsigned int n;
	unsigned int retry;
};

static void yz_unmap_tw_func(struct callback_head *cb)
{
	struct yz_unmap_tw *tw = container_of(cb, struct yz_unmap_tw, cb);
	struct pt_regs *regs = task_pt_regs(current);
	unsigned long pc = regs ? instruction_pointer(regs) : 0;
	unsigned int i;

	for (i = 0; i < tw->n; i++) {
		if (pc >= tw->addr[i] && pc < tw->addr[i] + tw->size[i]) {
			if (++tw->retry < 16) {
				init_task_work(&tw->cb, yz_unmap_tw_func);
				if (!yz_task_work_add(current, &tw->cb,
						      TWA_RESUME))
					return;
			}
			pr_warn("yukizygisk: yz_unmap pc=0x%lx still in core "
				"after %u tries, skip pid=%d\n",
				pc, tw->retry, current->pid);
			kfree(tw);
			return;
		}
	}

	for (i = 0; i < tw->n; i++) {
		pr_info("yukizygisk: yz_unmap [0x%lx +0x%lx] pid=%d\n",
			tw->addr[i], tw->size[i], current->pid);
		vm_munmap(tw->addr[i], tw->size[i]);
	}
	kfree(tw);
}

static int yz_ioctl_unmap_pid(void __user *arg)
{
	struct yz_unmap_pid_cmd cmd;
	struct task_struct *task;
	struct yz_unmap_tw *tw;
	unsigned int i;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.n_segs == 0 || cmd.n_segs > YZ_MAX_UNMAP_SEGS)
		return -EINVAL;

	rcu_read_lock();
	task = get_pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return -ESRCH;

	if (!yz_is_appuid(task_uid(task).val)) {
		pr_info("yukizygisk: yz_unmap_pid reject non-app pid=%u uid=%u\n",
			cmd.pid, task_uid(task).val);
		put_task_struct(task);
		return -EPERM;
	}

	tw = kzalloc(sizeof(*tw), GFP_KERNEL);
	if (!tw) {
		put_task_struct(task);
		return -ENOMEM;
	}
	init_task_work(&tw->cb, yz_unmap_tw_func);
	tw->n = cmd.n_segs;
	for (i = 0; i < cmd.n_segs; i++) {
		tw->addr[i] = (unsigned long)cmd.addr[i];
		tw->size[i] = (unsigned long)cmd.size[i];
	}
	if (yz_task_work_add(task, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		put_task_struct(task);
		return -ESRCH;
	}
	put_task_struct(task);
	pr_info("yukizygisk: yz_unmap_pid scheduled %u seg(s) for pid=%u\n",
		cmd.n_segs, cmd.pid);
	return 0;
}

static int yz_ioctl_unmap_self(void __user *arg)
{
	struct yz_unmap_self_cmd cmd;
	struct yz_unmap_tw *tw;
	unsigned int i;

	if (!current->mm)
		return -EINVAL;
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.n_segs == 0 || cmd.n_segs > YZ_MAX_UNMAP_SEGS)
		return -EINVAL;

	for (i = 0; i < cmd.n_segs; i++) {
		unsigned long a = (unsigned long)cmd.addr[i];
		unsigned long s = (unsigned long)cmd.size[i];

		if (a == 0 || s == 0 || a >= TASK_SIZE || s > TASK_SIZE ||
		    a + s < a || a + s > TASK_SIZE) {
			pr_warn("yukizygisk: yz_unmap_self bad seg "
				"[0x%lx +0x%lx] pid=%d\n",
				a, s, current->pid);
			return -EINVAL;
		}
	}

	tw = kzalloc(sizeof(*tw), GFP_KERNEL);
	if (!tw)
		return -ENOMEM;
	init_task_work(&tw->cb, yz_unmap_tw_func);
	tw->n = cmd.n_segs;
	for (i = 0; i < cmd.n_segs; i++) {
		tw->addr[i] = (unsigned long)cmd.addr[i];
		tw->size[i] = (unsigned long)cmd.size[i];
	}
	if (yz_task_work_add(current, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		return -ESRCH;
	}
	pr_info("yukizygisk: yz_unmap_self armed %u seg(s) pid=%d\n",
		cmd.n_segs, current->pid);
	return 0;
}

static int yz_ioctl_patch_text(void __user *arg)
{
	struct yz_patch_text_cmd cmd;
	struct task_struct *task;
	int n;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.len == 0 || cmd.len > YZ_PATCH_TEXT_MAX)
		return -EINVAL;
	if (cmd.addr == 0 || cmd.addr >= TASK_SIZE ||
	    cmd.addr + cmd.len < cmd.addr || cmd.addr + cmd.len > TASK_SIZE)
		return -EINVAL;

	rcu_read_lock();
	task = get_pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return -ESRCH;

	n = access_process_vm(task, (unsigned long)cmd.addr, cmd.bytes, cmd.len,
			      FOLL_FORCE | FOLL_WRITE);
	put_task_struct(task);
	if (n != (int)cmd.len) {
		pr_warn("yukizygisk: yz_patch_text wrote %d/%u @0x%llx pid=%u\n",
			n, cmd.len, cmd.addr, cmd.pid);
		return -EFAULT;
	}
	pr_info("yukizygisk: yz_patch_text %u byte(s) @0x%llx pid=%u\n",
		cmd.len, cmd.addr, cmd.pid);
	return 0;
}

static long yukizygisk_ioctl(struct file *file, unsigned int request,
			     unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	(void)file;

	switch (request) {
	case YZ_IOCTL_HANDOFF:
		return yz_zygote_ctl_handoff(uarg);
	case YZ_IOCTL_SET_DLOPEN:
		return yz_ioctl_set_dlopen(uarg);
	case YZ_IOCTL_RELOAD:
		yz_zygote_nl_emit_reload();
		return 0;
	case YZ_IOCTL_SET_YUKILINKER:
		return yz_ioctl_set_yukilinker(uarg);
	case YZ_IOCTL_UMOUNT_PID:
		return yz_ioctl_umount_pid(uarg);
	case YZ_IOCTL_UNMAP_PID:
		return yz_ioctl_unmap_pid(uarg);
	case YZ_IOCTL_UNMAP_SELF:
		return yz_ioctl_unmap_self(uarg);
	case YZ_IOCTL_PATCH_TEXT:
		return yz_ioctl_patch_text(uarg);
	case YZ_IOCTL_SET_NATIVE_TARGETS:
		return yz_ioctl_set_native_targets(uarg);
	case YZ_IOCTL_RESTORE_NATIVE_LOAD_POLICY:
		return yz_ioctl_restore_native_load_policy(uarg);
	case YZ_IOCTL_GET_SAFEMODE:
		return yz_ioctl_get_safemode(uarg);
	case YZ_IOCTL_GET_ROOT_STATUS:
		return yz_ioctl_get_root_status(uarg);
	case YZ_IOCTL_UID_SHOULD_UMOUNT:
		return yz_ioctl_uid_should_umount(uarg);
	default:
		return -ENOTTY;
	}
}

static int yukizygisk_release(struct inode *inode, struct file *file)
{
	(void)inode;
	(void)file;
	module_put(THIS_MODULE);
	return 0;
}

static const struct file_operations yukizygisk_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = yukizygisk_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = yukizygisk_ioctl,
#endif
	.release = yukizygisk_release,
};

int yukizygisk_control_init(void)
{
	pr_info("yukizygisk: anonymous control fd backend ready\n");
	return 0;
}

void yukizygisk_control_exit(void)
{
}

int yukizygisk_control_install_fd(void)
{
	struct file *file;
	int fd;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	if (!try_module_get(THIS_MODULE)) {
		put_unused_fd(fd);
		return -ENODEV;
	}

	file = anon_inode_getfile("ctl", &yukizygisk_fops, NULL,
				  O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		module_put(THIS_MODULE);
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	fd_install(fd, file);
	pr_info("yukizygisk: anonymous control fd installed pid=%d fd=%d\n",
		current->pid, fd);
	return fd;
}
