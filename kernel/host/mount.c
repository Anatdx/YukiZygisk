/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - Host mount namespace cleanup adapter.
 *
 * Derived from YukiSU kernel_umount helpers.
 *
 * License: GPL-2.0-only
 *
 * Author: Anatdx
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <uapi/linux/mount.h>

#include "host/host.h"
#include "host/mount.h"
#include "host/runtime.h"

#define YZ_PER_USER_RANGE 100000
#define YZ_UMOUNT_MAX_TARGETS 512
#define YZ_MOUNTINFO_BUF (256 * 1024)

typedef int (*yz_path_umount_fn)(struct path *path, int flags);

static yz_path_umount_fn yz_path_umount_ptr;

static bool yz_mount_is_appuid(uid_t uid)
{
	return uid % YZ_PER_USER_RANGE >= 10000;
}

static int yz_mount_resolve_path_umount(void)
{
	unsigned long addr;

	if (yz_path_umount_ptr)
		return 0;

	addr = yz_lookup_callable_quiet("path_umount");
	if (!addr) {
		pr_warn("yukizygisk: path_umount unavailable; mount cleanup disabled\n");
		return -ENOENT;
	}
	yz_path_umount_ptr = (void *)addr;
	return 0;
}

static int yz_try_umount(const char *mnt, int flags)
{
	struct path path;
	int ret;

	if (!mnt || !mnt[0])
		return -EINVAL;

	ret = yz_mount_resolve_path_umount();
	if (ret)
		return ret;

	ret = yz_kern_path(mnt, 0, &path);
	if (ret)
		return ret;

	if (path.dentry != path.mnt->mnt_root) {
		path_put(&path);
		return -EINVAL;
	}

	/* path_umount() consumes the successful kern_path() reference itself. */
	ret = yz_path_umount_ptr(&path, flags);
	if (ret)
		pr_info("yukizygisk: umount %s failed: %d\n", mnt, ret);
	return ret;
}

static bool yz_mount_is_module(const char *root, const char *target,
			       const char *source, const char *super)
{
	/* Standalone YukiZygisk owns this cleanup path. Match KSU-style
	 * mount-source tags plus the wider ZN/YZ-style roots that point back
	 * into /data/adb, then detach them here without depending on KSU's
	 * kernel_umount feature switch. */
	if (root && !strncmp(root, "/adb/modules", 12))
		return true;
	if (target && !strncmp(target, "/data/adb/", 10))
		return true;
	if (source && (!strcmp(source, "KSU") || !strcmp(source, "YukiSU") ||
		       !strcmp(source, "magisk") ||
		       !strcmp(source, "APatch") ||
		       !strcmp(source, "YukiZygisk")))
		return true;
	if (super && (strstr(super, "/adb/modules") ||
		      strstr(super, "/data/adb/")))
		return true;
	return false;
}

static bool yz_parse_mountinfo(char *line, char **root, char **target,
			       char **source, char **super)
{
	char *tok;
	char *f3 = NULL;
	char *f4 = NULL;
	int n = 0;

	while ((tok = strsep(&line, " ")) != NULL) {
		if (n == 3)
			f3 = tok;
		else if (n == 4)
			f4 = tok;
		else if (n >= 6 && !strcmp(tok, "-")) {
			char *fstype = strsep(&line, " ");
			char *src = strsep(&line, " ");

			if (!fstype || !src || !f3 || !f4)
				return false;
			*root = f3;
			*target = f4;
			*source = src;
			*super = strsep(&line, " ");
			return true;
		}
		n++;
	}
	return false;
}

static int yz_umount_scan_mountinfo(void)
{
	struct file *file;
	char *buf;
	char **targets;
	char *p;
	char *line;
	loff_t pos = 0;
	size_t total = 0;
	int count = 0;
	int i;
	int ret = 0;

	buf = vmalloc(YZ_MOUNTINFO_BUF);
	if (!buf)
		return -ENOMEM;

	targets = kmalloc_array(YZ_UMOUNT_MAX_TARGETS, sizeof(*targets),
				GFP_KERNEL);
	if (!targets) {
		vfree(buf);
		return -ENOMEM;
	}

	file = yz_file_open("/proc/self/mountinfo", O_RDONLY, 0);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto out_free;
	}

	while (total < YZ_MOUNTINFO_BUF - 1) {
		ssize_t n = yz_kernel_read(file, buf + total,
					   YZ_MOUNTINFO_BUF - 1 - total,
					   &pos);

		if (n < 0) {
			ret = n;
			break;
		}
		if (n == 0)
			break;
		total += n;
	}
	yz_file_close(file, NULL);
	if (ret)
		goto out_free;

	buf[total] = '\0';
	p = buf;
	while ((line = strsep(&p, "\n")) != NULL) {
		char *root;
		char *target;
		char *source;
		char *super;

		if (!line[0])
			continue;
		if (!yz_parse_mountinfo(line, &root, &target, &source, &super))
			continue;
		if (yz_mount_is_module(root, target, source, super) &&
		    count < YZ_UMOUNT_MAX_TARGETS)
			targets[count++] = target;
	}

	for (i = count - 1; i >= 0; i--) {
		pr_info("yukizygisk: detaching mount %s\n", targets[i]);
		yz_try_umount(targets[i], MNT_DETACH);
	}

out_free:
	kfree(targets);
	vfree(buf);
	return ret;
}

struct yz_umount_tw {
	struct callback_head cb;
};

static void yz_umount_tw_func(struct callback_head *cb)
{
	struct yz_umount_tw *tw = container_of(cb, struct yz_umount_tw, cb);
	const struct cred *old_cred;
	int ret;

	if (current->flags & PF_EXITING)
		goto out;

	/* Runs as task_work in the target app, so /proc/self/mountinfo and
	 * kern_path() resolve inside that app's mount namespace. */
	old_cred = yz_host_override_creds();
	ret = yz_umount_scan_mountinfo();
	yz_host_revert_creds(old_cred);
	if (ret)
		pr_info("yukizygisk: mount cleanup pid=%d failed: %d\n",
			current->pid, ret);

out:
	kfree(tw);
}

int yz_host_umount_pid(pid_t pid)
{
	struct task_struct *task;
	struct yz_umount_tw *tw;
	uid_t uid;
	int ret;

	if (pid <= 0)
		return -EINVAL;

	rcu_read_lock();
	task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return -ESRCH;

	uid = task_uid(task).val;
	if (!yz_mount_is_appuid(uid)) {
		pr_info("yukizygisk: umount_pid reject non-app pid=%d uid=%u\n",
			pid, uid);
		put_task_struct(task);
		return -EPERM;
	}

	tw = kzalloc(sizeof(*tw), GFP_KERNEL);
	if (!tw) {
		put_task_struct(task);
		return -ENOMEM;
	}

	init_task_work(&tw->cb, yz_umount_tw_func);
	ret = yz_task_work_add(task, &tw->cb, TWA_RESUME);
	if (ret) {
		kfree(tw);
		put_task_struct(task);
		return -ESRCH;
	}

	put_task_struct(task);
	pr_info("yukizygisk: umount_pid scheduled pid=%d uid=%u\n", pid, uid);
	return 0;
}
