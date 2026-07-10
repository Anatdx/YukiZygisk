/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Host runtime symbol resolver.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/err.h>
#include <linux/file.h>
#include <linux/kprobes.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/task_work.h>
#include <linux/string.h>
#include <linux/version.h>

#include "host/root_impl.h"
#include "host/runtime.h"

static bool yz_skip_kallsyms;
module_param_named(skip_kallsyms, yz_skip_kallsyms, bool, 0600);
MODULE_PARM_DESC(skip_kallsyms,
		 "Skip kallsyms_lookup_name bootstrap and use per-symbol kprobe resolution.");

unsigned long (*yz_kallsyms_lookup_name)(const char *name);
struct file *(*yz_filp_open)(const char *filename, int flags, umode_t mode);
int (*yz_filp_close)(struct file *file, fl_owner_t id);

static struct cred *(*yz_prepare_creds_fn)(void);
static void (*yz_abort_creds_fn)(struct cred *cred);
static const struct cred *(*yz_override_creds_fn)(const struct cred *cred);
static void (*yz_revert_creds_fn)(const struct cred *cred);
static ssize_t (*yz_kernel_read_fn)(struct file *file, void *buf,
				    size_t count, loff_t *pos);
static ssize_t (*yz_kernel_write_fn)(struct file *file, const void *buf,
				     size_t count, loff_t *pos);
static int (*yz_kern_path_fn)(const char *name, unsigned int flags,
			      struct path *path);
static int (*yz_close_fd_fn)(unsigned int fd);
static int (*yz_task_work_add_fn)(struct task_struct *task,
				  struct callback_head *twork,
				  enum task_work_notify_mode mode);
static long (*yz_copy_from_kernel_nofault_fn)(void *dst, const void *src,
					      size_t size);
static bool yz_copy_from_kernel_nofault_tried;
static bool (*yz_kallsyms_lookup_size_offset_fn)(unsigned long addr,
						 unsigned long *symbolsize,
						 unsigned long *offset);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define YZ_USE_KCFI 1
#else
#define YZ_USE_KCFI 0
#endif

bool yz_valid_kernel_addr(unsigned long addr)
{
	if (!addr)
		return false;
	if (IS_ERR_VALUE(addr))
		return false;
#if defined(CONFIG_64BIT)
	return (addr & (1UL << 63)) != 0;
#else
	return addr >= PAGE_OFFSET;
#endif
}

YZ_NOCFI unsigned long yz_lookup_name(const char *name)
{
	if (yz_kallsyms_lookup_name) {
		unsigned long addr = yz_kallsyms_lookup_name(name);

		if (addr && !IS_ERR_VALUE(addr))
			return addr;
	}

	{
		struct kprobe kp = { .symbol_name = name };
		unsigned long addr;
		int ret;

		ret = register_kprobe(&kp);
		if (ret < 0) {
			pr_alert("yukizygisk: kprobe %s failed: %d\n", name,
				 ret);
			return 0;
		}
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
		if (!addr || IS_ERR_VALUE(addr)) {
			pr_alert("yukizygisk: symbol %s invalid addr 0x%lx\n",
				 name, addr);
			return 0;
		}
		return addr;
	}
}

YZ_NOCFI unsigned long yz_lookup_name_quiet(const char *name)
{
	if (yz_kallsyms_lookup_name) {
		unsigned long addr = yz_kallsyms_lookup_name(name);

		if (addr && !IS_ERR_VALUE(addr))
			return addr;
	}

	{
		struct kprobe kp = { .symbol_name = name };
		unsigned long addr;
		int ret;

		ret = register_kprobe(&kp);
		if (ret < 0)
			return 0;
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
		if (!addr || IS_ERR_VALUE(addr))
			return 0;
		return addr;
	}
}

YZ_NOCFI unsigned long yz_lookup_callable(const char *name)
{
	unsigned long addr;

#if YZ_USE_KCFI
	addr = yz_lookup_name(name);
	if (addr)
		return addr;
#endif
	if (yz_kallsyms_lookup_name) {
		char jt[256];

		if (snprintf(jt, sizeof(jt), "%s.cfi_jt", name) <
		    (int)sizeof(jt)) {
			addr = yz_kallsyms_lookup_name(jt);
			if (addr && !IS_ERR_VALUE(addr))
				return addr;
			}
	}
#if YZ_USE_KCFI
	return 0;
#else
	return yz_lookup_name(name);
#endif
}

YZ_NOCFI unsigned long yz_lookup_callable_quiet(const char *name)
{
	unsigned long addr;

#if YZ_USE_KCFI
	addr = yz_lookup_name_quiet(name);
	if (addr)
		return addr;
#endif
	if (yz_kallsyms_lookup_name) {
		char jt[256];

		if (snprintf(jt, sizeof(jt), "%s.cfi_jt", name) <
		    (int)sizeof(jt)) {
			addr = yz_kallsyms_lookup_name(jt);
			if (addr && !IS_ERR_VALUE(addr))
				return addr;
			}
	}
#if YZ_USE_KCFI
	return 0;
#else
	return yz_lookup_name_quiet(name);
#endif
}

static void yz_resolve_kallsyms_lookup(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret;

	pr_info("yukizygisk: resolving kallsyms_lookup_name\n");
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_warn("yukizygisk: kprobe kallsyms_lookup_name failed: %d, using per-symbol kprobe\n",
			ret);
		return;
	}
	if (!yz_valid_kernel_addr((unsigned long)kp.addr)) {
		pr_warn("yukizygisk: invalid kallsyms_lookup_name addr 0x%lx\n",
			(unsigned long)kp.addr);
		unregister_kprobe(&kp);
		return;
	}
	yz_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	pr_info("yukizygisk: kallsyms_lookup_name resolved @ 0x%lx\n",
		(unsigned long)yz_kallsyms_lookup_name);
}

bool yz_kernel_read_nofault(void *dst, unsigned long src, size_t size)
{
	if (!yz_copy_from_kernel_nofault_tried) {
		unsigned long addr =
			yz_lookup_callable_quiet("copy_from_kernel_nofault");

		yz_copy_from_kernel_nofault_tried = true;
		if (addr && yz_valid_kernel_addr(addr))
			yz_copy_from_kernel_nofault_fn = (void *)addr;
	}

	return yz_copy_from_kernel_nofault_fn &&
	       yz_copy_from_kernel_nofault_fn(dst, (const void *)src, size) == 0;
}

bool yz_lookup_size_offset(unsigned long addr, unsigned long *symbolsize,
			   unsigned long *offset)
{
	if (!yz_kallsyms_lookup_size_offset_fn) {
		unsigned long sym =
			yz_lookup_callable_quiet("kallsyms_lookup_size_offset");

		if (sym && yz_valid_kernel_addr(sym))
			yz_kallsyms_lookup_size_offset_fn = (void *)sym;
	}

	return yz_kallsyms_lookup_size_offset_fn &&
	       yz_kallsyms_lookup_size_offset_fn(addr, symbolsize, offset);
}

YZ_NOCFI struct cred *yz_prepare_creds(void)
{
	return yz_prepare_creds_fn ? yz_prepare_creds_fn() : NULL;
}

YZ_NOCFI void yz_abort_creds(struct cred *cred)
{
	if (yz_abort_creds_fn)
		yz_abort_creds_fn(cred);
}

YZ_NOCFI const struct cred *yz_override_creds(const struct cred *cred)
{
	return yz_override_creds_fn ? yz_override_creds_fn(cred) : NULL;
}

YZ_NOCFI void yz_revert_creds(const struct cred *cred)
{
	if (yz_revert_creds_fn)
		yz_revert_creds_fn(cred);
}

YZ_NOCFI struct file *yz_file_open(const char *filename, int flags,
				   umode_t mode)
{
	return yz_filp_open ? yz_filp_open(filename, flags, mode) :
			      ERR_PTR(-ENOENT);
}

YZ_NOCFI int yz_file_close(struct file *file, fl_owner_t id)
{
	if (yz_filp_close)
		return yz_filp_close(file, id);
	fput(file);
	return 0;
}

YZ_NOCFI ssize_t yz_kernel_read(struct file *file, void *buf, size_t count,
				loff_t *pos)
{
	return yz_kernel_read_fn ? yz_kernel_read_fn(file, buf, count, pos) :
				   -ENOENT;
}

YZ_NOCFI ssize_t yz_kernel_write(struct file *file, const void *buf,
				 size_t count, loff_t *pos)
{
	return yz_kernel_write_fn ? yz_kernel_write_fn(file, buf, count, pos) :
				    -ENOENT;
}

YZ_NOCFI int yz_kern_path(const char *name, unsigned int flags,
			  struct path *path)
{
	return yz_kern_path_fn ? yz_kern_path_fn(name, flags, path) : -ENOENT;
}

YZ_NOCFI int yz_close_fd(unsigned int fd)
{
	return yz_close_fd_fn ? yz_close_fd_fn(fd) : -ENOENT;
}

YZ_NOCFI int yz_task_work_add(struct task_struct *task,
			      struct callback_head *twork,
			      enum task_work_notify_mode mode)
{
	if (!yz_task_work_add_fn)
		return -ENOENT;
	return yz_task_work_add_fn(task, twork, mode);
}

static int yz_resolve_runtime_symbols(void)
{
	yz_prepare_creds_fn =
		(void *)yz_lookup_callable_quiet("prepare_creds");
	yz_abort_creds_fn = (void *)yz_lookup_callable_quiet("abort_creds");
	yz_override_creds_fn =
		(void *)yz_lookup_callable_quiet("override_creds");
	yz_revert_creds_fn =
		(void *)yz_lookup_callable_quiet("revert_creds");
	yz_filp_open = (void *)yz_lookup_callable_quiet("filp_open");
	yz_filp_close = (void *)yz_lookup_callable_quiet("filp_close");
	yz_kernel_read_fn =
		(void *)yz_lookup_callable_quiet("kernel_read");
	yz_kernel_write_fn =
		(void *)yz_lookup_callable_quiet("kernel_write");
	yz_kern_path_fn = (void *)yz_lookup_callable_quiet("kern_path");
	yz_close_fd_fn = (void *)yz_lookup_callable_quiet("close_fd");
	yz_task_work_add_fn =
		(void *)yz_lookup_callable_quiet("task_work_add");

	if (!yz_prepare_creds_fn || !yz_abort_creds_fn ||
	    !yz_override_creds_fn || !yz_revert_creds_fn || !yz_filp_open ||
	    !yz_kernel_read_fn || !yz_kernel_write_fn || !yz_kern_path_fn ||
	    !yz_close_fd_fn || !yz_task_work_add_fn) {
		pr_err("yukizygisk: required runtime symbol missing: "
		       "prepare=%d abort=%d override=%d revert=%d open=%d "
		       "read=%d write=%d kern_path=%d close=%d task_work=%d\n",
		       !!yz_prepare_creds_fn, !!yz_abort_creds_fn,
		       !!yz_override_creds_fn, !!yz_revert_creds_fn,
		       !!yz_filp_open, !!yz_kernel_read_fn,
		       !!yz_kernel_write_fn, !!yz_kern_path_fn,
		       !!yz_close_fd_fn, !!yz_task_work_add_fn);
		return -ENOENT;
	}
	if (!yz_filp_close)
		pr_warn("yukizygisk: filp_close not found, falling back to fput\n");

	return 0;
}

int yz_host_runtime_init(void)
{
	int ret;

	if (!yz_skip_kallsyms)
		yz_resolve_kallsyms_lookup();
	else
		pr_info("yukizygisk: skipping kallsyms bootstrap\n");

	ret = yz_resolve_runtime_symbols();
	if (ret) {
		yz_host_runtime_exit();
		return ret;
	}

	ret = yz_host_root_detect();
	if (ret) {
		yz_host_runtime_exit();
		return ret;
	}
	return 0;
}

void yz_host_runtime_exit(void)
{
	yz_host_root_exit();
	yz_prepare_creds_fn = NULL;
	yz_abort_creds_fn = NULL;
	yz_override_creds_fn = NULL;
	yz_revert_creds_fn = NULL;
	yz_filp_open = NULL;
	yz_filp_close = NULL;
	yz_kernel_read_fn = NULL;
	yz_kernel_write_fn = NULL;
	yz_kern_path_fn = NULL;
	yz_close_fd_fn = NULL;
	yz_task_work_add_fn = NULL;
	yz_kallsyms_lookup_name = NULL;
	yz_kallsyms_lookup_size_offset_fn = NULL;
	yz_copy_from_kernel_nofault_fn = NULL;
	yz_copy_from_kernel_nofault_tried = false;
}
