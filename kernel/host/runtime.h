/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Host runtime symbol resolver.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _YUKIZYGISK_HOST_RUNTIME_H
#define _YUKIZYGISK_HOST_RUNTIME_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/task_work.h>
#include <linux/types.h>

struct path;

#if defined(__clang__)
#if __clang_major__ >= 17
#define YZ_NOCFI __attribute__((no_sanitize("cfi", "kcfi")))
#else
#define YZ_NOCFI __attribute__((no_sanitize("cfi")))
#endif
#else
#define YZ_NOCFI
#endif

extern unsigned long (*yz_kallsyms_lookup_name)(const char *name);
extern struct file *(*yz_filp_open)(const char *filename, int flags,
				    umode_t mode);
extern int (*yz_filp_close)(struct file *file, fl_owner_t id);

struct cred *yz_prepare_creds(void);
void yz_abort_creds(struct cred *cred);
const struct cred *yz_override_creds(const struct cred *cred);
void yz_revert_creds(const struct cred *cred);
struct file *yz_file_open(const char *filename, int flags, umode_t mode);
int yz_file_close(struct file *file, fl_owner_t id);
ssize_t yz_kernel_read(struct file *file, void *buf, size_t count,
		       loff_t *pos);
ssize_t yz_kernel_write(struct file *file, const void *buf, size_t count,
			loff_t *pos);
int yz_kern_path(const char *name, unsigned int flags, struct path *path);
int yz_close_fd(unsigned int fd);

int yz_host_runtime_init(void);
void yz_host_runtime_exit(void);

bool yz_valid_kernel_addr(unsigned long addr);
unsigned long yz_lookup_name(const char *name);
unsigned long yz_lookup_name_quiet(const char *name);
unsigned long yz_lookup_callable(const char *name);
unsigned long yz_lookup_callable_quiet(const char *name);
bool yz_lookup_size_offset(unsigned long addr, unsigned long *symbolsize,
			   unsigned long *offset);
bool yz_kernel_read_nofault(void *dst, unsigned long src, size_t size);
int yz_task_work_add(struct task_struct *task, struct callback_head *twork,
		     enum task_work_notify_mode mode);

#endif /* _YUKIZYGISK_HOST_RUNTIME_H */
