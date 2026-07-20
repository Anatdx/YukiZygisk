/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - SELinux host policy adapter declarations.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _YUKIZYGISK_HOST_POLICY_H
#define _YUKIZYGISK_HOST_POLICY_H

#include <linux/cred.h>

#include "host/host.h"

struct file;

int yz_host_policy_init(void);
void yz_host_policy_exit(void);

bool yz_host_policy_cred_has_type(const struct cred *cred,
				  const char *type_name);
int yz_host_policy_prepare_runtime_current(void);
int yz_host_policy_allow_file_current(struct file *file,
				      struct yz_file_load_policy *state);
int yz_host_policy_allow_file_cred(struct file *file, const struct cred *cred,
				   struct yz_file_load_policy *state);
int yz_host_policy_allow_execmem_current(struct yz_file_load_policy *state);
int yz_host_policy_restore(const struct yz_file_load_policy *state);

#endif /* _YUKIZYGISK_HOST_POLICY_H */
