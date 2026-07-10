/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - kernel <-> zygiskd netlink channel.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef __YZ_H_ZYGOTE_NL
#define __YZ_H_ZYGOTE_NL

#include <linux/types.h>

void yz_zygote_nl_init(void);
void yz_zygote_nl_exit(void);
void yz_zygote_nl_emit_specialize(u32 pid, u32 appid);
void yz_zygote_nl_emit_reload(void);
void yz_zygote_nl_emit_safemode(u32 pid, u32 crashes);
void yz_zygote_nl_emit_policy_refresh(u32 owner, u32 uid);

#endif // #ifndef __YZ_H_ZYGOTE_NL
