/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - kernel <-> zygiskd netlink channel (lifecycle event push).
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "feature/zygote_nl.h"
#include "uapi/yukizygisk.h"
#include "klog.h" // IWYU pragma: keep

static struct sock *yz_sock;

static void yz_zygote_nl_emit_event(u32 type, u32 pid, u32 appid)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct yz_event *ev;

	if (!yz_sock)
		return;

	skb = nlmsg_new(sizeof(*ev), GFP_ATOMIC);
	if (!skb)
		return;

	nlh = nlmsg_put(skb, 0, 0, YZ_NL_MSG_EVENT, sizeof(*ev), 0);
	if (!nlh) {
		nlmsg_free(skb);
		return;
	}

	ev = nlmsg_data(nlh);
	ev->type = type;
	ev->pid = pid;
	ev->appid = appid;

	/* -ESRCH just means no zygiskd is listening yet -- harmless. */
	nlmsg_multicast(yz_sock, skb, 0, YZ_NL_GROUP_EVENTS, GFP_ATOMIC);
}

void yz_zygote_nl_emit_specialize(u32 pid, u32 appid)
{
	yz_zygote_nl_emit_event(YZ_EV_SPECIALIZE, pid, appid);
}

/* Ask every listening zygiskd to re-read yzconfig.json (manager changed it). */
void yz_zygote_nl_emit_reload(void)
{
	yz_zygote_nl_emit_event(YZ_EV_RELOAD, 0, 0);
}

void yz_zygote_nl_emit_safemode(u32 pid, u32 crashes)
{
	yz_zygote_nl_emit_event(YZ_EV_SAFEMODE, pid, crashes);
}

void yz_zygote_nl_emit_policy_refresh(u32 owner, u32 uid)
{
	yz_zygote_nl_emit_event(YZ_EV_POLICY_REFRESH, owner, uid);
}

void yz_zygote_nl_init(void)
{
	struct netlink_kernel_cfg cfg = {
	    .groups = YZ_NL_GROUP_EVENTS,
	};

	yz_sock = netlink_kernel_create(&init_net, YZ_NETLINK_PROTO, &cfg);
	if (!yz_sock)
		pr_err("zygote_nl: netlink_kernel_create failed\n");
	else
		pr_info("zygote_nl: channel up (proto=%d)\n", YZ_NETLINK_PROTO);
}

void yz_zygote_nl_exit(void)
{
	if (yz_sock) {
		netlink_kernel_release(yz_sock);
		yz_sock = NULL;
	}
}
