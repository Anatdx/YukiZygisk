/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Standalone LKM entry point.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/printk.h>

#include "core/bootstrap.h"
#include "core/control.h"
#include "core/lifecycle.h"
#include "feature/zygote_ctl.h"
#include "feature/zygote_nl.h"
#include "feature/zygote_orch.h"
#include "feature/zygote_probe.h"
#include "host/host.h"
#include "uapi/yukizygisk.h"

static unsigned int yz_init_stage_mask = 0x3f;
module_param_named(init_stage_mask, yz_init_stage_mask, uint, 0644);
MODULE_PARM_DESC(init_stage_mask, "Debug stage mask: 0x01 probe, 0x02 nl, 0x04 orch, 0x08 ctl, 0x10 control, 0x20 bootstrap");

#define YZ_INIT_STAGE_PROBE 0x01u
#define YZ_INIT_STAGE_NL 0x02u
#define YZ_INIT_STAGE_ORCH 0x04u
#define YZ_INIT_STAGE_CTL 0x08u
#define YZ_INIT_STAGE_CONTROL 0x10u
#define YZ_INIT_STAGE_BOOTSTRAP 0x20u

static bool yz_stage_probe_active;
static bool yz_stage_nl_active;
static bool yz_stage_orch_active;
static bool yz_stage_ctl_active;
static bool yz_stage_control_active;
static bool yz_stage_bootstrap_active;
static bool yz_stage_lsm_active;
static bool yz_stage_host_active;
static DEFINE_MUTEX(yz_lifecycle_lock);

static void yukizygisk_deactivate_locked(bool skip_bootstrap)
{
	if (yz_stage_bootstrap_active) {
		if (!skip_bootstrap) {
			yukizygisk_bootstrap_exit();
			yz_stage_bootstrap_active = false;
		}
	}
	if (yz_stage_control_active) {
		yukizygisk_control_exit();
		yz_stage_control_active = false;
	}
	if (yz_stage_ctl_active) {
		yz_zygote_ctl_exit();
		yz_stage_ctl_active = false;
	}
	if (yz_stage_orch_active) {
		yz_zygote_orch_exit();
		yz_stage_orch_active = false;
	}
	if (yz_stage_nl_active) {
		yz_zygote_nl_exit();
		yz_stage_nl_active = false;
	}
	if (yz_stage_probe_active) {
		yz_zygote_probe_exit();
		yz_stage_probe_active = false;
	}
	if (yz_stage_lsm_active) {
		yz_host_lsm_exit();
		yz_stage_lsm_active = false;
	}
	if (yz_stage_host_active) {
		yz_host_exit();
		yz_stage_host_active = false;
	}
}

void yukizygisk_bootstrap_fail_closed(void)
{
	mutex_lock(&yz_lifecycle_lock);
	yukizygisk_deactivate_locked(true);
	mutex_unlock(&yz_lifecycle_lock);
}

static int __init yukizygisk_init(void)
{
	int ret;

	pr_info("yukizygisk: standalone LKM initializing\n");

	pr_info("yukizygisk: init step host\n");
	ret = yz_host_init();
	if (ret) {
		pr_err("yukizygisk: init step host failed: %d\n", ret);
		return ret;
	}
	yz_stage_host_active = true;
	pr_info("yukizygisk: init step host done\n");

	pr_info("yukizygisk: init step lsm\n");
	yz_host_lsm_init();
	yz_stage_lsm_active = true;
	pr_info("yukizygisk: init step lsm done\n");

	if (yz_init_stage_mask & YZ_INIT_STAGE_PROBE) {
		pr_info("yukizygisk: init step zygote_probe\n");
		yz_zygote_probe_init();
		yz_stage_probe_active = true;
		pr_info("yukizygisk: init step zygote_probe done\n");
	} else {
		pr_info("yukizygisk: init step zygote_probe skipped\n");
	}
	if (yz_init_stage_mask & YZ_INIT_STAGE_NL) {
		pr_info("yukizygisk: init step zygote_nl\n");
		yz_zygote_nl_init();
		yz_stage_nl_active = true;
		if (yz_host_policy_uses_fallback()) {
			struct yz_host_root_status status = { 0 };

			yz_host_get_root_status(&status);
			yz_zygote_nl_emit_policy_refresh(
				status.owner, YZ_POLICY_REFRESH_ALL);
		}
		pr_info("yukizygisk: init step zygote_nl done\n");
	} else {
		pr_info("yukizygisk: init step zygote_nl skipped\n");
	}
	if (yz_init_stage_mask & YZ_INIT_STAGE_ORCH) {
		pr_info("yukizygisk: init step zygote_orch\n");
		yz_zygote_orch_init();
		yz_stage_orch_active = true;
		pr_info("yukizygisk: init step zygote_orch done\n");
	} else {
		pr_info("yukizygisk: init step zygote_orch skipped\n");
	}
	if (yz_init_stage_mask & YZ_INIT_STAGE_CTL) {
		pr_info("yukizygisk: init step zygote_ctl\n");
		yz_zygote_ctl_init();
		yz_stage_ctl_active = true;
		pr_info("yukizygisk: init step zygote_ctl done\n");
	} else {
		pr_info("yukizygisk: init step zygote_ctl skipped\n");
	}

	if (yz_init_stage_mask & YZ_INIT_STAGE_CONTROL) {
		pr_info("yukizygisk: init step control\n");
		ret = yukizygisk_control_init();
		if (ret) {
			pr_err("yukizygisk: control backend init failed: %d\n",
			       ret);
			goto err_control;
		}
		yz_stage_control_active = true;
		pr_info("yukizygisk: init step control done\n");
	} else {
		pr_info("yukizygisk: init step control skipped\n");
	}

	if (yz_init_stage_mask & YZ_INIT_STAGE_BOOTSTRAP) {
		pr_info("yukizygisk: init step bootstrap\n");
		ret = yukizygisk_bootstrap_init();
		if (ret) {
			pr_err("yukizygisk: bootstrap init failed: %d\n", ret);
			goto err_bootstrap;
		}
		yz_stage_bootstrap_active = true;
		pr_info("yukizygisk: init step bootstrap done\n");
	} else {
		pr_info("yukizygisk: init step bootstrap skipped\n");
	}

	pr_info("yukizygisk: standalone LKM initialized\n");
	return 0;

err_bootstrap:
err_control:
	mutex_lock(&yz_lifecycle_lock);
	yukizygisk_deactivate_locked(false);
	mutex_unlock(&yz_lifecycle_lock);
	return ret;
}

static void __exit yukizygisk_exit(void)
{
	pr_info("yukizygisk: standalone LKM exiting\n");

	mutex_lock(&yz_lifecycle_lock);
	yukizygisk_deactivate_locked(false);
	mutex_unlock(&yz_lifecycle_lock);
}

module_init(yukizygisk_init);
module_exit(yukizygisk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatdx");
MODULE_DESCRIPTION("Standalone YukiZygisk kernel LKM");
