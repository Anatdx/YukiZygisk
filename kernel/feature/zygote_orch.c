/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - kernel-side orchestrator: per-app process lifecycle state
 * machine.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/compat.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>

#include <asm/syscall.h>
#include <asm/unistd.h>
#include <trace/events/sched.h>
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
#include <trace/events/syscalls.h>
#endif

#include "feature/zygote_orch.h"
#include "feature/zygote_nl.h"
#include "feature/zygote_ctl.h"
#include "host/host.h"
#include "klog.h" // IWYU pragma: keep

enum zo_state {
	ZO_FORKED, /* born from zygote; identity not yet known */
	ZO_SPECIALIZED, /* dropped to its app uid */
};

struct zo_child {
	pid_t pid; /* tgid of the app process; 0 == free slot */
	uid_t uid;
	enum zo_state state;
};

/* Holds only live app processes; the free probe reclaims slots. */
#define ZO_MAX_CHILDREN 512
static struct zo_child zo_children[ZO_MAX_CHILDREN];
static DEFINE_SPINLOCK(zo_lock);
static bool zo_trace_sys_exit_registered;
static struct tracepoint *zo_trace_sys_exit_tp;
static struct tracepoint *zo_trace_fork_tp;
static struct tracepoint *zo_trace_free_tp;

struct zo_specialize_event {
	pid_t pid;
	uid_t uid;
	u32 appid;
};

#define ZO_MAX_SPECIALIZE_EVENTS 128
static struct zo_specialize_event
	zo_specialize_events[ZO_MAX_SPECIALIZE_EVENTS];
static unsigned int zo_specialize_head;
static unsigned int zo_specialize_tail;
static unsigned int zo_specialize_dropped;
static bool zo_specialize_work_queued;
static DEFINE_SPINLOCK(zo_event_lock);
static void zo_specialize_work_fn(struct work_struct *work);
static DECLARE_WORK(zo_specialize_work, zo_specialize_work_fn);

/* caller holds zo_lock */
static int zo_slot_of(pid_t pid)
{
	int i;

	for (i = 0; i < ZO_MAX_CHILDREN; i++)
		if (zo_children[i].pid == pid)
			return i;
	return -1;
}

static void zo_track(pid_t pid)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&zo_lock, flags);
	if (zo_slot_of(pid) < 0) {
		i = zo_slot_of(0);
		if (i >= 0) {
			zo_children[i].pid = pid;
			zo_children[i].uid = (uid_t)-1;
			zo_children[i].state = ZO_FORKED;
		}
	}
	spin_unlock_irqrestore(&zo_lock, flags);
}

static void zo_queue_specialize_event(pid_t pid, uid_t uid, u32 appid)
{
	unsigned long flags;
	bool schedule = false;
	unsigned int next;

	spin_lock_irqsave(&zo_event_lock, flags);
	next = (zo_specialize_head + 1) % ZO_MAX_SPECIALIZE_EVENTS;
	if (next == zo_specialize_tail) {
		zo_specialize_dropped++;
	} else {
		zo_specialize_events[zo_specialize_head].pid = pid;
		zo_specialize_events[zo_specialize_head].uid = uid;
		zo_specialize_events[zo_specialize_head].appid = appid;
		zo_specialize_head = next;
	}
	if (!zo_specialize_work_queued) {
		zo_specialize_work_queued = true;
		schedule = true;
	}
	spin_unlock_irqrestore(&zo_event_lock, flags);

	if (schedule)
		schedule_work(&zo_specialize_work);
}

static bool zo_pop_specialize_event(struct zo_specialize_event *event,
				    unsigned int *dropped)
{
	unsigned long flags;
	bool have_event = false;

	spin_lock_irqsave(&zo_event_lock, flags);
	if (zo_specialize_tail != zo_specialize_head) {
		*event = zo_specialize_events[zo_specialize_tail];
		zo_specialize_tail =
			(zo_specialize_tail + 1) % ZO_MAX_SPECIALIZE_EVENTS;
		have_event = true;
	} else {
		*dropped = zo_specialize_dropped;
		zo_specialize_dropped = 0;
		if (!*dropped)
			zo_specialize_work_queued = false;
	}
	spin_unlock_irqrestore(&zo_event_lock, flags);
	return have_event;
}

static void zo_specialize_work_fn(struct work_struct *work)
{
	struct zo_specialize_event event;
	unsigned int dropped = 0;

	(void)work;

	for (;;) {
		dropped = 0;
		if (zo_pop_specialize_event(&event, &dropped)) {
			pr_info("zygote_orch: [specialize] pid=%d uid=%u appid=%u\n",
				event.pid, event.uid, event.appid);
			yz_zygote_nl_emit_specialize(event.pid, event.appid);
			continue;
		}
		if (dropped) {
			pr_warn("zygote_orch: dropped %u specialize event(s)\n",
				dropped);
			continue;
		}
		break;
	}
}

static void zo_specialize_events_reset(void)
{
	unsigned long flags;

	cancel_work_sync(&zo_specialize_work);

	spin_lock_irqsave(&zo_event_lock, flags);
	zo_specialize_head = 0;
	zo_specialize_tail = 0;
	zo_specialize_dropped = 0;
	zo_specialize_work_queued = false;
	spin_unlock_irqrestore(&zo_event_lock, flags);
}

struct zo_tracepoint_lookup {
	const char *name;
	struct tracepoint *tp;
};

static void zo_tracepoint_find(struct tracepoint *tp, void *priv)
{
	struct zo_tracepoint_lookup *lookup = priv;

	if (!lookup->tp && tp->name && !strcmp(tp->name, lookup->name))
		lookup->tp = tp;
}

static struct tracepoint *zo_lookup_tracepoint(const char *name)
{
	struct zo_tracepoint_lookup lookup = {
		.name = name,
	};

	for_each_kernel_tracepoint(zo_tracepoint_find, &lookup);
	return lookup.tp;
}

static int zo_register_tracepoint(struct tracepoint **slot, const char *name,
				  void *probe)
{
	struct tracepoint *tp;
	int ret;

	if (*slot)
		return -EALREADY;

	tp = zo_lookup_tracepoint(name);
	if (!tp)
		return -ENOENT;

	ret = tracepoint_probe_register(tp, probe, NULL);
	if (ret)
		return ret;

	*slot = tp;
	return 0;
}

static void zo_unregister_tracepoint(struct tracepoint **slot, void *probe)
{
	if (!*slot)
		return;

	tracepoint_probe_unregister(*slot, probe, NULL);
	*slot = NULL;
}

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
static void zo_on_sys_exit(void *data, struct pt_regs *regs, long ret)
{
	int nr;

	(void)data;

	if (ret < 0)
		return;
#ifdef CONFIG_COMPAT
	if (is_compat_task())
		return;
#endif

	nr = syscall_get_nr(current, regs);
	if (nr != __NR_setresuid)
		return;

	yz_zygote_orch_on_setresuid((uid_t)-1, current_uid().val);
}

static int zo_tracepoint_init(void)
{
	int ret;

	ret = zo_register_tracepoint(&zo_trace_sys_exit_tp, "sys_exit",
				     (void *)zo_on_sys_exit);
	if (ret)
		return ret;
	zo_trace_sys_exit_registered = true;
	pr_info("zygote_orch: setresuid sys_exit monitor armed\n");
	return 0;
}

static void zo_tracepoint_exit(void)
{
	if (!zo_trace_sys_exit_registered)
		return;
	zo_unregister_tracepoint(&zo_trace_sys_exit_tp,
				 (void *)zo_on_sys_exit);
	tracepoint_synchronize_unregister();
	zo_trace_sys_exit_registered = false;
}
#else
static int zo_tracepoint_init(void)
{
	return -EOPNOTSUPP;
}

static void zo_tracepoint_exit(void)
{
}
#endif

static void zo_setresuid_monitor_init(void)
{
#ifdef __NR_setresuid
	int ret;

	ret = zo_tracepoint_init();
	if (!ret)
		return;

	pr_warn("zygote_orch: sys_exit monitor unavailable: %d; "
		"setresuid specialize events disabled\n",
		ret);
#else
	pr_warn("zygote_orch: __NR_setresuid unavailable; specialize events disabled\n");
#endif
}

static void zo_setresuid_monitor_exit(void)
{
	zo_tracepoint_exit();
}

#ifdef CONFIG_TRACEPOINTS

static void zo_on_fork(void *data, struct task_struct *parent,
		       struct task_struct *child)
{
	bool from_zygote;

	(void)data;

	/* thread-group leaders only -- skip the zygote's own worker threads */
	if (child->pid != child->tgid)
		return;

	rcu_read_lock();
	from_zygote = yz_host_is_zygote(__task_cred(parent));
	rcu_read_unlock();
	if (!from_zygote)
		return;

	zo_track(child->pid);
	pr_info("zygote_orch: [fork] app pid=%d born from zygote %d\n",
		child->pid, parent->pid);
}

static void zo_on_free(void *data, struct task_struct *p)
{
	unsigned long flags;
	bool tracked = false;
	uid_t uid = 0;
	int i;

	(void)data;

	if (p->pid != p->tgid)
		return;

	spin_lock_irqsave(&zo_lock, flags);
	i = zo_slot_of(p->pid);
	if (i >= 0) {
		tracked = true;
		uid = zo_children[i].uid;
		zo_children[i].pid = 0;
	}
	spin_unlock_irqrestore(&zo_lock, flags);

	if (tracked) {
		pr_info("zygote_orch: [gone] app pid=%d uid=%u\n", p->pid, uid);
		yz_zygote_ctl_release(p->pid);
	}
}

void yz_zygote_orch_init(void)
{
	int ret = zo_register_tracepoint(&zo_trace_fork_tp,
					 "sched_process_fork",
					 (void *)zo_on_fork);

	if (ret) {
		pr_err("zygote_orch: register fork probe failed: %d\n", ret);
		return;
	}

	ret = zo_register_tracepoint(&zo_trace_free_tp,
				     "sched_process_free",
				     (void *)zo_on_free);
	if (ret) {
		pr_err("zygote_orch: register free probe failed: %d\n", ret);
		zo_unregister_tracepoint(&zo_trace_fork_tp,
					 (void *)zo_on_fork);
		tracepoint_synchronize_unregister();
		return;
	}

	zo_setresuid_monitor_init();
	pr_info("zygote_orch: lifecycle state machine armed\n");
}

void yz_zygote_orch_exit(void)
{
	zo_setresuid_monitor_exit();
	zo_specialize_events_reset();
	zo_unregister_tracepoint(&zo_trace_fork_tp, (void *)zo_on_fork);
	zo_unregister_tracepoint(&zo_trace_free_tp, (void *)zo_on_free);
	tracepoint_synchronize_unregister();
}

#else /* !CONFIG_TRACEPOINTS */

void yz_zygote_orch_init(void)
{
	pr_warn("zygote_orch: CONFIG_TRACEPOINTS off; orchestrator disabled\n");
}

void yz_zygote_orch_exit(void)
{
}

#endif /* CONFIG_TRACEPOINTS */

/* current == the specializing child; dropping to an app uid reveals its
 * identity -- the injection decision point. */
void yz_zygote_orch_on_setresuid(uid_t old_uid, uid_t new_uid)
{
	unsigned long flags;
	pid_t pid = current->pid;
	bool specialized = false;
	int i;

	(void)old_uid;

	if (new_uid < 10000) /* app uids only */
		return;

	/* Isolated processes (appId 90000-99999) live in a tightly confined
	 * sandbox the core already tears itself out of in-process. The kernel
	 * must not specialize them or broker fds into them -- that domain is
	 * expected to stay pristine, and any kernel-side residue there is
	 * observable from inside the sandbox. */
	if (new_uid % 100000 >= 90000)
		return;

	spin_lock_irqsave(&zo_lock, flags);
	i = zo_slot_of(pid);
	if (i >= 0 && zo_children[i].state == ZO_FORKED) {
		zo_children[i].uid = new_uid;
		zo_children[i].state = ZO_SPECIALIZED;
		specialized = true;
	}
	spin_unlock_irqrestore(&zo_lock, flags);

	if (specialized) {
		zo_queue_specialize_event(pid, new_uid, new_uid % 100000);
	}
}
