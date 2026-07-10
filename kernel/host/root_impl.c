/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Root implementation detector.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "host/root_impl.h"
#include "host/runtime.h"

#define YZ_KP_SYMBOL_NAME_LEN 32
#define YZ_KP_SYMBOL_SIZE 48
#define YZ_KP_SCAN_CHUNK PAGE_SIZE
#define YZ_KP_SCAN_OVERLAP YZ_KP_SYMBOL_SIZE
#define YZ_KP_MAX_SYMBOL_WALK 256
#define YZ_KP_MAX_SCAN_RANGE (512UL * 1024 * 1024)
#define YZ_KP_MAX_VMAP_RANGE (64UL * 1024 * 1024)
#define YZ_KP_MAX_VMAP_AREAS 4096
#define YZ_KP_VM_FLAGS 0x44UL
#define YZ_KP_SU_NAME "su_get_path"
#define YZ_KSU_DENYLIST_UID_MAX 4096
#define YZ_KSU_ALLOWLIST_PATH "/data/adb/ksu/.allowlist"

#define YZ_ROOT_FLAG_KSU_REDIRECT (1U << 0)

struct yz_kp_symbol {
	u64 addr;
	u64 hash;
	char name[YZ_KP_SYMBOL_NAME_LEN];
};

struct yz_kp_vmap_area {
	unsigned long va_start;
	unsigned long va_end;
	struct rb_node rb_node;
	struct list_head list;
	union {
		unsigned long subtree_max_size;
		struct vm_struct *vm;
	};
	unsigned long flags;
};

struct yz_kp_vmap_pool {
	struct list_head head;
	unsigned long len;
};

struct yz_kp_rb_list {
	struct rb_root root;
	struct list_head head;
	spinlock_t lock;
};

struct yz_kp_vmap_node {
	struct yz_kp_vmap_pool pool[256];
	spinlock_t pool_lock;
	bool skip_populate;
	struct yz_kp_rb_list busy;
	struct yz_kp_rb_list lazy;
	struct list_head purge_list;
	struct work_struct purge_work;
	unsigned long nr_purged;
};

int yz_root_mask;
int yz_ksu_dispatcher_nr = -1;
enum yz_root_owner yz_root_owner = YZ_ROOT_OWNER_NONE;
bool yz_root_policy_allowed;
yz_ksu_is_allow_uid_fn yz_ksu_is_allow_uid_ptr;
yz_ksu_uid_should_umount_fn yz_ksu_uid_should_umount_ptr;
yz_ksu_get_allow_list_fn yz_ksu_get_allow_list_ptr;

static int *yz_ksu_denylist_uids;
static u16 yz_ksu_denylist_count;

const char *(*yz_ap_su_get_path)(void);
int (*yz_ap_is_su_allow_uid)(uid_t uid);
int (*yz_ap_su_allow_uid_nums)(void);
int (*yz_ap_su_allow_uids)(int is_user, uid_t *out_uids, int out_num);
int (*yz_ap_su_allow_uid_profile)(int is_user, uid_t uid,
				  struct yz_ap_su_profile *profile);
int (*yz_ap_get_mod_exclude)(uid_t uid);
int (*yz_ap_list_mod_exclude)(uid_t *uids, int len);
int (*yz_ap_read_kstorage)(int gid, long did, void *data, int offset,
			   int len, bool data_is_user);
int (*yz_ap_list_kstorage_ids)(int gid, long *ids, int idslen,
			       bool data_is_user);

static YZ_NOCFI struct file *yz_open_ro(const char *path)
{
	if (!yz_filp_open)
		yz_filp_open = (void *)yz_lookup_callable_quiet("filp_open");
	if (!yz_filp_open)
		return ERR_PTR(-ENOENT);
	return yz_filp_open(path, O_RDONLY, 0);
}

static YZ_NOCFI void yz_close_file(struct file *file)
{
	if (!yz_filp_close)
		yz_filp_close = (void *)yz_lookup_callable_quiet("filp_close");
	if (yz_filp_close)
		yz_filp_close(file, NULL);
	else
		fput(file);
}

static void yz_ap_clear_symbols(void)
{
	yz_ap_su_get_path = NULL;
	yz_ap_is_su_allow_uid = NULL;
	yz_ap_su_allow_uid_nums = NULL;
	yz_ap_su_allow_uids = NULL;
	yz_ap_su_allow_uid_profile = NULL;
	yz_ap_get_mod_exclude = NULL;
	yz_ap_list_mod_exclude = NULL;
	yz_ap_read_kstorage = NULL;
	yz_ap_list_kstorage_ids = NULL;
}

static bool yz_kp_symbol_name_eq(const struct yz_kp_symbol *sym,
				 const char *name)
{
	size_t len = strlen(name);

	if (len >= YZ_KP_SYMBOL_NAME_LEN)
		return false;
	if (memcmp(sym->name, name, len) != 0)
		return false;
	return sym->name[len] == '\0';
}

static bool yz_kp_read_symbol(unsigned long entry, struct yz_kp_symbol *sym)
{
	if (!yz_valid_kernel_addr(entry))
		return false;
	return yz_kernel_read_nofault(sym, entry, sizeof(*sym));
}

static unsigned long yz_kp_lookup_near(unsigned long anchor, const char *name)
{
	struct yz_kp_symbol sym;
	int i;

	for (i = -YZ_KP_MAX_SYMBOL_WALK; i <= YZ_KP_MAX_SYMBOL_WALK; i++) {
		unsigned long entry = anchor + i * YZ_KP_SYMBOL_SIZE;

		if (!yz_kp_read_symbol(entry, &sym))
			continue;
		if (!yz_kp_symbol_name_eq(&sym, name))
			continue;
		if (!yz_valid_kernel_addr((unsigned long)sym.addr))
			return 0;
		return (unsigned long)sym.addr;
	}

	return 0;
}

static bool yz_kp_parse_table(unsigned long su_name_addr)
{
	unsigned long anchor = su_name_addr - offsetof(struct yz_kp_symbol, name);
	struct yz_kp_symbol sym;
	unsigned long addr;

	if (!yz_kp_read_symbol(anchor, &sym) ||
	    !yz_kp_symbol_name_eq(&sym, YZ_KP_SU_NAME) ||
	    !yz_valid_kernel_addr((unsigned long)sym.addr))
		return false;

	addr = yz_kp_lookup_near(anchor, "su_allow_uid_profile");
	if (!addr)
		return false;
	yz_ap_su_allow_uid_profile = (void *)addr;

	addr = yz_kp_lookup_near(anchor, "get_ap_mod_exclude");
	if (!addr)
		return false;
	yz_ap_get_mod_exclude = (void *)addr;

	yz_ap_su_get_path = (void *)(unsigned long)sym.addr;
	yz_ap_is_su_allow_uid =
		(void *)yz_kp_lookup_near(anchor, "is_su_allow_uid");
	yz_ap_su_allow_uid_nums =
		(void *)yz_kp_lookup_near(anchor, "su_allow_uid_nums");
	yz_ap_su_allow_uids =
		(void *)yz_kp_lookup_near(anchor, "su_allow_uids");
	yz_ap_list_mod_exclude =
		(void *)yz_kp_lookup_near(anchor, "list_ap_mod_exclude");
	yz_ap_read_kstorage =
		(void *)yz_kp_lookup_near(anchor, "read_kstorage");
	yz_ap_list_kstorage_ids =
		(void *)yz_kp_lookup_near(anchor, "list_kstorage_ids");

	pr_info("yukizygisk: APatch KP symbols detected: su_get_path=%px profile=%px exclude=%px\n",
		yz_ap_su_get_path, yz_ap_su_allow_uid_profile,
		yz_ap_get_mod_exclude);
	return true;
}

static bool yz_kp_scan_chunk(unsigned long base, const char *buf, size_t len)
{
	size_t name_len = strlen(YZ_KP_SU_NAME);
	size_t i;

	if (len < name_len)
		return false;

	for (i = 0; i <= len - name_len; i++) {
		if (buf[i] != YZ_KP_SU_NAME[0])
			continue;
		if (memcmp(buf + i, YZ_KP_SU_NAME, name_len) != 0)
			continue;
		if (yz_kp_parse_table(base + i))
			return true;
	}

	return false;
}

static bool yz_kp_scan_range(unsigned long start, unsigned long end,
			     const char *tag)
{
	char *buf;
	unsigned long pos;

	if (!yz_valid_kernel_addr(start) || !yz_valid_kernel_addr(end) ||
	    end <= start || end - start > YZ_KP_MAX_SCAN_RANGE) {
		pr_warn("yukizygisk: skip KP %s scan, bad range [%lx, %lx)\n",
			tag, start, end);
		return false;
	}

	buf = kmalloc(YZ_KP_SCAN_CHUNK + YZ_KP_SCAN_OVERLAP, GFP_KERNEL);
	if (!buf)
		return false;

	for (pos = start; pos < end; pos += YZ_KP_SCAN_CHUNK) {
		size_t len = min_t(unsigned long,
				   YZ_KP_SCAN_CHUNK + YZ_KP_SCAN_OVERLAP,
				   end - pos);

		if (!yz_kernel_read_nofault(buf, pos, len))
			continue;
		if (yz_kp_scan_chunk(pos, buf, len)) {
			kfree(buf);
			pr_info("yukizygisk: APatch KP symbol table found in %s range [%lx, %lx)\n",
				tag, start, end);
			return true;
		}
	}

	kfree(buf);
	return false;
}

static bool yz_kp_scan_kernel_image(void)
{
	unsigned long start = yz_lookup_callable_quiet("_text");
	unsigned long end = yz_lookup_callable_quiet("_end");

	if (!yz_valid_kernel_addr(start))
		start = yz_lookup_callable_quiet("_stext");

	return yz_kp_scan_range(start, end, "kernel image");
}

static bool yz_kp_scan_vmap_list(unsigned long head_addr, const char *tag)
{
	struct yz_kp_vmap_area va;
	struct list_head head;
	unsigned long pos;
	int count = 0;

	if (!yz_valid_kernel_addr(head_addr) ||
	    !yz_kernel_read_nofault(&head, head_addr, sizeof(head)))
		return false;

	pos = (unsigned long)head.next;
	while (yz_valid_kernel_addr(pos) && pos != head_addr &&
	       count++ < YZ_KP_MAX_VMAP_AREAS) {
		unsigned long va_addr =
			pos - offsetof(struct yz_kp_vmap_area, list);
		struct vm_struct vm;
		unsigned long size;

		if (!yz_kernel_read_nofault(&va, va_addr, sizeof(va)))
			break;

		if (yz_valid_kernel_addr(va.va_start) &&
		    yz_valid_kernel_addr(va.va_end) &&
		    va.va_end > va.va_start) {
			size = va.va_end - va.va_start;
			if (size >= YZ_KP_SYMBOL_SIZE &&
			    size <= YZ_KP_MAX_VMAP_RANGE &&
			    yz_valid_kernel_addr((unsigned long)va.vm) &&
			    yz_kernel_read_nofault(&vm, (unsigned long)va.vm,
						   sizeof(vm)) &&
			    (unsigned long)vm.addr == va.va_start &&
			    vm.size == size && vm.flags == YZ_KP_VM_FLAGS) {
				pr_info("yukizygisk: scanning APatch-like vmap [%lx, %lx) caller=%px\n",
					va.va_start, va.va_end, vm.caller);
				if (yz_kp_scan_range(va.va_start, va.va_end,
						     tag))
					return true;
			}
		}

		pos = (unsigned long)va.list.next;
	}

	return false;
}

static bool yz_kp_scan_vmap_nodes(void)
{
	unsigned long nodes_sym = yz_lookup_callable_quiet("vmap_nodes");
	unsigned long nr_sym = yz_lookup_callable_quiet("nr_vmap_nodes");
	struct yz_kp_vmap_node *nodes;
	unsigned int nr;
	unsigned int i;

	if (!yz_valid_kernel_addr(nodes_sym) ||
	    !yz_valid_kernel_addr(nr_sym) ||
	    !yz_kernel_read_nofault(&nodes, nodes_sym, sizeof(nodes)) ||
	    !yz_kernel_read_nofault(&nr, nr_sym, sizeof(nr)) ||
	    !yz_valid_kernel_addr((unsigned long)nodes) || nr == 0 || nr > 1024)
		return false;

	for (i = 0; i < nr; i++) {
		unsigned long head_addr = (unsigned long)&nodes[i].busy.head;

		if (yz_kp_scan_vmap_list(head_addr, "vmalloc"))
			return true;
	}

	return false;
}

static bool yz_kp_scan_legacy_vmap_list(void)
{
	unsigned long head_addr = yz_lookup_callable_quiet("vmap_area_list");

	if (!yz_valid_kernel_addr(head_addr))
		return false;

	return yz_kp_scan_vmap_list(head_addr, "vmalloc");
}

static bool yz_kp_scan_symbols(void)
{
	if (yz_kp_scan_kernel_image())
		return true;
	if (yz_kp_scan_vmap_nodes())
		return true;
	if (yz_kp_scan_legacy_vmap_list())
		return true;

	pr_info("yukizygisk: APatch KP symbol table not found in scanned memory\n");
	return false;
}

static bool yz_apatch_detect(void)
{
	unsigned long addr;

	yz_ap_clear_symbols();

	addr = yz_lookup_callable_quiet("su_get_path");
	if (addr && yz_valid_kernel_addr(addr)) {
		yz_ap_su_get_path = (void *)addr;
		yz_ap_su_allow_uid_profile =
			(void *)yz_lookup_callable_quiet("su_allow_uid_profile");
		yz_ap_get_mod_exclude =
			(void *)yz_lookup_callable_quiet("get_ap_mod_exclude");
		pr_info("yukizygisk: APatch sucompat detected via kallsyms\n");
		return true;
	}

	if (yz_kp_scan_symbols()) {
		pr_info("yukizygisk: APatch sucompat detected via KP symbol scan\n");
		return true;
	}

	return false;
}

static bool yz_path_exists(const char *path)
{
	struct file *file;

	if (!path)
		return false;
	file = yz_open_ro(path);
	if (IS_ERR(file))
		return false;
	yz_close_file(file);
	return true;
}

static bool yz_ksu_detect(bool *policy_available)
{
	unsigned long addr;
	bool seen = false;
	bool has_policy = false;

	addr = yz_lookup_callable_quiet("ksu_syscall_table");
	if (addr && yz_valid_kernel_addr(addr)) {
		yz_root_mask |= YZ_ROOT_KSU;
		seen = true;
		addr = yz_lookup_callable_quiet("ksu_dispatcher_nr");
		if (addr && yz_valid_kernel_addr(addr)) {
			int nr = -1;

			if (yz_kernel_read_nofault(&nr, addr, sizeof(nr)) &&
			    nr >= 0) {
				yz_ksu_dispatcher_nr = nr;
				yz_root_mask |= YZ_ROOT_KSU_RDR;
			}
		}
	}

	addr = yz_lookup_callable_quiet("ksu_uid_should_umount");
	if (addr && yz_valid_kernel_addr(addr)) {
		yz_root_mask |= YZ_ROOT_KSU;
		yz_ksu_uid_should_umount_ptr = (void *)addr;
		seen = true;
		has_policy = true;
	}

	addr = yz_lookup_callable_quiet("ksu_get_allow_list");
	if (addr && yz_valid_kernel_addr(addr)) {
		yz_root_mask |= YZ_ROOT_KSU;
		yz_ksu_get_allow_list_ptr = (void *)addr;
		seen = true;
		has_policy = true;
	}

	if (seen) {
		addr = yz_lookup_callable_quiet("__ksu_is_allow_uid_for_current");
		if (addr && yz_valid_kernel_addr(addr))
			yz_ksu_is_allow_uid_ptr = (void *)addr;
		if (!yz_ksu_is_allow_uid_ptr) {
			addr = yz_lookup_callable_quiet("__ksu_is_allow_uid");
			if (addr && yz_valid_kernel_addr(addr))
				yz_ksu_is_allow_uid_ptr = (void *)addr;
		}
	}

	if (yz_path_exists(YZ_KSU_ALLOWLIST_PATH)) {
		yz_root_mask |= YZ_ROOT_KSU;
		seen = true;
	}

	if (seen)
		pr_info("yukizygisk: KernelSU detected%s%s\n",
			(yz_root_mask & YZ_ROOT_KSU_RDR) ? " (redirect)" : "",
			has_policy ? "" : " (no policy source)");

	*policy_available = has_policy;
	return seen;
}

static bool yz_magisk_detect(void)
{
	static const char *const magisk_paths[] = {
		"/sbin/magisk",
		"/debug_ramdisk/sbin/magisk",
		"/data/adb/magisk/magisk",
		NULL,
	};
	int i;

	for (i = 0; magisk_paths[i]; i++) {
		struct file *file = yz_open_ro(magisk_paths[i]);

		if (IS_ERR(file))
			continue;
		yz_close_file(file);
		yz_root_mask |= YZ_ROOT_MAGISK;
		pr_info("yukizygisk: Magisk detected at %s\n",
			magisk_paths[i]);
		return true;
	}

	return false;
}

static void yz_ksu_clear_denylist(void)
{
	kfree(yz_ksu_denylist_uids);
	yz_ksu_denylist_uids = NULL;
	yz_ksu_denylist_count = 0;
}

static YZ_NOCFI int yz_ksu_prepare_denylist(void)
{
	int *uids;
	u16 out_length = 0;
	u16 out_total = 0;
	u16 i;
	u16 valid = 0;
	bool ok;

	if (yz_ksu_uid_should_umount_ptr) {
		pr_info("yukizygisk: KernelSU denylist backend: ksu_uid_should_umount\n");
		return 0;
	}
	if (!yz_ksu_get_allow_list_ptr)
		return -EOPNOTSUPP;

	uids = kcalloc(YZ_KSU_DENYLIST_UID_MAX, sizeof(*uids), GFP_KERNEL);
	if (!uids)
		return -ENOMEM;

	ok = yz_ksu_get_allow_list_ptr(uids, YZ_KSU_DENYLIST_UID_MAX,
					     &out_length, &out_total, false);
	if (!ok) {
		kfree(uids);
		return -EIO;
	}
	if (out_total > out_length) {
		pr_err("yukizygisk: KernelSU denylist has %u entries, bulk API returned %u; refusing a partial policy\n",
		       out_total, out_length);
		kfree(uids);
		return -E2BIG;
	}

	for (i = 0; i < out_length; i++) {
		if (uids[i] > 0)
			uids[valid++] = uids[i];
	}
	yz_ksu_denylist_uids = uids;
	yz_ksu_denylist_count = valid;
	pr_info("yukizygisk: KernelSU denylist backend: cached %u uid(s)\n",
		valid);
	return 0;
}

int yz_host_root_detect(void)
{
	bool ksu_seen;
	bool ksu_policy_available = false;
	bool apatch_seen;
	bool magisk_seen;
	int active_roots = 0;
	int ret;

	yz_ksu_clear_denylist();
	yz_root_mask = YZ_ROOT_NONE;
	yz_ksu_dispatcher_nr = -1;
	yz_root_owner = YZ_ROOT_OWNER_NONE;
	yz_root_policy_allowed = false;
	yz_ksu_is_allow_uid_ptr = NULL;
	yz_ksu_uid_should_umount_ptr = NULL;
	yz_ksu_get_allow_list_ptr = NULL;

	ksu_seen = yz_ksu_detect(&ksu_policy_available);
	if (ksu_seen && !ksu_policy_available)
		pr_warn("yukizygisk: KernelSU detected without allowlist policy source\n");

	if (yz_apatch_detect()) {
		yz_root_mask |= YZ_ROOT_APATCH;
		apatch_seen = true;
	} else {
		apatch_seen = false;
	}

	magisk_seen = yz_magisk_detect();

	if (ksu_seen)
		active_roots++;
	if (apatch_seen)
		active_roots++;
	if (magisk_seen)
		active_roots++;

	if (active_roots > 1) {
		yz_root_mask |= YZ_ROOT_MULTI;
		pr_err("yukizygisk: multi-root detected (mask=0x%x), refusing to load\n",
			yz_root_mask);
		return -EBUSY;
	}

	if (ksu_seen) {
		if (!ksu_policy_available) {
			pr_err("yukizygisk: KernelSU has no readable denylist backend, refusing to load\n");
			return -EOPNOTSUPP;
		}
		ret = yz_ksu_prepare_denylist();
		if (ret) {
			pr_err("yukizygisk: KernelSU denylist backend init failed: %d\n",
			       ret);
			return ret;
		}
		yz_root_owner = YZ_ROOT_OWNER_KERNELSU;
		yz_root_policy_allowed = true;
		pr_info("yukizygisk: root owner accepted: KernelSU%s\n",
			(yz_root_mask & YZ_ROOT_KSU_RDR) ? " (redirect)" : "");
		return 0;
	}

	if (apatch_seen) {
		if (!yz_ap_get_mod_exclude) {
			pr_err("yukizygisk: KernelPatch has no readable denylist backend, refusing to load\n");
			return -EOPNOTSUPP;
		}
		yz_root_owner = YZ_ROOT_OWNER_KERNELPATCH;
		yz_root_policy_allowed = true;
		pr_info("yukizygisk: root owner accepted: KernelPatch\n");
		return 0;
	}

	if (magisk_seen) {
		pr_err("yukizygisk: Magisk-only environment is unsupported, refusing to load\n");
		return -EOPNOTSUPP;
	}

	yz_root_mask |= YZ_ROOT_NON_ROOT;
	pr_err("yukizygisk: no supported root implementation found (mask=0x%x), refusing to load\n",
		yz_root_mask);
	return -ENODEV;
}

bool yz_host_root_allows_policy(void)
{
	return READ_ONCE(yz_root_policy_allowed);
}

YZ_NOCFI bool yz_host_uid_should_umount(uid_t uid)
{
	u16 i;

	if (uid == 0 || !READ_ONCE(yz_root_policy_allowed))
		return false;

	switch (READ_ONCE(yz_root_owner)) {
	case YZ_ROOT_OWNER_KERNELSU:
		if (yz_ksu_uid_should_umount_ptr)
			return yz_ksu_uid_should_umount_ptr(uid);
		for (i = 0; i < READ_ONCE(yz_ksu_denylist_count); i++) {
			if (yz_ksu_denylist_uids[i] == (int)uid)
				return true;
		}
		return false;
	case YZ_ROOT_OWNER_KERNELPATCH:
		return yz_ap_get_mod_exclude && yz_ap_get_mod_exclude(uid) != 0;
	case YZ_ROOT_OWNER_NONE:
	default:
		return false;
	}
}

const char *yz_host_root_name(void)
{
	switch (READ_ONCE(yz_root_owner)) {
	case YZ_ROOT_OWNER_KERNELSU:
		return (yz_root_mask & YZ_ROOT_KSU_RDR) ?
			"kernelsu-redirect" : "kernelsu";
	case YZ_ROOT_OWNER_KERNELPATCH:
		return "kernelpatch";
	case YZ_ROOT_OWNER_NONE:
	default:
		return "unsupported";
	}
}

u32 yz_host_root_flags(void)
{
	return (yz_root_mask & YZ_ROOT_KSU_RDR) ?
		YZ_ROOT_FLAG_KSU_REDIRECT : 0;
}

void yz_host_root_exit(void)
{
	yz_root_policy_allowed = false;
	yz_root_owner = YZ_ROOT_OWNER_NONE;
	yz_ksu_clear_denylist();
	yz_ksu_is_allow_uid_ptr = NULL;
	yz_ksu_uid_should_umount_ptr = NULL;
	yz_ksu_get_allow_list_ptr = NULL;
	yz_ap_clear_symbols();
}
