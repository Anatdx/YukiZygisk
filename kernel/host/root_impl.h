/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Root implementation detector.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _YUKIZYGISK_HOST_ROOT_IMPL_H
#define _YUKIZYGISK_HOST_ROOT_IMPL_H

#include <linux/types.h>

struct file;

enum yz_root_impl_type {
	YZ_ROOT_NONE = 0,
	YZ_ROOT_KSU = 1 << 0,
	YZ_ROOT_KSU_RDR = 1 << 1,
	YZ_ROOT_APATCH = 1 << 2,
	YZ_ROOT_MAGISK = 1 << 3,
	YZ_ROOT_MULTI = 1 << 4,
	YZ_ROOT_NON_ROOT = 1 << 5,
};

enum yz_root_owner {
	YZ_ROOT_OWNER_NONE = 0,
	YZ_ROOT_OWNER_KERNELSU = 1,
	YZ_ROOT_OWNER_KERNELPATCH = 2,
};

struct yz_ap_su_profile {
	uid_t uid;
	uid_t to_uid;
	char scontext[0x60];
};

typedef bool (*yz_ksu_is_allow_uid_fn)(uid_t uid);
typedef bool (*yz_ksu_uid_should_umount_fn)(uid_t uid);
typedef bool (*yz_ksu_get_allow_list_fn)(int *array, u16 length,
					 u16 *out_length, u16 *out_total,
					 bool allow);

extern int yz_root_mask;
extern int yz_ksu_dispatcher_nr;
extern enum yz_root_owner yz_root_owner;
extern bool yz_root_policy_allowed;
extern yz_ksu_is_allow_uid_fn yz_ksu_is_allow_uid_ptr;
extern yz_ksu_uid_should_umount_fn yz_ksu_uid_should_umount_ptr;
extern yz_ksu_get_allow_list_fn yz_ksu_get_allow_list_ptr;

extern const char *(*yz_ap_su_get_path)(void);
extern int (*yz_ap_is_su_allow_uid)(uid_t uid);
extern int (*yz_ap_su_allow_uid_nums)(void);
extern int (*yz_ap_su_allow_uids)(int is_user, uid_t *out_uids,
				  int out_num);
extern int (*yz_ap_su_allow_uid_profile)(int is_user, uid_t uid,
					 struct yz_ap_su_profile *profile);
extern int (*yz_ap_get_mod_exclude)(uid_t uid);
extern int (*yz_ap_list_mod_exclude)(uid_t *uids, int len);
extern int (*yz_ap_read_kstorage)(int gid, long did, void *data, int offset,
				  int len, bool data_is_user);
extern int (*yz_ap_list_kstorage_ids)(int gid, long *ids, int idslen,
				      bool data_is_user);

int yz_host_root_detect(void);
void yz_host_root_exit(void);
bool yz_host_root_allows_policy(void);
bool yz_host_policy_uses_fallback(void);
bool yz_host_policy_cache_ready(void);
int yz_host_uid_should_umount(uid_t uid, bool *should_umount);
int yz_host_install_policy_cache(struct file *file);
const char *yz_host_root_name(void);
u32 yz_host_root_flags(void);

#endif /* _YUKIZYGISK_HOST_ROOT_IMPL_H */
