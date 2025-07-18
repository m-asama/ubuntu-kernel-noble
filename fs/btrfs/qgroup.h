/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014 Facebook.  All rights reserved.
 */

#ifndef BTRFS_QGROUP_H
#define BTRFS_QGROUP_H

#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/kobject.h>
#include "ulist.h"
#include "delayed-ref.h"
#include "misc.h"

/*
 * Btrfs qgroup overview
 *
 * Btrfs qgroup splits into 3 main part:
 * 1) Reserve
 *    Reserve metadata/data space for incoming operations
 *    Affect how qgroup limit works
 *
 * 2) Trace
 *    Tell btrfs qgroup to trace dirty extents.
 *
 *    Dirty extents including:
 *    - Newly allocated extents
 *    - Extents going to be deleted (in this trans)
 *    - Extents whose owner is going to be modified
 *
 *    This is the main part affects whether qgroup numbers will stay
 *    consistent.
 *    Btrfs qgroup can trace clean extents and won't cause any problem,
 *    but it will consume extra CPU time, it should be avoided if possible.
 *
 * 3) Account
 *    Btrfs qgroup will updates its numbers, based on dirty extents traced
 *    in previous step.
 *
 *    Normally at qgroup rescan and transaction commit time.
 */

/*
 * Special performance optimization for balance.
 *
 * For balance, we need to swap subtree of subvolume and reloc trees.
 * In theory, we need to trace all subtree blocks of both subvolume and reloc
 * trees, since their owner has changed during such swap.
 *
 * However since balance has ensured that both subtrees are containing the
 * same contents and have the same tree structures, such swap won't cause
 * qgroup number change.
 *
 * But there is a race window between subtree swap and transaction commit,
 * during that window, if we increase/decrease tree level or merge/split tree
 * blocks, we still need to trace the original subtrees.
 *
 * So for balance, we use a delayed subtree tracing, whose workflow is:
 *
 * 1) Record the subtree root block get swapped.
 *
 *    During subtree swap:
 *    O = Old tree blocks
 *    N = New tree blocks
 *          reloc tree                     subvolume tree X
 *             Root                               Root
 *            /    \                             /    \
 *          NA     OB                          OA      OB
 *        /  |     |  \                      /  |      |  \
 *      NC  ND     OE  OF                   OC  OD     OE  OF
 *
 *   In this case, NA and OA are going to be swapped, record (NA, OA) into
 *   subvolume tree X.
 *
 * 2) After subtree swap.
 *          reloc tree                     subvolume tree X
 *             Root                               Root
 *            /    \                             /    \
 *          OA     OB                          NA      OB
 *        /  |     |  \                      /  |      |  \
 *      OC  OD     OE  OF                   NC  ND     OE  OF
 *
 * 3a) COW happens for OB
 *     If we are going to COW tree block OB, we check OB's bytenr against
 *     tree X's swapped_blocks structure.
 *     If it doesn't fit any, nothing will happen.
 *
 * 3b) COW happens for NA
 *     Check NA's bytenr against tree X's swapped_blocks, and get a hit.
 *     Then we do subtree scan on both subtrees OA and NA.
 *     Resulting 6 tree blocks to be scanned (OA, OC, OD, NA, NC, ND).
 *
 *     Then no matter what we do to subvolume tree X, qgroup numbers will
 *     still be correct.
 *     Then NA's record gets removed from X's swapped_blocks.
 *
 * 4)  Transaction commit
 *     Any record in X's swapped_blocks gets removed, since there is no
 *     modification to the swapped subtrees, no need to trigger heavy qgroup
 *     subtree rescan for them.
 */

/*
 * These flags share the flags field of the btrfs_qgroup_status_item with the
 * persisted flags defined in btrfs_tree.h.
 *
 * To minimize the chance of collision with new persisted status flags, these
 * count backwards from the MSB.
 */
#define BTRFS_QGROUP_RUNTIME_FLAG_CANCEL_RESCAN		(1ULL << 63)
#define BTRFS_QGROUP_RUNTIME_FLAG_NO_ACCOUNTING		(1ULL << 62)

#define BTRFS_QGROUP_DROP_SUBTREE_THRES_DEFAULT		(3)

/*
 * Record a dirty extent, and info qgroup to update quota on it
 * TODO: Use kmem cache to alloc it.
 */
struct btrfs_qgroup_extent_record {
	struct rb_node node;
	u64 bytenr;
	u64 num_bytes;

	/*
	 * For qgroup reserved data space freeing.
	 *
	 * @data_rsv_refroot and @data_rsv will be recorded after
	 * BTRFS_ADD_DELAYED_EXTENT is called.
	 * And will be used to free reserved qgroup space at
	 * transaction commit time.
	 */
	u32 data_rsv;		/* reserved data space needs to be freed */
	u64 data_rsv_refroot;	/* which root the reserved data belongs to */
	struct ulist *old_roots;
};

struct btrfs_qgroup_swapped_block {
	struct rb_node node;

	int level;
	bool trace_leaf;

	/* bytenr/generation of the tree block in subvolume tree after swap */
	u64 subvol_bytenr;
	u64 subvol_generation;

	/* bytenr/generation of the tree block in reloc tree after swap */
	u64 reloc_bytenr;
	u64 reloc_generation;

	u64 last_snapshot;
	struct btrfs_key first_key;
};

/*
 * Qgroup reservation types:
 *
 * DATA:
 *	space reserved for data
 *
 * META_PERTRANS:
 * 	Space reserved for metadata (per-transaction)
 * 	Due to the fact that qgroup data is only updated at transaction commit
 * 	time, reserved space for metadata must be kept until transaction
 * 	commits.
 * 	Any metadata reserved that are used in btrfs_start_transaction() should
 * 	be of this type.
 *
 * META_PREALLOC:
 *	There are cases where metadata space is reserved before starting
 *	transaction, and then btrfs_join_transaction() to get a trans handle.
 *	Any metadata reserved for such usage should be of this type.
 *	And after join_transaction() part (or all) of such reservation should
 *	be converted into META_PERTRANS.
 */
enum btrfs_qgroup_rsv_type {
	BTRFS_QGROUP_RSV_DATA,
	BTRFS_QGROUP_RSV_META_PERTRANS,
	BTRFS_QGROUP_RSV_META_PREALLOC,
	BTRFS_QGROUP_RSV_LAST,
};

/*
 * Represents how many bytes we have reserved for this qgroup.
 *
 * Each type should have different reservation behavior.
 * E.g, data follows its io_tree flag modification, while
 * *currently* meta is just reserve-and-clear during transaction.
 *
 * TODO: Add new type for reservation which can survive transaction commit.
 * Current metadata reservation behavior is not suitable for such case.
 */
struct btrfs_qgroup_rsv {
	u64 values[BTRFS_QGROUP_RSV_LAST];
};

/*
 * one struct for each qgroup, organized in fs_info->qgroup_tree.
 */
struct btrfs_qgroup {
	u64 qgroupid;

	/*
	 * state
	 */
	u64 rfer;	/* referenced */
	u64 rfer_cmpr;	/* referenced compressed */
	u64 excl;	/* exclusive */
	u64 excl_cmpr;	/* exclusive compressed */

	/*
	 * limits
	 */
	u64 lim_flags;	/* which limits are set */
	u64 max_rfer;
	u64 max_excl;
	u64 rsv_rfer;
	u64 rsv_excl;

	/*
	 * reservation tracking
	 */
	struct btrfs_qgroup_rsv rsv;

	/*
	 * lists
	 */
	struct list_head groups;  /* groups this group is member of */
	struct list_head members; /* groups that are members of this group */
	struct list_head dirty;   /* dirty groups */

	/*
	 * For qgroup iteration usage.
	 *
	 * The iteration list should always be empty until qgroup_iterator_add()
	 * is called.  And should be reset to empty after the iteration is
	 * finished.
	 */
	struct list_head iterator;

	/*
	 * For nested iterator usage.
	 *
	 * Here we support at most one level of nested iterator calls like:
	 *
	 *	LIST_HEAD(all_qgroups);
	 *	{
	 *		LIST_HEAD(local_qgroups);
	 *		qgroup_iterator_add(local_qgroups, qg);
	 *		qgroup_iterator_nested_add(all_qgroups, qg);
	 *		do_some_work(local_qgroups);
	 *		qgroup_iterator_clean(local_qgroups);
	 *	}
	 *	do_some_work(all_qgroups);
	 *	qgroup_iterator_nested_clean(all_qgroups);
	 */
	struct list_head nested_iterator;
	struct rb_node node;	  /* tree of qgroups */

	/*
	 * temp variables for accounting operations
	 * Refer to qgroup_shared_accounting() for details.
	 */
	u64 old_refcnt;
	u64 new_refcnt;

	/*
	 * Sysfs kobjectid
	 */
	struct kobject kobj;
};

struct btrfs_squota_delta {
	/* The fstree root this delta counts against. */
	u64 root;
	/* The number of bytes in the extent being counted. */
	u64 num_bytes;
	/* The generation the extent was created in. */
	u64 generation;
	/* Whether we are using or freeing the extent. */
	bool is_inc;
	/* Whether the extent is data or metadata. */
	bool is_data;
};

static inline u64 btrfs_qgroup_subvolid(u64 qgroupid)
{
	return (qgroupid & ((1ULL << BTRFS_QGROUP_LEVEL_SHIFT) - 1));
}

/*
 * For qgroup event trace points only
 */
enum {
	ENUM_BIT(QGROUP_RESERVE),
	ENUM_BIT(QGROUP_RELEASE),
	ENUM_BIT(QGROUP_FREE),
};

enum btrfs_qgroup_mode {
	BTRFS_QGROUP_MODE_DISABLED,
	BTRFS_QGROUP_MODE_FULL,
	BTRFS_QGROUP_MODE_SIMPLE
};

enum btrfs_qgroup_mode btrfs_qgroup_mode(struct btrfs_fs_info *fs_info);
bool btrfs_qgroup_enabled(struct btrfs_fs_info *fs_info);
bool btrfs_qgroup_full_accounting(struct btrfs_fs_info *fs_info);
int btrfs_quota_enable(struct btrfs_fs_info *fs_info,
		       struct btrfs_ioctl_quota_ctl_args *quota_ctl_args);
int btrfs_quota_disable(struct btrfs_fs_info *fs_info);
int btrfs_qgroup_rescan(struct btrfs_fs_info *fs_info);
void btrfs_qgroup_rescan_resume(struct btrfs_fs_info *fs_info);
int btrfs_qgroup_wait_for_completion(struct btrfs_fs_info *fs_info,
				     bool interruptible);
int btrfs_add_qgroup_relation(struct btrfs_trans_handle *trans, u64 src, u64 dst);
int btrfs_del_qgroup_relation(struct btrfs_trans_handle *trans, u64 src,
			      u64 dst);
int btrfs_create_qgroup(struct btrfs_trans_handle *trans, u64 qgroupid);
int btrfs_remove_qgroup(struct btrfs_trans_handle *trans, u64 qgroupid);
int btrfs_limit_qgroup(struct btrfs_trans_handle *trans, u64 qgroupid,
		       struct btrfs_qgroup_limit *limit);
int btrfs_read_qgroup_config(struct btrfs_fs_info *fs_info);
void btrfs_free_qgroup_config(struct btrfs_fs_info *fs_info);
struct btrfs_delayed_extent_op;

int btrfs_qgroup_trace_extent_nolock(
		struct btrfs_fs_info *fs_info,
		struct btrfs_delayed_ref_root *delayed_refs,
		struct btrfs_qgroup_extent_record *record);
int btrfs_qgroup_trace_extent_post(struct btrfs_trans_handle *trans,
				   struct btrfs_qgroup_extent_record *qrecord);
int btrfs_qgroup_trace_extent(struct btrfs_trans_handle *trans, u64 bytenr,
			      u64 num_bytes);
int btrfs_qgroup_trace_leaf_items(struct btrfs_trans_handle *trans,
				  struct extent_buffer *eb);
int btrfs_qgroup_trace_subtree(struct btrfs_trans_handle *trans,
			       struct extent_buffer *root_eb,
			       u64 root_gen, int root_level);
int btrfs_qgroup_account_extent(struct btrfs_trans_handle *trans, u64 bytenr,
				u64 num_bytes, struct ulist *old_roots,
				struct ulist *new_roots);
int btrfs_qgroup_account_extents(struct btrfs_trans_handle *trans);
int btrfs_run_qgroups(struct btrfs_trans_handle *trans);
int btrfs_qgroup_check_inherit(struct btrfs_fs_info *fs_info,
			       struct btrfs_qgroup_inherit *inherit,
			       size_t size);
int btrfs_qgroup_inherit(struct btrfs_trans_handle *trans, u64 srcid,
			 u64 objectid, u64 inode_rootid,
			 struct btrfs_qgroup_inherit *inherit);
void btrfs_qgroup_free_refroot(struct btrfs_fs_info *fs_info,
			       u64 ref_root, u64 num_bytes,
			       enum btrfs_qgroup_rsv_type type);

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
int btrfs_verify_qgroup_counts(struct btrfs_fs_info *fs_info, u64 qgroupid,
			       u64 rfer, u64 excl);
#endif

/* New io_tree based accurate qgroup reserve API */
int btrfs_qgroup_reserve_data(struct btrfs_inode *inode,
			struct extent_changeset **reserved, u64 start, u64 len);
int btrfs_qgroup_release_data(struct btrfs_inode *inode, u64 start, u64 len, u64 *released);
int btrfs_qgroup_free_data(struct btrfs_inode *inode,
			   struct extent_changeset *reserved, u64 start,
			   u64 len, u64 *freed);
int btrfs_qgroup_reserve_meta(struct btrfs_root *root, int num_bytes,
			      enum btrfs_qgroup_rsv_type type, bool enforce);
int __btrfs_qgroup_reserve_meta(struct btrfs_root *root, int num_bytes,
				enum btrfs_qgroup_rsv_type type, bool enforce,
				bool noflush);
/* Reserve metadata space for pertrans and prealloc type */
static inline int btrfs_qgroup_reserve_meta_pertrans(struct btrfs_root *root,
				int num_bytes, bool enforce)
{
	return __btrfs_qgroup_reserve_meta(root, num_bytes,
					   BTRFS_QGROUP_RSV_META_PERTRANS,
					   enforce, false);
}
static inline int btrfs_qgroup_reserve_meta_prealloc(struct btrfs_root *root,
						     int num_bytes, bool enforce,
						     bool noflush)
{
	return __btrfs_qgroup_reserve_meta(root, num_bytes,
					   BTRFS_QGROUP_RSV_META_PREALLOC,
					   enforce, noflush);
}

void __btrfs_qgroup_free_meta(struct btrfs_root *root, int num_bytes,
			     enum btrfs_qgroup_rsv_type type);

/* Free per-transaction meta reservation for error handling */
static inline void btrfs_qgroup_free_meta_pertrans(struct btrfs_root *root,
						   int num_bytes)
{
	__btrfs_qgroup_free_meta(root, num_bytes,
			BTRFS_QGROUP_RSV_META_PERTRANS);
}

/* Pre-allocated meta reservation can be freed at need */
static inline void btrfs_qgroup_free_meta_prealloc(struct btrfs_root *root,
						   int num_bytes)
{
	__btrfs_qgroup_free_meta(root, num_bytes,
			BTRFS_QGROUP_RSV_META_PREALLOC);
}

void btrfs_qgroup_free_meta_all_pertrans(struct btrfs_root *root);
void btrfs_qgroup_convert_reserved_meta(struct btrfs_root *root, int num_bytes);
void btrfs_qgroup_check_reserved_leak(struct btrfs_inode *inode);

/* btrfs_qgroup_swapped_blocks related functions */
void btrfs_qgroup_init_swapped_blocks(
	struct btrfs_qgroup_swapped_blocks *swapped_blocks);

void btrfs_qgroup_clean_swapped_blocks(struct btrfs_root *root);
int btrfs_qgroup_add_swapped_blocks(struct btrfs_trans_handle *trans,
		struct btrfs_root *subvol_root,
		struct btrfs_block_group *bg,
		struct extent_buffer *subvol_parent, int subvol_slot,
		struct extent_buffer *reloc_parent, int reloc_slot,
		u64 last_snapshot);
int btrfs_qgroup_trace_subtree_after_cow(struct btrfs_trans_handle *trans,
		struct btrfs_root *root, struct extent_buffer *eb);
void btrfs_qgroup_destroy_extent_records(struct btrfs_transaction *trans);
bool btrfs_check_quota_leak(struct btrfs_fs_info *fs_info);
void btrfs_free_squota_rsv(struct btrfs_fs_info *fs_info, u64 root, u64 rsv_bytes);
int btrfs_record_squota_delta(struct btrfs_fs_info *fs_info,
			      struct btrfs_squota_delta *delta);

#endif
