/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>
#include <linux/fs_pin.h>

struct mnt_namespace {
	struct ns_common	ns;
	struct mount *	root;
	struct rb_root		mounts; /* Protected by namespace_sem */
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
	unsigned int		nr_mounts; /* # of mounts in the namespace */
	unsigned int		pending_mounts;
} __randomize_layout;

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rb_node mnt_node; /* node in the ns->mounts rbtree */
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	struct mountpoint *mnt_mp;	/* where is it mounted */
	union {
		struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting; /* list entry for umount propagation */
#ifdef CONFIG_FSNOTIFY
	struct fsnotify_mark_connector __rcu *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier, reused */
	u64 mnt_id_unique;		/* mount ID unique until reboot */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
} __randomize_layout;

#define MNT_NS_INTERNAL ERR_PTR(-EINVAL) /* distinct from any mnt_namespace */

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

static inline int mnt_has_parent(struct mount *mnt)
{
	return mnt != mnt->mnt_parent;
}

static inline int is_mounted(struct vfsmount *mnt)
{
	/* neither detached nor internal? */
	return !IS_ERR_OR_NULL(real_mount(mnt)->mnt_ns);
}

extern struct mount *__lookup_mnt(struct vfsmount *, struct dentry *);

extern int __legitimize_mnt(struct vfsmount *, unsigned);

static inline bool __path_is_mountpoint(const struct path *path)
{
	struct mount *m = __lookup_mnt(path->mnt, path->dentry);
	return m && likely(!(m->mnt.mnt_flags & MNT_SYNC_UMOUNT));
}

extern void __detach_mounts(struct dentry *dentry);

static inline void detach_mounts(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return;
	__detach_mounts(dentry);
}

static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	refcount_inc(&ns->ns.count);
}

extern seqlock_t mount_lock;

struct proc_mounts {
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
};

extern const struct seq_operations mounts_op;

extern bool __is_local_mountpoint(struct dentry *dentry);
static inline bool is_local_mountpoint(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return false;

	return __is_local_mountpoint(dentry);
}

static inline bool is_anon_ns(struct mnt_namespace *ns)
{
	return ns->seq == 0;
}

static inline bool mnt_ns_attached(const struct mount *mnt)
{
	return !RB_EMPTY_NODE(&mnt->mnt_node);
}

static inline void move_from_ns(struct mount *mnt, struct list_head *dt_list)
{
	WARN_ON(!mnt_ns_attached(mnt));
	rb_erase(&mnt->mnt_node, &mnt->mnt_ns->mounts);
	RB_CLEAR_NODE(&mnt->mnt_node);
	list_add_tail(&mnt->mnt_list, dt_list);
}

extern void mnt_cursor_del(struct mnt_namespace *ns, struct mount *cursor);
