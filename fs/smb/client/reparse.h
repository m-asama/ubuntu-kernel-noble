/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024 Paulo Alcantara <pc@manguebit.com>
 */

#ifndef _CIFS_REPARSE_H
#define _CIFS_REPARSE_H

#include <linux/fs.h>
#include <linux/stat.h>
#include "cifsglob.h"

#define REPARSE_SYM_PATH_MAX 4060

/*
 * Used only by cifs.ko to ignore reparse points from files when client or
 * server doesn't support FSCTL_GET_REPARSE_POINT.
 */
#define IO_REPARSE_TAG_INTERNAL ((__u32)~0U)

static inline dev_t reparse_nfs_mkdev(struct reparse_posix_data *buf)
{
	u64 v = le64_to_cpu(*(__le64 *)buf->DataBuffer);

	return MKDEV(v >> 32, v & 0xffffffff);
}

static inline u64 reparse_mode_nfs_type(mode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFBLK: return NFS_SPECFILE_BLK;
	case S_IFCHR: return NFS_SPECFILE_CHR;
	case S_IFIFO: return NFS_SPECFILE_FIFO;
	case S_IFSOCK: return NFS_SPECFILE_SOCK;
	}
	return 0;
}

/*
 * Match a reparse point inode if reparse tag and ctime haven't changed.
 *
 * Windows Server updates ctime of reparse points when their data have changed.
 * The server doesn't allow changing reparse tags from existing reparse points,
 * though it's worth checking.
 */
static inline bool reparse_inode_match(struct inode *inode,
				       struct cifs_fattr *fattr)
{
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct timespec64 ctime = inode_get_ctime(inode);

	/*
	 * Do not match reparse tags when client or server doesn't support
	 * FSCTL_GET_REPARSE_POINT.  @fattr->cf_cifstag should contain correct
	 * reparse tag from query dir response but the client won't be able to
	 * read the reparse point data anyway.  This spares us a revalidation.
	 */
	if (cinode->reparse_tag != IO_REPARSE_TAG_INTERNAL &&
	    cinode->reparse_tag != fattr->cf_cifstag)
		return false;
	return (cinode->cifsAttrs & ATTR_REPARSE) &&
		timespec64_equal(&ctime, &fattr->cf_ctime);
}

static inline bool cifs_open_data_reparse(struct cifs_open_info_data *data)
{
	struct smb2_file_all_info *fi = &data->fi;
	u32 attrs = le32_to_cpu(fi->Attributes);
	bool ret;

	ret = data->reparse_point || (attrs & ATTR_REPARSE);
	if (ret)
		attrs |= ATTR_REPARSE;
	fi->Attributes = cpu_to_le32(attrs);
	return ret;
}

bool cifs_reparse_point_to_fattr(struct cifs_sb_info *cifs_sb,
				 struct cifs_fattr *fattr,
				 struct cifs_open_info_data *data);
int smb2_create_reparse_symlink(const unsigned int xid, struct inode *inode,
				struct dentry *dentry, struct cifs_tcon *tcon,
				const char *full_path, const char *symname);
int smb2_make_nfs_node(unsigned int xid, struct inode *inode,
		       struct dentry *dentry, struct cifs_tcon *tcon,
		       const char *full_path, umode_t mode, dev_t dev);
int smb2_parse_reparse_point(struct cifs_sb_info *cifs_sb,
			     const char *full_path,
			     struct kvec *rsp_iov,
			     struct cifs_open_info_data *data);

#endif /* _CIFS_REPARSE_H */
