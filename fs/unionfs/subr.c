/*
 * Copyright (c) 2003-2007 Erez Zadok
 * Copyright (c) 2003-2006 Charles P. Wright
 * Copyright (c) 2005-2007 Josef 'Jeff' Sipek
 * Copyright (c) 2005-2006 Junjiro Okajima
 * Copyright (c) 2005      Arun M. Krishnakumar
 * Copyright (c) 2004-2006 David P. Quigley
 * Copyright (c) 2003-2004 Mohammad Nayyer Zubair
 * Copyright (c) 2003      Puja Gupta
 * Copyright (c) 2003      Harikesavan Krishnan
 * Copyright (c) 2003-2007 Stony Brook University
 * Copyright (c) 2003-2007 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "union.h"

/*
 * Pass an unionfs dentry and an index.  It will try to create a whiteout
 * for the filename in dentry, and will try in branch 'index'.  On error,
 * it will proceed to a branch to the left.
 */
int create_whiteout(struct dentry *dentry, int start)
{
	int bstart, bend, bindex;
	struct dentry *lower_dir_dentry;
	struct dentry *lower_dentry;
	struct dentry *lower_wh_dentry;
	struct nameidata nd;
	char *name = NULL;
	int err = -EINVAL;

	verify_locked(dentry);

	bstart = dbstart(dentry);
	bend = dbend(dentry);

	/* create dentry's whiteout equivalent */
	name = alloc_whname(dentry->d_name.name, dentry->d_name.len);
	if (unlikely(IS_ERR(name))) {
		err = PTR_ERR(name);
		goto out;
	}

	for (bindex = start; bindex >= 0; bindex--) {
		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);

		if (!lower_dentry) {
			/*
			 * if lower dentry is not present, create the
			 * entire lower dentry directory structure and go
			 * ahead.  Since we want to just create whiteout, we
			 * only want the parent dentry, and hence get rid of
			 * this dentry.
			 */
			lower_dentry = create_parents(dentry->d_inode,
						      dentry,
						      dentry->d_name.name,
						      bindex);
			if (!lower_dentry || IS_ERR(lower_dentry)) {
				int ret = PTR_ERR(lower_dentry);
				if (!IS_COPYUP_ERR(ret))
					printk(KERN_ERR
					       "unionfs: create_parents for "
					       "whiteout failed: bindex=%d "
					       "err=%d\n", bindex, ret);
				continue;
			}
		}

		lower_wh_dentry =
			lookup_one_len(name, lower_dentry->d_parent,
				       dentry->d_name.len + UNIONFS_WHLEN);
		if (IS_ERR(lower_wh_dentry))
			continue;

		/*
		 * The whiteout already exists. This used to be impossible,
		 * but now is possible because of opaqueness.
		 */
		if (lower_wh_dentry->d_inode) {
			dput(lower_wh_dentry);
			err = 0;
			goto out;
		}

		err = init_lower_nd(&nd, LOOKUP_CREATE);
		if (unlikely(err < 0))
			goto out;
		lower_dir_dentry = lock_parent_wh(lower_wh_dentry);
		err = is_robranch_super(dentry->d_sb, bindex);
		if (!err)
			err = vfs_create(lower_dir_dentry->d_inode,
					 lower_wh_dentry,
					 ~current->fs->umask & S_IRWXUGO,
					 &nd);
		unlock_dir(lower_dir_dentry);
		dput(lower_wh_dentry);
		release_lower_nd(&nd, err);

		if (!err || !IS_COPYUP_ERR(err))
			break;
	}

	/* set dbopaque so that lookup will not proceed after this branch */
	if (!err)
		set_dbopaque(dentry, bindex);

out:
	kfree(name);
	return err;
}

/*
 * This is a helper function for rename, which ends up with hosed over
 * dentries when it needs to revert.
 */
int unionfs_refresh_lower_dentry(struct dentry *dentry, int bindex)
{
	struct dentry *lower_dentry;
	struct dentry *lower_parent;
	int err = 0;

	verify_locked(dentry);

	unionfs_lock_dentry(dentry->d_parent, UNIONFS_DMUTEX_CHILD);
	lower_parent = unionfs_lower_dentry_idx(dentry->d_parent, bindex);
	unionfs_unlock_dentry(dentry->d_parent);

	BUG_ON(!S_ISDIR(lower_parent->d_inode->i_mode));

	lower_dentry = lookup_one_len(dentry->d_name.name, lower_parent,
				      dentry->d_name.len);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		goto out;
	}

	dput(unionfs_lower_dentry_idx(dentry, bindex));
	iput(unionfs_lower_inode_idx(dentry->d_inode, bindex));
	unionfs_set_lower_inode_idx(dentry->d_inode, bindex, NULL);

	if (!lower_dentry->d_inode) {
		dput(lower_dentry);
		unionfs_set_lower_dentry_idx(dentry, bindex, NULL);
	} else {
		unionfs_set_lower_dentry_idx(dentry, bindex, lower_dentry);
		unionfs_set_lower_inode_idx(dentry->d_inode, bindex,
					    igrab(lower_dentry->d_inode));
	}

out:
	return err;
}

int make_dir_opaque(struct dentry *dentry, int bindex)
{
	int err = 0;
	struct dentry *lower_dentry, *diropq;
	struct inode *lower_dir;
	struct nameidata nd;
	kernel_cap_t orig_cap;

	/*
	 * Opaque directory whiteout markers are special files (like regular
	 * whiteouts), and should appear to the users as if they don't
	 * exist.  They should be created/deleted regardless of directory
	 * search/create permissions, but only for the duration of this
	 * creation of the .wh.__dir_opaque: file.  Note, this does not
	 * circumvent normal ->permission).
	 */
	orig_cap = current->cap_effective;
	cap_raise(current->cap_effective, CAP_DAC_READ_SEARCH);
	cap_raise(current->cap_effective, CAP_DAC_OVERRIDE);

	lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
	lower_dir = lower_dentry->d_inode;
	BUG_ON(!S_ISDIR(dentry->d_inode->i_mode) ||
	       !S_ISDIR(lower_dir->i_mode));

	mutex_lock(&lower_dir->i_mutex);
	diropq = lookup_one_len(UNIONFS_DIR_OPAQUE, lower_dentry,
				sizeof(UNIONFS_DIR_OPAQUE) - 1);
	if (IS_ERR(diropq)) {
		err = PTR_ERR(diropq);
		goto out;
	}

	err = init_lower_nd(&nd, LOOKUP_CREATE);
	if (unlikely(err < 0))
		goto out;
	if (!diropq->d_inode)
		err = vfs_create(lower_dir, diropq, S_IRUGO, &nd);
	if (!err)
		set_dbopaque(dentry, bindex);
	release_lower_nd(&nd, err);

	dput(diropq);

out:
	mutex_unlock(&lower_dir->i_mutex);
	current->cap_effective = orig_cap;
	return err;
}

/*
 * returns the right n_link value based on the inode type
 */
int unionfs_get_nlinks(const struct inode *inode)
{
	/* don't bother to do all the work since we're unlinked */
	if (inode->i_nlink == 0)
		return 0;

	if (!S_ISDIR(inode->i_mode))
		return unionfs_lower_inode(inode)->i_nlink;

	/*
	 * For directories, we return 1. The only place that could cares
	 * about links is readdir, and there's d_type there so even that
	 * doesn't matter.
	 */
	return 1;
}

/* construct whiteout filename */
char *alloc_whname(const char *name, int len)
{
	char *buf;

	buf = kmalloc(len + UNIONFS_WHLEN + 1, GFP_KERNEL);
	if (unlikely(!buf))
		return ERR_PTR(-ENOMEM);

	strcpy(buf, UNIONFS_WHPFX);
	strlcat(buf, name, len + UNIONFS_WHLEN + 1);

	return buf;
}

/* copy a/m/ctime from the lower branch with the newest times */
void unionfs_copy_attr_times(struct inode *upper)
{
	int bindex;
	struct inode *lower;

	if (!upper)
		return;
	if (ibstart(upper) < 0) {
#ifdef CONFIG_UNION_FS_DEBUG
		WARN_ON(ibstart(upper) < 0);
#endif /* CONFIG_UNION_FS_DEBUG */
		return;
	}
	for (bindex = ibstart(upper); bindex <= ibend(upper); bindex++) {
		lower = unionfs_lower_inode_idx(upper, bindex);
		if (!lower)
			continue; /* not all lower dir objects may exist */
		if (unlikely(timespec_compare(&upper->i_mtime,
					      &lower->i_mtime) < 0))
			upper->i_mtime = lower->i_mtime;
		if (unlikely(timespec_compare(&upper->i_ctime,
					      &lower->i_ctime) < 0))
			upper->i_ctime = lower->i_ctime;
		if (unlikely(timespec_compare(&upper->i_atime,
					      &lower->i_atime) < 0))
			upper->i_atime = lower->i_atime;
	}
}

/*
 * A unionfs/fanout version of fsstack_copy_attr_all.  Uses a
 * unionfs_get_nlinks to properly calcluate the number of links to a file.
 * Also, copies the max() of all a/m/ctimes for all lower inodes (which is
 * important if the lower inode is a directory type)
 */
void unionfs_copy_attr_all(struct inode *dest,
			   const struct inode *src)
{
	dest->i_mode = src->i_mode;
	dest->i_uid = src->i_uid;
	dest->i_gid = src->i_gid;
	dest->i_rdev = src->i_rdev;

	unionfs_copy_attr_times(dest);

	dest->i_blkbits = src->i_blkbits;
	dest->i_flags = src->i_flags;

	/*
	 * Update the nlinks AFTER updating the above fields, because the
	 * get_links callback may depend on them.
	 */
	dest->i_nlink = unionfs_get_nlinks(dest);
}
