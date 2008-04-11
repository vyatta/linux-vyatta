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
 * Helper function when creating new objects (create, symlink, and mknod).
 * Checks to see if there's a whiteout in @lower_dentry's parent directory,
 * whose name is taken from @dentry.  Then tries to remove that whiteout, if
 * found.
 *
 * Return 0 if no whiteout was found, or if one was found and successfully
 * removed (a zero tells the caller that @lower_dentry belongs to a good
 * branch to create the new object in).  Return -ERRNO if an error occurred
 * during whiteout lookup or in trying to unlink the whiteout.
 */
static int check_for_whiteout(struct dentry *dentry,
			      struct dentry *lower_dentry)
{
	int err = 0;
	struct dentry *wh_dentry = NULL;
	struct dentry *lower_dir_dentry;
	char *name = NULL;

	/*
	 * check if whiteout exists in this branch, i.e. lookup .wh.foo
	 * first.
	 */
	name = alloc_whname(dentry->d_name.name, dentry->d_name.len);
	if (unlikely(IS_ERR(name))) {
		err = PTR_ERR(name);
		goto out;
	}

	wh_dentry = lookup_one_len(name, lower_dentry->d_parent,
				   dentry->d_name.len + UNIONFS_WHLEN);
	if (IS_ERR(wh_dentry)) {
		err = PTR_ERR(wh_dentry);
		wh_dentry = NULL;
		goto out;
	}

	if (!wh_dentry->d_inode) /* no whiteout exists */
		goto out;

	/* .wh.foo has been found, so let's unlink it */
	lower_dir_dentry = lock_parent_wh(wh_dentry);
	/* see Documentation/filesystems/unionfs/issues.txt */
	lockdep_off();
	err = vfs_unlink(lower_dir_dentry->d_inode, wh_dentry);
	lockdep_on();
	unlock_dir(lower_dir_dentry);

	/*
	 * Whiteouts are special files and should be deleted no matter what
	 * (as if they never existed), in order to allow this create
	 * operation to succeed.  This is especially important in sticky
	 * directories: a whiteout may have been created by one user, but
	 * the newly created file may be created by another user.
	 * Therefore, in order to maintain Unix semantics, if the vfs_unlink
	 * above failed, then we have to try to directly unlink the
	 * whiteout.  Note: in the ODF version of unionfs, whiteout are
	 * handled much more cleanly.
	 */
	if (err == -EPERM) {
		struct inode *inode = lower_dir_dentry->d_inode;
		err = inode->i_op->unlink(inode, wh_dentry);
	}
	if (err)
		printk(KERN_ERR "unionfs: could not "
		       "unlink whiteout, err = %d\n", err);

out:
	dput(wh_dentry);
	kfree(name);
	return err;
}

/*
 * Find a writeable branch to create new object in.  Checks all writeble
 * branches of the parent inode, from istart to iend order; if none are
 * suitable, also tries branch 0 (which may require a copyup).
 *
 * Return a lower_dentry we can use to create object in, or ERR_PTR.
 */
static struct dentry *find_writeable_branch(struct inode *parent,
					    struct dentry *dentry)
{
	int err = -EINVAL;
	int bindex, istart, iend;
	struct dentry *lower_dentry = NULL;

	istart = ibstart(parent);
	iend = ibend(parent);
	if (istart < 0)
		goto out;

begin:
	for (bindex = istart; bindex <= iend; bindex++) {
		/* skip non-writeable branches */
		err = is_robranch_super(dentry->d_sb, bindex);
		if (err) {
			err = -EROFS;
			continue;
		}
		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry)
			continue;
		/*
		 * check for whiteouts in writeable branch, and remove them
		 * if necessary.
		 */
		err = check_for_whiteout(dentry, lower_dentry);
		if (err)
			continue;
	}
	/*
	 * If istart wasn't already branch 0, and we got any error, then try
	 * branch 0 (which may require copyup)
	 */
	if (err && istart > 0) {
		istart = iend = 0;
		goto begin;
	}

	/*
	 * If we tried even branch 0, and still got an error, abort.  But if
	 * the error was an EROFS, then we should try to copyup.
	 */
	if (err && err != -EROFS)
		goto out;

	/*
	 * If we get here, then check if copyup needed.  If lower_dentry is
	 * NULL, create the entire dentry directory structure in branch 0.
	 */
	if (!lower_dentry) {
		bindex = 0;
		lower_dentry = create_parents(parent, dentry,
					      dentry->d_name.name, bindex);
		if (IS_ERR(lower_dentry)) {
			err = PTR_ERR(lower_dentry);
			goto out;
		}
	}
	err = 0;		/* all's well */
out:
	if (err)
		return ERR_PTR(err);
	return lower_dentry;
}

static int unionfs_create(struct inode *parent, struct dentry *dentry,
			  int mode, struct nameidata *nd)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	int valid = 0;
	struct nameidata lower_nd;

	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);
	unionfs_lock_dentry(dentry->d_parent, UNIONFS_DMUTEX_PARENT);

	valid = __unionfs_d_revalidate_chain(dentry->d_parent, nd, false);
	if (unlikely(!valid)) {
		err = -ESTALE;	/* same as what real_lookup does */
		goto out;
	}

	valid = __unionfs_d_revalidate_one_locked(dentry, nd, false);
	/*
	 * It's only a bug if this dentry was not negative and couldn't be
	 * revalidated (shouldn't happen).
	 */
	BUG_ON(!valid && dentry->d_inode);

	lower_dentry = find_writeable_branch(parent, dentry);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		goto out;
	}

	lower_parent_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_parent_dentry)) {
		err = PTR_ERR(lower_parent_dentry);
		goto out;
	}

	err = init_lower_nd(&lower_nd, LOOKUP_CREATE);
	if (unlikely(err < 0))
		goto out;
	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode,
			 &lower_nd);
	release_lower_nd(&lower_nd, err);

	if (!err) {
		err = PTR_ERR(unionfs_interpose(dentry, parent->i_sb, 0));
		if (!err) {
			unionfs_copy_attr_times(parent);
			fsstack_copy_inode_size(parent,
						lower_parent_dentry->d_inode);
			/* update no. of links on parent directory */
			parent->i_nlink = unionfs_get_nlinks(parent);
		}
	}

	unlock_dir(lower_parent_dentry);

out:
	if (!err) {
		unionfs_postcopyup_setmnt(dentry);
		unionfs_check_inode(parent);
		unionfs_check_dentry(dentry);
		unionfs_check_nd(nd);
	}
	unionfs_unlock_dentry(dentry->d_parent);
	unionfs_unlock_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);
	return err;
}

/*
 * unionfs_lookup is the only special function which takes a dentry, yet we
 * do NOT want to call __unionfs_d_revalidate_chain because by definition,
 * we don't have a valid dentry here yet.
 */
static struct dentry *unionfs_lookup(struct inode *parent,
				     struct dentry *dentry,
				     struct nameidata *nd)
{
	struct path path_save = {NULL, NULL};
	struct dentry *ret;

	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	if (dentry != dentry->d_parent)
		unionfs_lock_dentry(dentry->d_parent, UNIONFS_DMUTEX_ROOT);

	/* save the dentry & vfsmnt from namei */
	if (nd) {
		path_save.dentry = nd->dentry;
		path_save.mnt = nd->mnt;
	}

	/*
	 * unionfs_lookup_backend returns a locked dentry upon success,
	 * so we'll have to unlock it below.
	 */
	ret = unionfs_lookup_backend(dentry, nd, INTERPOSE_LOOKUP);

	/* restore the dentry & vfsmnt in namei */
	if (nd) {
		nd->dentry = path_save.dentry;
		nd->mnt = path_save.mnt;
	}
	if (!IS_ERR(ret)) {
		if (ret)
			dentry = ret;
		unionfs_copy_attr_times(dentry->d_inode);
		/* parent times may have changed */
		unionfs_copy_attr_times(dentry->d_parent->d_inode);
	}

	unionfs_check_inode(parent);
	if (!IS_ERR(ret)) {
		unionfs_check_dentry(dentry);
		unionfs_check_nd(nd);
		unionfs_unlock_dentry(dentry);
	}

	if (dentry != dentry->d_parent) {
		unionfs_check_dentry(dentry->d_parent);
		unionfs_unlock_dentry(dentry->d_parent);
	}
	unionfs_read_unlock(dentry->d_sb);

	return ret;
}

static int unionfs_link(struct dentry *old_dentry, struct inode *dir,
			struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_dir_dentry = NULL;
	struct dentry *whiteout_dentry;
	char *name = NULL;

	unionfs_read_lock(old_dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	unionfs_double_lock_dentry(new_dentry, old_dentry);

	if (unlikely(!__unionfs_d_revalidate_chain(old_dentry, NULL, false))) {
		err = -ESTALE;
		goto out;
	}
	if (unlikely(new_dentry->d_inode &&
		     !__unionfs_d_revalidate_chain(new_dentry, NULL, false))) {
		err = -ESTALE;
		goto out;
	}

	lower_new_dentry = unionfs_lower_dentry(new_dentry);

	/*
	 * check if whiteout exists in the branch of new dentry, i.e. lookup
	 * .wh.foo first. If present, delete it
	 */
	name = alloc_whname(new_dentry->d_name.name, new_dentry->d_name.len);
	if (unlikely(IS_ERR(name))) {
		err = PTR_ERR(name);
		goto out;
	}

	whiteout_dentry = lookup_one_len(name, lower_new_dentry->d_parent,
					 new_dentry->d_name.len +
					 UNIONFS_WHLEN);
	if (IS_ERR(whiteout_dentry)) {
		err = PTR_ERR(whiteout_dentry);
		goto out;
	}

	if (!whiteout_dentry->d_inode) {
		dput(whiteout_dentry);
		whiteout_dentry = NULL;
	} else {
		/* found a .wh.foo entry, unlink it and then call vfs_link() */
		lower_dir_dentry = lock_parent_wh(whiteout_dentry);
		err = is_robranch_super(new_dentry->d_sb, dbstart(new_dentry));
		if (!err) {
			/* see Documentation/filesystems/unionfs/issues.txt */
			lockdep_off();
			err = vfs_unlink(lower_dir_dentry->d_inode,
					 whiteout_dentry);
			lockdep_on();
		}

		fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
		dir->i_nlink = unionfs_get_nlinks(dir);
		unlock_dir(lower_dir_dentry);
		lower_dir_dentry = NULL;
		dput(whiteout_dentry);
		if (err)
			goto out;
	}

	if (dbstart(old_dentry) != dbstart(new_dentry)) {
		lower_new_dentry = create_parents(dir, new_dentry,
						  new_dentry->d_name.name,
						  dbstart(old_dentry));
		err = PTR_ERR(lower_new_dentry);
		if (IS_COPYUP_ERR(err))
			goto docopyup;
		if (!lower_new_dentry || IS_ERR(lower_new_dentry))
			goto out;
	}
	lower_new_dentry = unionfs_lower_dentry(new_dentry);
	lower_old_dentry = unionfs_lower_dentry(old_dentry);

	BUG_ON(dbstart(old_dentry) != dbstart(new_dentry));
	lower_dir_dentry = lock_parent(lower_new_dentry);
	err = is_robranch(old_dentry);
	if (!err) {
		/* see Documentation/filesystems/unionfs/issues.txt */
		lockdep_off();
		err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
			       lower_new_dentry);
		lockdep_on();
	}
	unlock_dir(lower_dir_dentry);

docopyup:
	if (IS_COPYUP_ERR(err)) {
		int old_bstart = dbstart(old_dentry);
		int bindex;

		for (bindex = old_bstart - 1; bindex >= 0; bindex--) {
			err = copyup_dentry(old_dentry->d_parent->d_inode,
					    old_dentry, old_bstart,
					    bindex, old_dentry->d_name.name,
					    old_dentry->d_name.len, NULL,
					    i_size_read(old_dentry->d_inode));
			if (!err) {
				lower_new_dentry =
					create_parents(dir, new_dentry,
						       new_dentry->d_name.name,
						       bindex);
				lower_old_dentry =
					unionfs_lower_dentry(old_dentry);
				lower_dir_dentry =
					lock_parent(lower_new_dentry);
				/*
				 * see
				 * Documentation/filesystems/unionfs/issues.txt
				 */
				lockdep_off();
				/* do vfs_link */
				err = vfs_link(lower_old_dentry,
					       lower_dir_dentry->d_inode,
					       lower_new_dentry);
				lockdep_on();
				unlock_dir(lower_dir_dentry);
				goto check_link;
			}
		}
		goto out;
	}

check_link:
	if (err || !lower_new_dentry->d_inode)
		goto out;

	/* Its a hard link, so use the same inode */
	new_dentry->d_inode = igrab(old_dentry->d_inode);
	d_instantiate(new_dentry, new_dentry->d_inode);
	unionfs_copy_attr_all(dir, lower_new_dentry->d_parent->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_parent->d_inode);

	/* propagate number of hard-links */
	old_dentry->d_inode->i_nlink = unionfs_get_nlinks(old_dentry->d_inode);
	/* new dentry's ctime may have changed due to hard-link counts */
	unionfs_copy_attr_times(new_dentry->d_inode);

out:
	if (!new_dentry->d_inode)
		d_drop(new_dentry);

	kfree(name);
	if (!err)
		unionfs_postcopyup_setmnt(new_dentry);

	unionfs_check_inode(dir);
	unionfs_check_dentry(new_dentry);
	unionfs_check_dentry(old_dentry);

	unionfs_unlock_dentry(new_dentry);
	unionfs_unlock_dentry(old_dentry);
	unionfs_read_unlock(old_dentry->d_sb);

	return err;
}

static int unionfs_symlink(struct inode *parent, struct dentry *dentry,
			   const char *symname)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *wh_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	char *name = NULL;
	int valid = 0;
	umode_t mode;

	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);
	unionfs_lock_dentry(dentry->d_parent, UNIONFS_DMUTEX_PARENT);

	valid = __unionfs_d_revalidate_chain(dentry->d_parent, NULL, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}
	if (unlikely(dentry->d_inode &&
		     !__unionfs_d_revalidate_one_locked(dentry, NULL, false))) {
		err = -ESTALE;
		goto out;
	}

	/*
	 * It's only a bug if this dentry was not negative and couldn't be
	 * revalidated (shouldn't happen).
	 */
	BUG_ON(!valid && dentry->d_inode);

	lower_dentry = find_writeable_branch(parent, dentry);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		goto out;
	}

	lower_parent_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_parent_dentry)) {
		err = PTR_ERR(lower_parent_dentry);
		goto out;
	}

	mode = S_IALLUGO;
	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry,
			  symname, mode);
	if (!err) {
		err = PTR_ERR(unionfs_interpose(dentry, parent->i_sb, 0));
		if (!err) {
			unionfs_copy_attr_times(parent);
			fsstack_copy_inode_size(parent,
						lower_parent_dentry->d_inode);
			/* update no. of links on parent directory */
			parent->i_nlink = unionfs_get_nlinks(parent);
		}
	}

	unlock_dir(lower_parent_dentry);

out:
	dput(wh_dentry);
	kfree(name);

	if (!err) {
		unionfs_postcopyup_setmnt(dentry);
		unionfs_check_inode(parent);
		unionfs_check_dentry(dentry);
	}
	unionfs_unlock_dentry(dentry->d_parent);
	unionfs_unlock_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);
	return err;
}

static int unionfs_mkdir(struct inode *parent, struct dentry *dentry, int mode)
{
	int err = 0;
	struct dentry *lower_dentry = NULL, *whiteout_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	int bindex = 0, bstart;
	char *name = NULL;
	int whiteout_unlinked = 0;
	struct sioq_args args;
	int valid;

	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);
	unionfs_lock_dentry(dentry->d_parent, UNIONFS_DMUTEX_PARENT);

	valid = __unionfs_d_revalidate_chain(dentry->d_parent, NULL, false);
	if (unlikely(!valid)) {
		err = -ESTALE;	/* same as what real_lookup does */
		goto out;
	}
	if (unlikely(dentry->d_inode &&
		     !__unionfs_d_revalidate_one_locked(dentry, NULL, false))) {
		err = -ESTALE;
		goto out;
	}

	bstart = dbstart(dentry);

	lower_dentry = unionfs_lower_dentry(dentry);

	/*
	 * check if whiteout exists in this branch, i.e. lookup .wh.foo
	 * first.
	 */
	name = alloc_whname(dentry->d_name.name, dentry->d_name.len);
	if (unlikely(IS_ERR(name))) {
		err = PTR_ERR(name);
		goto out;
	}

	whiteout_dentry = lookup_one_len(name, lower_dentry->d_parent,
					 dentry->d_name.len + UNIONFS_WHLEN);
	if (IS_ERR(whiteout_dentry)) {
		err = PTR_ERR(whiteout_dentry);
		goto out;
	}

	if (!whiteout_dentry->d_inode) {
		dput(whiteout_dentry);
		whiteout_dentry = NULL;
	} else {
		lower_parent_dentry = lock_parent_wh(whiteout_dentry);

		/* found a.wh.foo entry, remove it then do vfs_mkdir */
		err = is_robranch_super(dentry->d_sb, bstart);
		if (!err) {
			args.unlink.parent = lower_parent_dentry->d_inode;
			args.unlink.dentry = whiteout_dentry;
			run_sioq(__unionfs_unlink, &args);
			err = args.err;
		}
		dput(whiteout_dentry);

		unlock_dir(lower_parent_dentry);

		if (err) {
			/* exit if the error returned was NOT -EROFS */
			if (!IS_COPYUP_ERR(err))
				goto out;
			bstart--;
		} else {
			whiteout_unlinked = 1;
		}
	}

	for (bindex = bstart; bindex >= 0; bindex--) {
		int i;
		int bend = dbend(dentry);

		if (is_robranch_super(dentry->d_sb, bindex))
			continue;

		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry) {
			lower_dentry = create_parents(parent, dentry,
						      dentry->d_name.name,
						      bindex);
			if (!lower_dentry || IS_ERR(lower_dentry)) {
				printk(KERN_ERR "unionfs: lower dentry "
				       " NULL for bindex = %d\n", bindex);
				continue;
			}
		}

		lower_parent_dentry = lock_parent(lower_dentry);

		if (IS_ERR(lower_parent_dentry)) {
			err = PTR_ERR(lower_parent_dentry);
			goto out;
		}

		err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry,
				mode);

		unlock_dir(lower_parent_dentry);

		/* did the mkdir succeed? */
		if (err)
			break;

		for (i = bindex + 1; i < bend; i++) {
			if (unionfs_lower_dentry_idx(dentry, i)) {
				dput(unionfs_lower_dentry_idx(dentry, i));
				unionfs_set_lower_dentry_idx(dentry, i, NULL);
			}
		}
		set_dbend(dentry, bindex);

		/*
		 * Only INTERPOSE_LOOKUP can return a value other than 0 on
		 * err.
		 */
		err = PTR_ERR(unionfs_interpose(dentry, parent->i_sb, 0));
		if (!err) {
			unionfs_copy_attr_times(parent);
			fsstack_copy_inode_size(parent,
						lower_parent_dentry->d_inode);

			/* update number of links on parent directory */
			parent->i_nlink = unionfs_get_nlinks(parent);
		}

		err = make_dir_opaque(dentry, dbstart(dentry));
		if (err) {
			printk(KERN_ERR "unionfs: mkdir: error creating "
			       ".wh.__dir_opaque: %d\n", err);
			goto out;
		}

		/* we are done! */
		break;
	}

out:
	if (!dentry->d_inode)
		d_drop(dentry);

	kfree(name);

	if (!err) {
		unionfs_copy_attr_times(dentry->d_inode);
		unionfs_postcopyup_setmnt(dentry);
	}
	unionfs_check_inode(parent);
	unionfs_check_dentry(dentry);
	unionfs_unlock_dentry(dentry->d_parent);
	unionfs_unlock_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);

	return err;
}

static int unionfs_mknod(struct inode *parent, struct dentry *dentry, int mode,
			 dev_t dev)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *wh_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	char *name = NULL;
	int valid = 0;

	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);
	unionfs_lock_dentry(dentry->d_parent, UNIONFS_DMUTEX_PARENT);

	valid = __unionfs_d_revalidate_chain(dentry->d_parent, NULL, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}
	if (unlikely(dentry->d_inode &&
		     !__unionfs_d_revalidate_one_locked(dentry, NULL, false))) {
		err = -ESTALE;
		goto out;
	}

	/*
	 * It's only a bug if this dentry was not negative and couldn't be
	 * revalidated (shouldn't happen).
	 */
	BUG_ON(!valid && dentry->d_inode);

	lower_dentry = find_writeable_branch(parent, dentry);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		goto out;
	}

	lower_parent_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_parent_dentry)) {
		err = PTR_ERR(lower_parent_dentry);
		goto out;
	}

	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (!err) {
		err = PTR_ERR(unionfs_interpose(dentry, parent->i_sb, 0));
		if (!err) {
			unionfs_copy_attr_times(parent);
			fsstack_copy_inode_size(parent,
						lower_parent_dentry->d_inode);
			/* update no. of links on parent directory */
			parent->i_nlink = unionfs_get_nlinks(parent);
		}
	}

	unlock_dir(lower_parent_dentry);

out:
	dput(wh_dentry);
	kfree(name);

	if (!err) {
		unionfs_postcopyup_setmnt(dentry);
		unionfs_check_inode(parent);
		unionfs_check_dentry(dentry);
	}
	unionfs_unlock_dentry(dentry->d_parent);
	unionfs_unlock_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);
	return err;
}

static int unionfs_readlink(struct dentry *dentry, char __user *buf,
			    int bufsiz)
{
	int err;
	struct dentry *lower_dentry;

	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);

	if (unlikely(!__unionfs_d_revalidate_chain(dentry, NULL, false))) {
		err = -ESTALE;
		goto out;
	}

	lower_dentry = unionfs_lower_dentry(dentry);

	if (!lower_dentry->d_inode->i_op ||
	    !lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err > 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_dentry->d_inode);

out:
	unionfs_check_dentry(dentry);
	unionfs_unlock_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);

	return err;
}

/*
 * unionfs_follow_link takes a dentry, but it is simple.  It only needs to
 * allocate some memory and then call our ->readlink method.  Our
 * unionfs_readlink *does* lock our dentry and revalidate the dentry.
 * Therefore, we do not have to lock our dentry here, to prevent a deadlock;
 * nor do we need to revalidate it either.  It is safe to not lock our
 * dentry here, nor revalidate it, because unionfs_follow_link does not do
 * anything (prior to calling ->readlink) which could become inconsistent
 * due to branch management.  We also don't need to lock our super because
 * this function isn't affected by branch-management.
 */
static void *unionfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (unlikely(!buf)) {
		err = -ENOMEM;
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = dentry->d_inode->i_op->readlink(dentry, (char __user *)buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = NULL;
		goto out;
	}
	buf[err] = 0;
	nd_set_link(nd, buf);
	err = 0;

out:
	if (!err) {
		unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);
		unionfs_check_dentry(dentry);
		unionfs_unlock_dentry(dentry);
	}
	unionfs_check_nd(nd);
	return ERR_PTR(err);
}

/* FIXME: We may not have to lock here */
static void unionfs_put_link(struct dentry *dentry, struct nameidata *nd,
			     void *cookie)
{
	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);

	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);
	if (unlikely(!__unionfs_d_revalidate_chain(dentry, nd, false)))
		printk(KERN_ERR
		       "unionfs: put_link failed to revalidate dentry\n");

	unionfs_check_dentry(dentry);
	unionfs_check_nd(nd);
	kfree(nd_get_link(nd));
	unionfs_unlock_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);
}

/*
 * Don't grab the superblock read-lock in unionfs_permission, which prevents
 * a deadlock with the branch-management "add branch" code (which grabbed
 * the write lock).  It is safe to not grab the read lock here, because even
 * with branch management taking place, there is no chance that
 * unionfs_permission, or anything it calls, will use stale branch
 * information.
 */
static int unionfs_permission(struct inode *inode, int mask,
			      struct nameidata *nd)
{
	struct inode *lower_inode = NULL;
	int err = 0;
	int bindex, bstart, bend;
	const int is_file = !S_ISDIR(inode->i_mode);
	const int write_mask = (mask & MAY_WRITE) && !(mask & MAY_READ);

	if (nd)
		unionfs_lock_dentry(nd->dentry, UNIONFS_DMUTEX_CHILD);

	if (!UNIONFS_I(inode)->lower_inodes) {
		if (is_file)	/* dirs can be unlinked but chdir'ed to */
			err = -ESTALE;	/* force revalidate */
		goto out;
	}
	bstart = ibstart(inode);
	bend = ibend(inode);
	if (unlikely(bstart < 0 || bend < 0)) {
		/*
		 * With branch-management, we can get a stale inode here.
		 * If so, we return ESTALE back to link_path_walk, which
		 * would discard the dcache entry and re-lookup the
		 * dentry+inode.  This should be equivalent to issuing
		 * __unionfs_d_revalidate_chain on nd.dentry here.
		 */
		if (is_file)	/* dirs can be unlinked but chdir'ed to */
			err = -ESTALE;	/* force revalidate */
		goto out;
	}

	for (bindex = bstart; bindex <= bend; bindex++) {
		lower_inode = unionfs_lower_inode_idx(inode, bindex);
		if (!lower_inode)
			continue;

		/*
		 * check the condition for D-F-D underlying files/directories,
		 * we don't have to check for files, if we are checking for
		 * directories.
		 */
		if (!is_file && !S_ISDIR(lower_inode->i_mode))
			continue;

		/*
		 * We check basic permissions, but we ignore any conditions
		 * such as readonly file systems or branches marked as
		 * readonly, because those conditions should lead to a
		 * copyup taking place later on.
		 */
		err = permission(lower_inode, mask, nd);
		if (err && bindex > 0) {
			umode_t mode = lower_inode->i_mode;
			if (is_robranch_super(inode->i_sb, bindex) &&
			    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
				err = 0;
			if (IS_COPYUP_ERR(err))
				err = 0;
		}

		/*
		 * The permissions are an intersection of the overall directory
		 * permissions, so we fail if one fails.
		 */
		if (err)
			goto out;

		/* only the leftmost file matters. */
		if (is_file || write_mask) {
			if (is_file && write_mask) {
				err = get_write_access(lower_inode);
				if (!err)
					put_write_access(lower_inode);
			}
			break;
		}
	}
	/* sync times which may have changed (asynchronously) below */
	unionfs_copy_attr_times(inode);

out:
	unionfs_check_inode(inode);
	unionfs_check_nd(nd);
	if (nd)
		unionfs_unlock_dentry(nd->dentry);
	return err;
}

static int unionfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	int bstart, bend, bindex;
	loff_t size;

	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);

	if (unlikely(!__unionfs_d_revalidate_chain(dentry, NULL, false))) {
		err = -ESTALE;
		goto out;
	}

	bstart = dbstart(dentry);
	bend = dbend(dentry);
	inode = dentry->d_inode;

	/*
	 * mode change is for clearing setuid/setgid. Allow lower filesystem
	 * to reinterpret it in its own way.
	 */
	if (ia->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		ia->ia_valid &= ~ATTR_MODE;

	lower_dentry = unionfs_lower_dentry(dentry);
	BUG_ON(!lower_dentry);	/* should never happen after above revalidate */

	/* copyup if the file is on a read only branch */
	if (is_robranch_super(dentry->d_sb, bstart)
	    || IS_RDONLY(lower_dentry->d_inode)) {
		/* check if we have a branch to copy up to */
		if (bstart <= 0) {
			err = -EACCES;
			goto out;
		}

		if (ia->ia_valid & ATTR_SIZE)
			size = ia->ia_size;
		else
			size = i_size_read(inode);
		/* copyup to next available branch */
		for (bindex = bstart - 1; bindex >= 0; bindex--) {
			err = copyup_dentry(dentry->d_parent->d_inode,
					    dentry, bstart, bindex,
					    dentry->d_name.name,
					    dentry->d_name.len,
					    NULL, size);
			if (!err)
				break;
		}
		if (err)
			goto out;
		/* get updated lower_dentry after copyup */
		lower_dentry = unionfs_lower_dentry(dentry);
	}

	lower_inode = unionfs_lower_inode(inode);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		size = i_size_read(inode);
		if (ia->ia_size < size || (ia->ia_size > size &&
		    inode->i_sb->s_maxbytes < lower_inode->i_sb->s_maxbytes)) {
			err = vmtruncate(inode, ia->ia_size);
			if (err)
				goto out;
		}
	}

	/* notify the (possibly copied-up) lower inode */
	err = notify_change(lower_dentry, ia);
	if (err)
		goto out;

	/* get attributes from the first lower inode */
	unionfs_copy_attr_all(inode, lower_inode);
	/*
	 * unionfs_copy_attr_all will copy the lower times to our inode if
	 * the lower ones are newer (useful for cache coherency).  However,
	 * ->setattr is the only place in which we may have to copy the
	 * lower inode times absolutely, to support utimes(2).
	 */
	if (ia->ia_valid & ATTR_MTIME_SET)
		inode->i_mtime = lower_inode->i_mtime;
	if (ia->ia_valid & ATTR_CTIME)
		inode->i_ctime = lower_inode->i_ctime;
	if (ia->ia_valid & ATTR_ATIME_SET)
		inode->i_atime = lower_inode->i_atime;
	fsstack_copy_inode_size(inode, lower_inode);

out:
	if (!err)
		unionfs_check_dentry(dentry);
	unionfs_unlock_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);

	return err;
}

struct inode_operations unionfs_symlink_iops = {
	.readlink	= unionfs_readlink,
	.permission	= unionfs_permission,
	.follow_link	= unionfs_follow_link,
	.setattr	= unionfs_setattr,
	.put_link	= unionfs_put_link,
};

struct inode_operations unionfs_dir_iops = {
	.create		= unionfs_create,
	.lookup		= unionfs_lookup,
	.link		= unionfs_link,
	.unlink		= unionfs_unlink,
	.symlink	= unionfs_symlink,
	.mkdir		= unionfs_mkdir,
	.rmdir		= unionfs_rmdir,
	.mknod		= unionfs_mknod,
	.rename		= unionfs_rename,
	.permission	= unionfs_permission,
	.setattr	= unionfs_setattr,
#ifdef CONFIG_UNION_FS_XATTR
	.setxattr	= unionfs_setxattr,
	.getxattr	= unionfs_getxattr,
	.removexattr	= unionfs_removexattr,
	.listxattr	= unionfs_listxattr,
#endif /* CONFIG_UNION_FS_XATTR */
};

struct inode_operations unionfs_main_iops = {
	.permission	= unionfs_permission,
	.setattr	= unionfs_setattr,
#ifdef CONFIG_UNION_FS_XATTR
	.setxattr	= unionfs_setxattr,
	.getxattr	= unionfs_getxattr,
	.removexattr	= unionfs_removexattr,
	.listxattr	= unionfs_listxattr,
#endif /* CONFIG_UNION_FS_XATTR */
};
