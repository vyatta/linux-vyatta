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

static int unionfs_create(struct inode *parent, struct dentry *dentry,
			  int mode, struct nameidata *nd)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *wh_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	char *name = NULL;
	int valid = 0;
	struct nameidata lower_nd;

	unionfs_read_lock(dentry->d_sb);
	unionfs_lock_dentry(dentry);

	unionfs_lock_dentry(dentry->d_parent);
	valid = __unionfs_d_revalidate_chain(dentry->d_parent, nd, false);
	unionfs_unlock_dentry(dentry->d_parent);
	if (unlikely(!valid)) {
		err = -ESTALE;	/* same as what real_lookup does */
		goto out;
	}
	valid = __unionfs_d_revalidate_chain(dentry, nd, false);
	/*
	 * It's only a bug if this dentry was not negative and couldn't be
	 * revalidated (shouldn't happen).
	 */
	BUG_ON(!valid && dentry->d_inode);

	/*
	 * We shouldn't create things in a read-only branch; this check is a
	 * bit redundant as we don't allow branch 0 to be read-only at the
	 * moment
	 */
	err = is_robranch_super(dentry->d_sb, 0);
	if (err) {
		err = -EROFS;
		goto out;
	}

	/*
	 * We _always_ create on branch 0
	 */
	lower_dentry = unionfs_lower_dentry_idx(dentry, 0);
	if (lower_dentry) {
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

		if (wh_dentry->d_inode) {
			/*
			 * .wh.foo has been found, so let's unlink it
			 */
			struct dentry *lower_dir_dentry;

			lower_dir_dentry = lock_parent(wh_dentry);
			err = vfs_unlink(lower_dir_dentry->d_inode, wh_dentry);
			unlock_dir(lower_dir_dentry);

			if (err) {
				printk(KERN_ERR "unionfs: create: could not "
				       "unlink whiteout, err = %d\n", err);
				goto out;
			}
		}
	} else {
		/*
		 * if lower_dentry is NULL, create the entire
		 * dentry directory structure in branch 0.
		 */
		lower_dentry = create_parents(parent, dentry,
					      dentry->d_name.name, 0);
		if (IS_ERR(lower_dentry)) {
			err = PTR_ERR(lower_dentry);
			goto out;
		}
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
	dput(wh_dentry);
	kfree(name);

	if (!err)
		unionfs_postcopyup_setmnt(dentry);
	unionfs_unlock_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);

	unionfs_check_inode(parent);
	if (!err) {
		unionfs_check_dentry(dentry->d_parent);
		unionfs_check_nd(nd);
	}
	unionfs_check_dentry(dentry);
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
	struct path path_save;
	struct dentry *ret;

	unionfs_read_lock(dentry->d_sb);

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
		/* parent times may have changed */
		unionfs_copy_attr_times(dentry->d_parent->d_inode);
		unionfs_unlock_dentry(dentry);
	}

	unionfs_check_inode(parent);
	unionfs_check_dentry(dentry);
	unionfs_check_dentry(dentry->d_parent);
	unionfs_check_nd(nd);
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

	unionfs_read_lock(old_dentry->d_sb);
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
		lower_dir_dentry = lock_parent(whiteout_dentry);
		err = is_robranch_super(new_dentry->d_sb, dbstart(new_dentry));
		if (!err)
			err = vfs_unlink(lower_dir_dentry->d_inode,
					 whiteout_dentry);

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
	if (!err)
		err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
			       lower_new_dentry);
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
					    old_dentry->d_inode->i_size);
			if (!err) {
				lower_new_dentry =
					create_parents(dir, new_dentry,
						       new_dentry->d_name.name,
						       bindex);
				lower_old_dentry =
					unionfs_lower_dentry(old_dentry);
				lower_dir_dentry =
					lock_parent(lower_new_dentry);
				/* do vfs_link */
				err = vfs_link(lower_old_dentry,
					       lower_dir_dentry->d_inode,
					       lower_new_dentry);
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

	unionfs_unlock_dentry(new_dentry);
	unionfs_unlock_dentry(old_dentry);

	unionfs_check_inode(dir);
	unionfs_check_dentry(new_dentry);
	unionfs_check_dentry(old_dentry);
	unionfs_read_unlock(old_dentry->d_sb);

	return err;
}

static int unionfs_symlink(struct inode *dir, struct dentry *dentry,
			   const char *symname)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *whiteout_dentry = NULL;
	struct dentry *lower_dir_dentry = NULL;
	umode_t mode;
	int bindex = 0, bstart;
	char *name = NULL;

	unionfs_read_lock(dentry->d_sb);
	unionfs_lock_dentry(dentry);

	if (unlikely(dentry->d_inode &&
		     !__unionfs_d_revalidate_chain(dentry, NULL, false))) {
		err = -ESTALE;
		goto out;
	}

	/* We start out in the leftmost branch. */
	bstart = dbstart(dentry);

	lower_dentry = unionfs_lower_dentry(dentry);

	/*
	 * check if whiteout exists in this branch, i.e. lookup .wh.foo
	 * first. If present, delete it
	 */
	name = alloc_whname(dentry->d_name.name, dentry->d_name.len);
	if (unlikely(IS_ERR(name))) {
		err = PTR_ERR(name);
		goto out;
	}

	whiteout_dentry =
		lookup_one_len(name, lower_dentry->d_parent,
			       dentry->d_name.len + UNIONFS_WHLEN);
	if (IS_ERR(whiteout_dentry)) {
		err = PTR_ERR(whiteout_dentry);
		goto out;
	}

	if (!whiteout_dentry->d_inode) {
		dput(whiteout_dentry);
		whiteout_dentry = NULL;
	} else {
		/*
		 * found a .wh.foo entry, unlink it and then call
		 * vfs_symlink().
		 */
		lower_dir_dentry = lock_parent(whiteout_dentry);

		err = is_robranch_super(dentry->d_sb, bstart);
		if (!err)
			err = vfs_unlink(lower_dir_dentry->d_inode,
					 whiteout_dentry);
		dput(whiteout_dentry);

		fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
		/* propagate number of hard-links */
		dir->i_nlink = unionfs_get_nlinks(dir);

		unlock_dir(lower_dir_dentry);

		if (err) {
			/* exit if the error returned was NOT -EROFS */
			if (!IS_COPYUP_ERR(err))
				goto out;
			/*
			 * should now try to create symlink in the another
			 * branch.
			 */
			bstart--;
		}
	}

	/*
	 * deleted whiteout if it was present, now do a normal vfs_symlink()
	 * with possible recursive directory creation
	 */
	for (bindex = bstart; bindex >= 0; bindex--) {
		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry) {
			/*
			 * if lower_dentry is NULL, create the entire
			 * dentry directory structure in branch 'bindex'.
			 * lower_dentry will NOT be null when bindex ==
			 * bstart because lookup passed as a negative
			 * unionfs dentry pointing to a lone negative
			 * underlying dentry
			 */
			lower_dentry = create_parents(dir, dentry,
						      dentry->d_name.name,
						      bindex);
			if (!lower_dentry || IS_ERR(lower_dentry)) {
				if (IS_ERR(lower_dentry))
					err = PTR_ERR(lower_dentry);

				printk(KERN_ERR "unionfs: lower dentry "
				       "NULL (or error) for bindex = %d\n",
				       bindex);
				continue;
			}
		}

		lower_dir_dentry = lock_parent(lower_dentry);

		err = is_robranch_super(dentry->d_sb, bindex);
		if (!err) {
			mode = S_IALLUGO;
			err = vfs_symlink(lower_dir_dentry->d_inode,
					  lower_dentry, symname, mode);
		}
		unlock_dir(lower_dir_dentry);

		if (err || !lower_dentry->d_inode) {
			/*
			 * break out of for loop if error returned was NOT
			 * -EROFS.
			 */
			if (!IS_COPYUP_ERR(err))
				break;
		} else {
			/*
			 * Only INTERPOSE_LOOKUP can return a value other
			 * than 0 on err.
			 */
			err = PTR_ERR(unionfs_interpose(dentry,
							dir->i_sb, 0));
			if (!err) {
				fsstack_copy_attr_times(dir,
							lower_dir_dentry->
							d_inode);
				fsstack_copy_inode_size(dir,
							lower_dir_dentry->
							d_inode);
				/*
				 * update number of links on parent
				 * directory.
				 */
				dir->i_nlink = unionfs_get_nlinks(dir);
			}
			break;
		}
	}

out:
	if (!dentry->d_inode)
		d_drop(dentry);

	kfree(name);
	if (!err)
		unionfs_postcopyup_setmnt(dentry);
	unionfs_unlock_dentry(dentry);

	unionfs_check_inode(dir);
	unionfs_check_dentry(dentry);
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

	unionfs_read_lock(dentry->d_sb);
	unionfs_lock_dentry(dentry);

	if (unlikely(dentry->d_inode &&
		     !__unionfs_d_revalidate_chain(dentry, NULL, false))) {
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
		lower_parent_dentry = lock_parent(whiteout_dentry);

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

	if (!err)
		unionfs_copy_attr_times(dentry->d_inode);
	unionfs_unlock_dentry(dentry);
	unionfs_check_inode(parent);
	unionfs_check_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);

	return err;
}

static int unionfs_mknod(struct inode *dir, struct dentry *dentry, int mode,
			 dev_t dev)
{
	int err = 0;
	struct dentry *lower_dentry = NULL, *whiteout_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	int bindex = 0, bstart;
	char *name = NULL;
	int whiteout_unlinked = 0;

	unionfs_read_lock(dentry->d_sb);
	unionfs_lock_dentry(dentry);

	if (unlikely(dentry->d_inode &&
		     !__unionfs_d_revalidate_chain(dentry, NULL, false))) {
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
		/* found .wh.foo, unlink it */
		lower_parent_dentry = lock_parent(whiteout_dentry);

		/* found a.wh.foo entry, remove it then do vfs_mkdir */
		err = is_robranch_super(dentry->d_sb, bstart);
		if (!err)
			err = vfs_unlink(lower_parent_dentry->d_inode,
					 whiteout_dentry);
		dput(whiteout_dentry);

		unlock_dir(lower_parent_dentry);

		if (err) {
			if (!IS_COPYUP_ERR(err))
				goto out;
			bstart--;
		} else {
			whiteout_unlinked = 1;
		}
	}

	for (bindex = bstart; bindex >= 0; bindex--) {
		if (is_robranch_super(dentry->d_sb, bindex))
			continue;

		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry) {
			lower_dentry = create_parents(dir, dentry,
						      dentry->d_name.name,
						      bindex);
			if (IS_ERR(lower_dentry)) {
				printk(KERN_ERR "unionfs: failed to create "
				       "parents on %d, err = %ld\n",
				       bindex, PTR_ERR(lower_dentry));
				continue;
			}
		}

		lower_parent_dentry = lock_parent(lower_dentry);
		if (IS_ERR(lower_parent_dentry)) {
			err = PTR_ERR(lower_parent_dentry);
			goto out;
		}

		err = vfs_mknod(lower_parent_dentry->d_inode,
				lower_dentry, mode, dev);

		if (err) {
			unlock_dir(lower_parent_dentry);
			break;
		}

		/*
		 * Only INTERPOSE_LOOKUP can return a value other than 0 on
		 * err.
		 */
		err = PTR_ERR(unionfs_interpose(dentry, dir->i_sb, 0));
		if (!err) {
			fsstack_copy_attr_times(dir,
						lower_parent_dentry->d_inode);
			fsstack_copy_inode_size(dir,
						lower_parent_dentry->d_inode);
			/* update number of links on parent directory */
			dir->i_nlink = unionfs_get_nlinks(dir);
		}
		unlock_dir(lower_parent_dentry);

		break;
	}

out:
	if (!dentry->d_inode)
		d_drop(dentry);

	kfree(name);

	if (!err)
		unionfs_postcopyup_setmnt(dentry);
	unionfs_unlock_dentry(dentry);

	unionfs_check_inode(dir);
	unionfs_check_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);

	return err;
}

static int unionfs_readlink(struct dentry *dentry, char __user *buf,
			    int bufsiz)
{
	int err;
	struct dentry *lower_dentry;

	unionfs_read_lock(dentry->d_sb);
	unionfs_lock_dentry(dentry);

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
	unionfs_unlock_dentry(dentry);
	unionfs_check_dentry(dentry);
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
 * due to branch management.
 */
static void *unionfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	unionfs_read_lock(dentry->d_sb);

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
	unionfs_check_dentry(dentry);
	unionfs_check_nd(nd);
	unionfs_read_unlock(dentry->d_sb);
	return ERR_PTR(err);
}

/* FIXME: We may not have to lock here */
static void unionfs_put_link(struct dentry *dentry, struct nameidata *nd,
			     void *cookie)
{
	unionfs_read_lock(dentry->d_sb);

	unionfs_lock_dentry(dentry);
	if (unlikely(!__unionfs_d_revalidate_chain(dentry, nd, false)))
		printk(KERN_ERR
		       "unionfs: put_link failed to revalidate dentry\n");
	unionfs_unlock_dentry(dentry);

	unionfs_check_dentry(dentry);
	unionfs_check_nd(nd);
	kfree(nd_get_link(nd));
	unionfs_read_unlock(dentry->d_sb);
}

/*
 * Basically copied from the kernel vfs permission(), but we've changed
 * the following:
 *   (1) the IS_RDONLY check is skipped, and
 *   (2) We return 0 (success) if the non-leftmost branch is mounted
 *       readonly, to allow copyup to work.
 *   (3) we do call security_inode_permission, and therefore security inside
 *       SELinux, etc. are performed.
 *
 * @inode: the lower inode we're checking permission on
 */
static int inode_permission(struct super_block *sb, struct inode *inode,
			    int mask, struct nameidata *nd, int bindex)
{
	int retval, submask;

	if (mask & MAY_WRITE) {
		umode_t mode = inode->i_mode;
		/* The first branch is allowed to be really readonly. */
		if (bindex == 0 &&
		    IS_RDONLY(inode) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;
		/*
		 * Nobody gets write access to an immutable file.
		 */
		if (IS_IMMUTABLE(inode))
			return -EACCES;
		/*
		 * For all other branches than the first one, we ignore
		 * EROFS or if the branch is mounted as readonly, to let
		 * copyup take place.
		 */
		if (bindex > 0 &&
		    is_robranch_super(sb, bindex) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return 0;
	}

	/* Ordinary permission routines do not understand MAY_APPEND. */
	submask = mask & ~MAY_APPEND;
	if (inode->i_op && inode->i_op->permission)
		retval = inode->i_op->permission(inode, submask, nd);
	else
		retval = generic_permission(inode, submask, NULL);

	if (retval && retval != -EROFS)	/* ignore EROFS */
		return retval;

	retval = security_inode_permission(inode, mask, nd);
	return ((retval == -EROFS) ? 0 : retval);	/* ignore EROFS */
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
		 * We use our own special version of permission, such that
		 * only the first branch returns -EROFS.
		 */
		err = inode_permission(inode->i_sb, lower_inode, mask, nd,
				       bindex);

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
	return err;
}

static int unionfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct inode *inode = NULL;
	struct inode *lower_inode = NULL;
	int bstart, bend, bindex;
	int i;
	int copyup = 0;

	unionfs_read_lock(dentry->d_sb);
	unionfs_lock_dentry(dentry);

	if (unlikely(!__unionfs_d_revalidate_chain(dentry, NULL, false))) {
		err = -ESTALE;
		goto out;
	}

	bstart = dbstart(dentry);
	bend = dbend(dentry);
	inode = dentry->d_inode;

	for (bindex = bstart; (bindex <= bend) || (bindex == bstart);
	     bindex++) {
		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry)
			continue;
		BUG_ON(lower_dentry->d_inode == NULL);

		/* If the file is on a read only branch */
		if (is_robranch_super(dentry->d_sb, bindex)
		    || IS_RDONLY(lower_dentry->d_inode)) {
			if (copyup || (bindex != bstart))
				continue;
			/* Only if its the leftmost file, copyup the file */
			for (i = bstart - 1; i >= 0; i--) {
				loff_t size = dentry->d_inode->i_size;
				if (ia->ia_valid & ATTR_SIZE)
					size = ia->ia_size;
				err = copyup_dentry(dentry->d_parent->d_inode,
						    dentry, bstart, i,
						    dentry->d_name.name,
						    dentry->d_name.len,
						    NULL, size);

				if (!err) {
					copyup = 1;
					lower_dentry =
						unionfs_lower_dentry(dentry);
					break;
				}
				/*
				 * if error is in the leftmost branch, pass
				 * it up.
				 */
				if (i == 0)
					goto out;
			}

		}
		err = notify_change(lower_dentry, ia);
		if (err)
			goto out;
		break;
	}

	/* for mmap */
	if (ia->ia_valid & ATTR_SIZE) {
		if (ia->ia_size != i_size_read(inode)) {
			err = vmtruncate(inode, ia->ia_size);
			if (err)
				printk(KERN_ERR
				       "unionfs: setattr: vmtruncate failed\n");
		}
	}

	/* get the size from the first lower inode */
	lower_inode = unionfs_lower_inode(inode);
	unionfs_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);
	/* if setattr succeeded, then parent dir may have changed */
	unionfs_copy_attr_times(dentry->d_parent->d_inode);
out:
	unionfs_unlock_dentry(dentry);
	unionfs_check_dentry(dentry);
	unionfs_check_dentry(dentry->d_parent);
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
