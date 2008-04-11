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

static int realloc_dentry_private_data(struct dentry *dentry);

/* is the filename valid == !(whiteout for a file or opaque dir marker) */
static int is_validname(const char *name)
{
	if (!strncmp(name, UNIONFS_WHPFX, UNIONFS_WHLEN))
		return 0;
	if (!strncmp(name, UNIONFS_DIR_OPAQUE_NAME,
		     sizeof(UNIONFS_DIR_OPAQUE_NAME) - 1))
		return 0;
	return 1;
}

/* The rest of these are utility functions for lookup. */
static noinline_for_stack int is_opaque_dir(struct dentry *dentry, int bindex)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *wh_lower_dentry;
	struct inode *lower_inode;
	struct sioq_args args;

	lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
	lower_inode = lower_dentry->d_inode;

	BUG_ON(!S_ISDIR(lower_inode->i_mode));

	mutex_lock(&lower_inode->i_mutex);

	if (!permission(lower_inode, MAY_EXEC, NULL)) {
		wh_lower_dentry =
			lookup_one_len(UNIONFS_DIR_OPAQUE, lower_dentry,
				       sizeof(UNIONFS_DIR_OPAQUE) - 1);
	} else {
		args.is_opaque.dentry = lower_dentry;
		run_sioq(__is_opaque_dir, &args);
		wh_lower_dentry = args.ret;
	}

	mutex_unlock(&lower_inode->i_mutex);

	if (IS_ERR(wh_lower_dentry)) {
		err = PTR_ERR(wh_lower_dentry);
		goto out;
	}

	/* This is an opaque dir iff wh_lower_dentry is positive */
	err = !!wh_lower_dentry->d_inode;

	dput(wh_lower_dentry);
out:
	return err;
}

/*
 * Main (and complex) driver function for Unionfs's lookup
 *
 * Returns: NULL (ok), ERR_PTR if an error occurred, or a non-null non-error
 * PTR if d_splice returned a different dentry.
 *
 * If lookupmode is INTERPOSE_PARTIAL/REVAL/REVAL_NEG, the passed dentry's
 * inode info must be locked.  If lookupmode is INTERPOSE_LOOKUP (i.e., a
 * newly looked-up dentry), then unionfs_lookup_backend will return a locked
 * dentry's info, which the caller must unlock.
 */
struct dentry *unionfs_lookup_backend(struct dentry *dentry,
				      struct nameidata *nd, int lookupmode)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *wh_lower_dentry = NULL;
	struct dentry *lower_dir_dentry = NULL;
	struct dentry *parent_dentry = NULL;
	struct dentry *d_interposed = NULL;
	int bindex, bstart = -1, bend, bopaque;
	int dentry_count = 0;	/* Number of positive dentries. */
	int first_dentry_offset = -1; /* -1 is uninitialized */
	struct dentry *first_dentry = NULL;
	struct dentry *first_lower_dentry = NULL;
	struct vfsmount *first_lower_mnt = NULL;
	int opaque;
	char *whname = NULL;
	const char *name;
	int namelen;

	/*
	 * We should already have a lock on this dentry in the case of a
	 * partial lookup, or a revalidation. Otherwise it is returned from
	 * new_dentry_private_data already locked.
	 */
	if (lookupmode == INTERPOSE_PARTIAL || lookupmode == INTERPOSE_REVAL ||
	    lookupmode == INTERPOSE_REVAL_NEG)
		verify_locked(dentry);
	else			/* this could only be INTERPOSE_LOOKUP */
		BUG_ON(UNIONFS_D(dentry) != NULL);

	switch (lookupmode) {
	case INTERPOSE_PARTIAL:
		break;
	case INTERPOSE_LOOKUP:
		err = new_dentry_private_data(dentry, UNIONFS_DMUTEX_CHILD);
		if (unlikely(err))
			goto out;
		break;
	default:
		/* default: can only be INTERPOSE_REVAL/REVAL_NEG */
		err = realloc_dentry_private_data(dentry);
		if (unlikely(err))
			goto out;
		break;
	}

	/* must initialize dentry operations */
	dentry->d_op = &unionfs_dops;

	parent_dentry = dget_parent(dentry);
	/* We never partial lookup the root directory. */
	if (parent_dentry == dentry) {
		dput(parent_dentry);
		parent_dentry = NULL;
		goto out;
	}

	name = dentry->d_name.name;
	namelen = dentry->d_name.len;

	/* No dentries should get created for possible whiteout names. */
	if (!is_validname(name)) {
		err = -EPERM;
		goto out_free;
	}

	/* Now start the actual lookup procedure. */
	bstart = dbstart(parent_dentry);
	bend = dbend(parent_dentry);
	bopaque = dbopaque(parent_dentry);
	BUG_ON(bstart < 0);

	/*
	 * It would be ideal if we could convert partial lookups to only have
	 * to do this work when they really need to.  It could probably improve
	 * performance quite a bit, and maybe simplify the rest of the code.
	 */
	if (lookupmode == INTERPOSE_PARTIAL) {
		bstart++;
		if ((bopaque != -1) && (bopaque < bend))
			bend = bopaque;
	}

	for (bindex = bstart; bindex <= bend; bindex++) {
		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
		if (lookupmode == INTERPOSE_PARTIAL && lower_dentry)
			continue;
		BUG_ON(lower_dentry != NULL);

		lower_dir_dentry =
			unionfs_lower_dentry_idx(parent_dentry, bindex);

		/* if the parent lower dentry does not exist skip this */
		if (!(lower_dir_dentry && lower_dir_dentry->d_inode))
			continue;

		/* also skip it if the parent isn't a directory. */
		if (!S_ISDIR(lower_dir_dentry->d_inode->i_mode))
			continue;

		/* Reuse the whiteout name because its value doesn't change. */
		if (!whname) {
			whname = alloc_whname(name, namelen);
			if (unlikely(IS_ERR(whname))) {
				err = PTR_ERR(whname);
				goto out_free;
			}
		}

		/* check if whiteout exists in this branch: lookup .wh.foo */
		wh_lower_dentry = lookup_one_len(whname, lower_dir_dentry,
						 namelen + UNIONFS_WHLEN);
		if (IS_ERR(wh_lower_dentry)) {
			dput(first_lower_dentry);
			unionfs_mntput(first_dentry, first_dentry_offset);
			err = PTR_ERR(wh_lower_dentry);
			goto out_free;
		}

		if (wh_lower_dentry->d_inode) {
			/* We found a whiteout so let's give up. */
			if (S_ISREG(wh_lower_dentry->d_inode->i_mode)) {
				set_dbend(dentry, bindex);
				set_dbopaque(dentry, bindex);
				dput(wh_lower_dentry);
				break;
			}
			err = -EIO;
			printk(KERN_ERR "unionfs: EIO: invalid whiteout "
			       "entry type %d\n",
			       wh_lower_dentry->d_inode->i_mode);
			dput(wh_lower_dentry);
			dput(first_lower_dentry);
			unionfs_mntput(first_dentry, first_dentry_offset);
			goto out_free;
		}

		dput(wh_lower_dentry);
		wh_lower_dentry = NULL;

		/* Now do regular lookup; lookup foo */
		BUG_ON(!lower_dir_dentry);
		lower_dentry = lookup_one_len(name, lower_dir_dentry, namelen);
		if (IS_ERR(lower_dentry)) {
			dput(first_lower_dentry);
			unionfs_mntput(first_dentry, first_dentry_offset);
			err = PTR_ERR(lower_dentry);
			goto out_free;
		}

		/*
		 * Store the first negative dentry specially, because if they
		 * are all negative we need this for future creates.
		 */
		if (!lower_dentry->d_inode) {
			if (!first_lower_dentry && (dbstart(dentry) == -1)) {
				first_lower_dentry = lower_dentry;
				/*
				 * FIXME: following line needs to be changed
				 * to allow mount-point crossing
				 */
				first_dentry = parent_dentry;
				first_lower_mnt =
					unionfs_mntget(parent_dentry, bindex);
				first_dentry_offset = bindex;
			} else {
				dput(lower_dentry);
			}

			continue;
		}

		/*
		 * If we already found at least one positive dentry
		 * (dentry_count is non-zero), then we skip all remaining
		 * positive dentries if their type is a non-dir.  This is
		 * because only directories are allowed to stack on multiple
		 * branches, but we have to skip non-dirs (to avoid, say,
		 * calling readdir on a regular file).
		 */
		if ((lookupmode != INTERPOSE_PARTIAL) &&
		    !S_ISDIR(lower_dentry->d_inode->i_mode) &&
		    dentry_count) {
			dput(lower_dentry);
			continue;
		}

		/* number of positive dentries */
		dentry_count++;

		/* store underlying dentry */
		if (dbstart(dentry) == -1)
			set_dbstart(dentry, bindex);
		unionfs_set_lower_dentry_idx(dentry, bindex, lower_dentry);
		/*
		 * FIXME: the following line needs to get fixed to allow
		 * mount-point crossing
		 */
		unionfs_set_lower_mnt_idx(dentry, bindex,
					  unionfs_mntget(parent_dentry,
							 bindex));
		set_dbend(dentry, bindex);

		/* update parent directory's atime with the bindex */
		fsstack_copy_attr_atime(parent_dentry->d_inode,
					lower_dir_dentry->d_inode);

		/* We terminate file lookups here. */
		if (!S_ISDIR(lower_dentry->d_inode->i_mode)) {
			if (lookupmode == INTERPOSE_PARTIAL)
				continue;
			if (dentry_count == 1)
				goto out_positive;
		}

		opaque = is_opaque_dir(dentry, bindex);
		if (opaque < 0) {
			dput(first_lower_dentry);
			unionfs_mntput(first_dentry, first_dentry_offset);
			err = opaque;
			goto out_free;
		} else if (opaque) {
			set_dbend(dentry, bindex);
			set_dbopaque(dentry, bindex);
			break;
		}
	}

	if (dentry_count)
		goto out_positive;
	else
		goto out_negative;

out_negative:
	if (lookupmode == INTERPOSE_PARTIAL)
		goto out;

	/* If we've only got negative dentries, then use the leftmost one. */
	if (lookupmode == INTERPOSE_REVAL) {
		if (dentry->d_inode)
			UNIONFS_I(dentry->d_inode)->stale = 1;
		goto out;
	}
	if (!lower_dir_dentry) {
		err = -ENOENT;
		goto out;
	}
	/* This should only happen if we found a whiteout. */
	if (first_dentry_offset == -1) {
		first_lower_dentry = lookup_one_len(name, lower_dir_dentry,
						    namelen);
		first_dentry_offset = bindex;
		if (IS_ERR(first_lower_dentry)) {
			err = PTR_ERR(first_lower_dentry);
			goto out;
		}

		/*
		 * FIXME: the following line needs to be changed to allow
		 * mount-point crossing
		 */
		first_dentry = dentry;
		first_lower_mnt = unionfs_mntget(dentry->d_sb->s_root,
						 bindex);
	}
	unionfs_set_lower_dentry_idx(dentry, first_dentry_offset,
				     first_lower_dentry);
	unionfs_set_lower_mnt_idx(dentry, first_dentry_offset,
				  first_lower_mnt);
	set_dbstart(dentry, first_dentry_offset);
	set_dbend(dentry, first_dentry_offset);

	if (lookupmode == INTERPOSE_REVAL_NEG)
		BUG_ON(dentry->d_inode != NULL);
	else
		d_add(dentry, NULL);
	goto out;

/* This part of the code is for positive dentries. */
out_positive:
	BUG_ON(dentry_count <= 0);

	/*
	 * If we're holding onto the first negative dentry & corresponding
	 * vfsmount - throw it out.
	 */
	dput(first_lower_dentry);
	unionfs_mntput(first_dentry, first_dentry_offset);

	/* Partial lookups need to re-interpose, or throw away older negs. */
	if (lookupmode == INTERPOSE_PARTIAL) {
		if (dentry->d_inode) {
			unionfs_reinterpose(dentry);
			goto out;
		}

		/*
		 * This somehow turned positive, so it is as if we had a
		 * negative revalidation.
		 */
		lookupmode = INTERPOSE_REVAL_NEG;

		update_bstart(dentry);
		bstart = dbstart(dentry);
		bend = dbend(dentry);
	}

	/*
	 * Interpose can return a dentry if d_splice returned a different
	 * dentry.
	 */
	d_interposed = unionfs_interpose(dentry, dentry->d_sb, lookupmode);
	if (IS_ERR(d_interposed))
		err = PTR_ERR(d_interposed);
	else if (d_interposed)
		dentry = d_interposed;

	if (err)
		goto out_drop;

	goto out;

out_drop:
	d_drop(dentry);

out_free:
	/* should dput all the underlying dentries on error condition */
	bstart = dbstart(dentry);
	if (bstart >= 0) {
		bend = dbend(dentry);
		for (bindex = bstart; bindex <= bend; bindex++) {
			dput(unionfs_lower_dentry_idx(dentry, bindex));
			unionfs_mntput(dentry, bindex);
		}
	}
	kfree(UNIONFS_D(dentry)->lower_paths);
	UNIONFS_D(dentry)->lower_paths = NULL;
	set_dbstart(dentry, -1);
	set_dbend(dentry, -1);

out:
	if (!err && UNIONFS_D(dentry)) {
		BUG_ON(dbend(dentry) > UNIONFS_D(dentry)->bcount);
		BUG_ON(dbend(dentry) > sbmax(dentry->d_sb));
		if (dbstart(dentry) < 0 &&
		    dentry->d_inode && bstart >= 0 &&
		    (!UNIONFS_I(dentry->d_inode) ||
		     !UNIONFS_I(dentry->d_inode)->lower_inodes)) {
			unionfs_mntput(dentry->d_sb->s_root, bstart);
			dput(first_lower_dentry);
			UNIONFS_I(dentry->d_inode)->stale = 1;
		}
	}
	kfree(whname);
	dput(parent_dentry);
	if (err && (lookupmode == INTERPOSE_LOOKUP))
		unionfs_unlock_dentry(dentry);
	if (!err && d_interposed)
		return d_interposed;
	if (dentry->d_inode && UNIONFS_I(dentry->d_inode)->stale &&
	    first_dentry_offset >= 0)
		unionfs_mntput(dentry->d_sb->s_root, first_dentry_offset);
	return ERR_PTR(err);
}

/*
 * This is a utility function that fills in a unionfs dentry.
 * Caller must lock this dentry with unionfs_lock_dentry.
 *
 * Returns: 0 (ok), or -ERRNO if an error occurred.
 */
int unionfs_partial_lookup(struct dentry *dentry)
{
	struct dentry *tmp;
	struct nameidata nd = { .flags = 0 };
	int err = -ENOSYS;

	tmp = unionfs_lookup_backend(dentry, &nd, INTERPOSE_PARTIAL);
	if (!tmp) {
		err = 0;
		goto out;
	}
	if (IS_ERR(tmp)) {
		err = PTR_ERR(tmp);
		goto out;
	}
	/* need to change the interface */
	BUG_ON(tmp != dentry);
out:
	return err;
}

/* The dentry cache is just so we have properly sized dentries. */
static struct kmem_cache *unionfs_dentry_cachep;
int unionfs_init_dentry_cache(void)
{
	unionfs_dentry_cachep =
		kmem_cache_create("unionfs_dentry",
				  sizeof(struct unionfs_dentry_info),
				  0, SLAB_RECLAIM_ACCOUNT, NULL);

	return (unionfs_dentry_cachep ? 0 : -ENOMEM);
}

void unionfs_destroy_dentry_cache(void)
{
	if (unionfs_dentry_cachep)
		kmem_cache_destroy(unionfs_dentry_cachep);
}

void free_dentry_private_data(struct dentry *dentry)
{
	if (!dentry || !dentry->d_fsdata)
		return;
	kmem_cache_free(unionfs_dentry_cachep, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

static inline int __realloc_dentry_private_data(struct dentry *dentry)
{
	struct unionfs_dentry_info *info = UNIONFS_D(dentry);
	void *p;
	int size;

	BUG_ON(!info);

	size = sizeof(struct path) * sbmax(dentry->d_sb);
	p = krealloc(info->lower_paths, size, GFP_ATOMIC);
	if (unlikely(!p))
		return -ENOMEM;

	info->lower_paths = p;

	info->bstart = -1;
	info->bend = -1;
	info->bopaque = -1;
	info->bcount = sbmax(dentry->d_sb);
	atomic_set(&info->generation,
			atomic_read(&UNIONFS_SB(dentry->d_sb)->generation));

	memset(info->lower_paths, 0, size);

	return 0;
}

/* UNIONFS_D(dentry)->lock must be locked */
static int realloc_dentry_private_data(struct dentry *dentry)
{
	if (!__realloc_dentry_private_data(dentry))
		return 0;

	kfree(UNIONFS_D(dentry)->lower_paths);
	free_dentry_private_data(dentry);
	return -ENOMEM;
}

/* allocate new dentry private data */
int new_dentry_private_data(struct dentry *dentry, int subclass)
{
	struct unionfs_dentry_info *info = UNIONFS_D(dentry);

	BUG_ON(info);

	info = kmem_cache_alloc(unionfs_dentry_cachep, GFP_ATOMIC);
	if (unlikely(!info))
		return -ENOMEM;

	mutex_init(&info->lock);
	mutex_lock_nested(&info->lock, subclass);

	info->lower_paths = NULL;

	dentry->d_fsdata = info;

	if (!__realloc_dentry_private_data(dentry))
		return 0;

	mutex_unlock(&info->lock);
	free_dentry_private_data(dentry);
	return -ENOMEM;
}

/*
 * scan through the lower dentry objects, and set bstart to reflect the
 * starting branch
 */
void update_bstart(struct dentry *dentry)
{
	int bindex;
	int bstart = dbstart(dentry);
	int bend = dbend(dentry);
	struct dentry *lower_dentry;

	for (bindex = bstart; bindex <= bend; bindex++) {
		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry)
			continue;
		if (lower_dentry->d_inode) {
			set_dbstart(dentry, bindex);
			break;
		}
		dput(lower_dentry);
		unionfs_set_lower_dentry_idx(dentry, bindex, NULL);
	}
}


/*
 * Initialize a nameidata structure (the intent part) we can pass to a lower
 * file system.  Returns 0 on success or -error (only -ENOMEM possible).
 * Inside that nd structure, this function may also return an allocated
 * struct file (for open intents).  The caller, when done with this nd, must
 * kfree the intent file (using release_lower_nd).
 *
 * XXX: this code, and the callers of this code, should be redone using
 * vfs_path_lookup() when (1) the nameidata structure is refactored into a
 * separate intent-structure, and (2) open_namei() is broken into a VFS-only
 * function and a method that other file systems can call.
 */
int init_lower_nd(struct nameidata *nd, unsigned int flags)
{
	int err = 0;
#ifdef ALLOC_LOWER_ND_FILE
	/*
	 * XXX: one day we may need to have the lower return an open file
	 * for us.  It is not needed in 2.6.23-rc1 for nfs2/nfs3, but may
	 * very well be needed for nfs4.
	 */
	struct file *file;
#endif /* ALLOC_LOWER_ND_FILE */

	memset(nd, 0, sizeof(struct nameidata));
	if (!flags)
		return err;

	switch (flags) {
	case LOOKUP_CREATE:
		nd->intent.open.flags |= O_CREAT;
		/* fall through: shared code for create/open cases */
	case LOOKUP_OPEN:
		nd->flags = flags;
		nd->intent.open.flags |= (FMODE_READ | FMODE_WRITE);
#ifdef ALLOC_LOWER_ND_FILE
		file = kzalloc(sizeof(struct file), GFP_KERNEL);
		if (unlikely(!file)) {
			err = -ENOMEM;
			break; /* exit switch statement and thus return */
		}
		nd->intent.open.file = file;
#endif /* ALLOC_LOWER_ND_FILE */
		break;
	case LOOKUP_ACCESS:
		nd->flags = flags;
		break;
	default:
		/*
		 * We should never get here, for now.
		 * We can add new cases here later on.
		 */
		pr_debug("unionfs: unknown nameidata flag 0x%x\n", flags);
		BUG();
		break;
	}

	return err;
}

void release_lower_nd(struct nameidata *nd, int err)
{
	if (!nd->intent.open.file)
		return;
	else if (!err)
		release_open_intent(nd);
#ifdef ALLOC_LOWER_ND_FILE
	kfree(nd->intent.open.file);
#endif /* ALLOC_LOWER_ND_FILE */
}
