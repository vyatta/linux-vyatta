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


static inline void __dput_lowers(struct dentry *dentry, int start, int end)
{
	struct dentry *lower_dentry;
	int bindex;

	if (start < 0)
		return;
	for (bindex = start; bindex <= end; bindex++) {
		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry)
			continue;
		unionfs_set_lower_dentry_idx(dentry, bindex, NULL);
		dput(lower_dentry);
	}
}

static inline void __iput_lowers(struct inode *inode, int start, int end)
{
	struct inode *lower_inode;
	int bindex;

	if (start < 0)
		return;
	for (bindex = start; bindex <= end; bindex++) {
		lower_inode = unionfs_lower_inode_idx(inode, bindex);
		if (!lower_inode)
			continue;
		unionfs_set_lower_inode_idx(inode, bindex, NULL);
		iput(lower_inode);
	}
}

/*
 * Revalidate a single dentry.
 * Assume that dentry's info node is locked.
 * Assume that parent(s) are all valid already, but
 * the child may not yet be valid.
 * Returns true if valid, false otherwise.
 */
static bool __unionfs_d_revalidate_one(struct dentry *dentry,
				       struct nameidata *nd)
{
	bool valid = true;	/* default is valid */
	struct dentry *lower_dentry;
	int bindex, bstart, bend;
	int sbgen, dgen;
	int positive = 0;
	int interpose_flag;
	struct nameidata lowernd; /* TODO: be gentler to the stack */

	if (nd)
		memcpy(&lowernd, nd, sizeof(struct nameidata));
	else
		memset(&lowernd, 0, sizeof(struct nameidata));

	verify_locked(dentry);
	verify_locked(dentry->d_parent);

	/* if the dentry is unhashed, do NOT revalidate */
	if (d_deleted(dentry))
		goto out;

	BUG_ON(dbstart(dentry) == -1);
	if (dentry->d_inode)
		positive = 1;
	dgen = atomic_read(&UNIONFS_D(dentry)->generation);
	sbgen = atomic_read(&UNIONFS_SB(dentry->d_sb)->generation);
	/*
	 * If we are working on an unconnected dentry, then there is no
	 * revalidation to be done, because this file does not exist within
	 * the namespace, and Unionfs operates on the namespace, not data.
	 */
	if (unlikely(sbgen != dgen)) {
		struct dentry *result;
		int pdgen;

		/* The root entry should always be valid */
		BUG_ON(IS_ROOT(dentry));

		/* We can't work correctly if our parent isn't valid. */
		pdgen = atomic_read(&UNIONFS_D(dentry->d_parent)->generation);
		BUG_ON(pdgen != sbgen);	/* should never happen here */

		/* Free the pointers for our inodes and this dentry. */
		bstart = dbstart(dentry);
		bend = dbend(dentry);
		__dput_lowers(dentry, bstart, bend);
		set_dbstart(dentry, -1);
		set_dbend(dentry, -1);

		interpose_flag = INTERPOSE_REVAL_NEG;
		if (positive) {
			interpose_flag = INTERPOSE_REVAL;

			bstart = ibstart(dentry->d_inode);
			bend = ibend(dentry->d_inode);
			__iput_lowers(dentry->d_inode, bstart, bend);
			kfree(UNIONFS_I(dentry->d_inode)->lower_inodes);
			UNIONFS_I(dentry->d_inode)->lower_inodes = NULL;
			ibstart(dentry->d_inode) = -1;
			ibend(dentry->d_inode) = -1;
		}

		result = unionfs_lookup_backend(dentry, &lowernd,
						interpose_flag);
		if (result) {
			if (IS_ERR(result)) {
				valid = false;
				goto out;
			}
			/*
			 * current unionfs_lookup_backend() doesn't return
			 * a valid dentry
			 */
			dput(dentry);
			dentry = result;
		}

		if (unlikely(positive && UNIONFS_I(dentry->d_inode)->stale)) {
			make_bad_inode(dentry->d_inode);
			d_drop(dentry);
			valid = false;
			goto out;
		}
		goto out;
	}

	/* The revalidation must occur across all branches */
	bstart = dbstart(dentry);
	bend = dbend(dentry);
	BUG_ON(bstart == -1);
	for (bindex = bstart; bindex <= bend; bindex++) {
		lower_dentry = unionfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry || !lower_dentry->d_op
		    || !lower_dentry->d_op->d_revalidate)
			continue;
		/*
		 * Don't pass nameidata to lower file system, because we
		 * don't want an arbitrary lower file being opened or
		 * returned to us: it may be useless to us because of the
		 * fanout nature of unionfs (cf. file/directory open-file
		 * invariants).  We will open lower files as and when needed
		 * later on.
		 */
		if (!lower_dentry->d_op->d_revalidate(lower_dentry, NULL))
			valid = false;
	}

	if (!dentry->d_inode ||
	    ibstart(dentry->d_inode) < 0 ||
	    ibend(dentry->d_inode) < 0) {
		valid = false;
		goto out;
	}

	if (valid) {
		/*
		 * If we get here, and we copy the meta-data from the lower
		 * inode to our inode, then it is vital that we have already
		 * purged all unionfs-level file data.  We do that in the
		 * caller (__unionfs_d_revalidate_chain) by calling
		 * purge_inode_data.
		 */
		unionfs_copy_attr_all(dentry->d_inode,
				      unionfs_lower_inode(dentry->d_inode));
		fsstack_copy_inode_size(dentry->d_inode,
					unionfs_lower_inode(dentry->d_inode));
	}

out:
	return valid;
}

/*
 * Determine if the lower inode objects have changed from below the unionfs
 * inode.  Return true if changed, false otherwise.
 *
 * We check if the mtime or ctime have changed.  However, the inode times
 * can be changed by anyone without much protection, including
 * asynchronously.  This can sometimes cause unionfs to find that the lower
 * file system doesn't change its inode times quick enough, resulting in a
 * false positive indication (which is harmless, it just makes unionfs do
 * extra work in re-validating the objects).  To minimize the chances of
 * these situations, we still consider such small time changes valid, but we
 * don't print debugging messages unless the time changes are greater than
 * UNIONFS_MIN_CC_TIME (which defaults to 3 seconds, as with NFS's acregmin)
 * because significant changes are more likely due to users manually
 * touching lower files.
 */
bool is_newer_lower(const struct dentry *dentry)
{
	int bindex;
	struct inode *inode;
	struct inode *lower_inode;

	/* ignore if we're called on semi-initialized dentries/inodes */
	if (!dentry || !UNIONFS_D(dentry))
		return false;
	inode = dentry->d_inode;
	if (!inode || !UNIONFS_I(inode)->lower_inodes ||
	    ibstart(inode) < 0 || ibend(inode) < 0)
		return false;

	for (bindex = ibstart(inode); bindex <= ibend(inode); bindex++) {
		lower_inode = unionfs_lower_inode_idx(inode, bindex);
		if (!lower_inode)
			continue;

		/* check if mtime/ctime have changed */
		if (unlikely(timespec_compare(&inode->i_mtime,
					      &lower_inode->i_mtime) < 0)) {
			if ((lower_inode->i_mtime.tv_sec -
			     inode->i_mtime.tv_sec) > UNIONFS_MIN_CC_TIME) {
				pr_info("unionfs: new lower inode mtime "
					"(bindex=%d, name=%s)\n", bindex,
					dentry->d_name.name);
				show_dinode_times(dentry);
			}
			return true;
		}
		if (unlikely(timespec_compare(&inode->i_ctime,
					      &lower_inode->i_ctime) < 0)) {
			if ((lower_inode->i_ctime.tv_sec -
			     inode->i_ctime.tv_sec) > UNIONFS_MIN_CC_TIME) {
				pr_info("unionfs: new lower inode ctime "
					"(bindex=%d, name=%s)\n", bindex,
					dentry->d_name.name);
				show_dinode_times(dentry);
			}
			return true;
		}
	}
	return false;		/* default: lower is not newer */
}

/*
 * Purge and invalidate as many data pages of a unionfs inode.  This is
 * called when the lower inode has changed, and we want to force processes
 * to re-get the new data.
 */
static inline void purge_inode_data(struct inode *inode)
{
	/* remove all non-private mappings */
	unmap_mapping_range(inode->i_mapping, 0, 0, 0);
	/* invalidate as many pages as possible */
	invalidate_mapping_pages(inode->i_mapping, 0, -1);
	/*
	 * Don't try to truncate_inode_pages here, because this could lead
	 * to a deadlock between some of address_space ops and dentry
	 * revalidation: the address space op is invoked with a lock on our
	 * own page, and truncate_inode_pages will block on locked pages.
	 */
}

/*
 * Revalidate a single file/symlink/special dentry.  Assume that info nodes
 * of the dentry and its parent are locked.  Assume that parent(s) are all
 * valid already, but the child may not yet be valid.  Returns true if
 * valid, false otherwise.
 */
bool __unionfs_d_revalidate_one_locked(struct dentry *dentry,
				       struct nameidata *nd,
				       bool willwrite)
{
	bool valid = false;	/* default is invalid */
	int sbgen, dgen, bindex;

	verify_locked(dentry);
	verify_locked(dentry->d_parent);

	sbgen = atomic_read(&UNIONFS_SB(dentry->d_sb)->generation);
	dgen = atomic_read(&UNIONFS_D(dentry)->generation);

	if (unlikely(is_newer_lower(dentry))) {
		/* root dentry special case as aforementioned */
		if (IS_ROOT(dentry)) {
			unionfs_copy_attr_times(dentry->d_inode);
		} else {
			/*
			 * reset generation number to zero, guaranteed to be
			 * "old"
			 */
			dgen = 0;
			atomic_set(&UNIONFS_D(dentry)->generation, dgen);
		}
		if (!willwrite)
			purge_inode_data(dentry->d_inode);
	}
	valid = __unionfs_d_revalidate_one(dentry, nd);

	/*
	 * If __unionfs_d_revalidate_one() succeeded above, then it will
	 * have incremented the refcnt of the mnt's, but also the branch
	 * indices of the dentry will have been updated (to take into
	 * account any branch insertions/deletion.  So the current
	 * dbstart/dbend match the current, and new, indices of the mnts
	 * which __unionfs_d_revalidate_one has incremented.  Note: the "if"
	 * test below does not depend on whether chain_len was 0 or greater.
	 */
	if (!valid || sbgen == dgen)
		goto out;
	for (bindex = dbstart(dentry); bindex <= dbend(dentry); bindex++)
		unionfs_mntput(dentry, bindex);
out:
	return valid;
}

/*
 * Revalidate a parent chain of dentries, then the actual node.
 * Assumes that dentry is locked, but will lock all parents if/when needed.
 *
 * If 'willwrite' is true, and the lower inode times are not in sync, then
 * *don't* purge_inode_data, as it could deadlock if ->write calls us and we
 * try to truncate a locked page.  Besides, if unionfs is about to write
 * data to a file, then there's the data unionfs is about to write is more
 * authoritative than what's below, therefore we can safely overwrite the
 * lower inode times and data.
 */
bool __unionfs_d_revalidate_chain(struct dentry *dentry, struct nameidata *nd,
				  bool willwrite)
{
	bool valid = false;	/* default is invalid */
	struct dentry **chain = NULL; /* chain of dentries to reval */
	int chain_len = 0;
	struct dentry *dtmp;
	int sbgen, dgen, i;
	int saved_bstart, saved_bend, bindex;

	/* find length of chain needed to revalidate */
	/* XXX: should I grab some global (dcache?) lock? */
	chain_len = 0;
	sbgen = atomic_read(&UNIONFS_SB(dentry->d_sb)->generation);
	dtmp = dentry->d_parent;
	verify_locked(dentry);
	if (dentry != dtmp)
		unionfs_lock_dentry(dtmp, UNIONFS_DMUTEX_REVAL_PARENT);
	dgen = atomic_read(&UNIONFS_D(dtmp)->generation);
	/* XXX: should we check if is_newer_lower all the way up? */
	if (unlikely(is_newer_lower(dtmp))) {
		/*
		 * Special case: the root dentry's generation number must
		 * always be valid, but its lower inode times don't have to
		 * be, so sync up the times only.
		 */
		if (IS_ROOT(dtmp)) {
			unionfs_copy_attr_times(dtmp->d_inode);
		} else {
			/*
			 * reset generation number to zero, guaranteed to be
			 * "old"
			 */
			dgen = 0;
			atomic_set(&UNIONFS_D(dtmp)->generation, dgen);
		}
		purge_inode_data(dtmp->d_inode);
	}
	if (dentry != dtmp)
		unionfs_unlock_dentry(dtmp);
	while (sbgen != dgen) {
		/* The root entry should always be valid */
		BUG_ON(IS_ROOT(dtmp));
		chain_len++;
		dtmp = dtmp->d_parent;
		dgen = atomic_read(&UNIONFS_D(dtmp)->generation);
	}
	if (chain_len == 0)
		goto out_this;	/* shortcut if parents are OK */

	/*
	 * Allocate array of dentries to reval.  We could use linked lists,
	 * but the number of entries we need to alloc here is often small,
	 * and short lived, so locality will be better.
	 */
	chain = kzalloc(chain_len * sizeof(struct dentry *), GFP_KERNEL);
	if (unlikely(!chain)) {
		printk(KERN_CRIT "unionfs: no more memory in %s\n",
		       __func__);
		goto out;
	}

	/* grab all dentries in chain, in child to parent order */
	dtmp = dentry;
	for (i = chain_len-1; i >= 0; i--)
		dtmp = chain[i] = dget_parent(dtmp);

	/*
	 * call __unionfs_d_revalidate_one() on each dentry, but in parent
	 * to child order.
	 */
	for (i = 0; i < chain_len; i++) {
		unionfs_lock_dentry(chain[i], UNIONFS_DMUTEX_REVAL_CHILD);
		if (chain[i] != chain[i]->d_parent)
			unionfs_lock_dentry(chain[i]->d_parent,
					    UNIONFS_DMUTEX_REVAL_PARENT);
		saved_bstart = dbstart(chain[i]);
		saved_bend = dbend(chain[i]);
		sbgen = atomic_read(&UNIONFS_SB(dentry->d_sb)->generation);
		dgen = atomic_read(&UNIONFS_D(chain[i])->generation);

		valid = __unionfs_d_revalidate_one(chain[i], nd);
		/* XXX: is this the correct mntput condition?! */
		if (valid && chain_len > 0 &&
		    sbgen != dgen && chain[i]->d_inode &&
		    S_ISDIR(chain[i]->d_inode->i_mode)) {
			for (bindex = saved_bstart; bindex <= saved_bend;
			     bindex++)
				unionfs_mntput(chain[i], bindex);
		}
		if (chain[i] != chain[i]->d_parent)
			unionfs_unlock_dentry(chain[i]->d_parent);
		unionfs_unlock_dentry(chain[i]);

		if (unlikely(!valid))
			goto out_free;
	}


out_this:
	/* finally, lock this dentry and revalidate it */
	verify_locked(dentry);	/* verify child is locked */
	if (dentry != dentry->d_parent)
		unionfs_lock_dentry(dentry->d_parent,
				    UNIONFS_DMUTEX_REVAL_PARENT);
	valid = __unionfs_d_revalidate_one_locked(dentry, nd, willwrite);
	if (dentry != dentry->d_parent)
		unionfs_unlock_dentry(dentry->d_parent);

out_free:
	/* unlock/dput all dentries in chain and return status */
	if (chain_len > 0) {
		for (i = 0; i < chain_len; i++)
			dput(chain[i]);
		kfree(chain);
	}
out:
	return valid;
}

static int unionfs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	int err;

	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);

	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);
	err = __unionfs_d_revalidate_chain(dentry, nd, false);
	if (likely(err > 0)) { /* true==1: dentry is valid */
		unionfs_postcopyup_setmnt(dentry);
		unionfs_check_dentry(dentry);
		unionfs_check_nd(nd);
	}
	unionfs_unlock_dentry(dentry);

	unionfs_read_unlock(dentry->d_sb);

	return err;
}

static void unionfs_d_release(struct dentry *dentry)
{
	int bindex, bstart, bend;

	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	/* must lock our branch configuration here */
	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);

	unionfs_check_dentry(dentry);
	/* this could be a negative dentry, so check first */
	if (unlikely(!UNIONFS_D(dentry) || dbstart(dentry) < 0)) {
		unionfs_unlock_dentry(dentry);
		goto out;	/* due to a (normal) failed lookup */
	}

	/* Release all the lower dentries */
	bstart = dbstart(dentry);
	bend = dbend(dentry);
	for (bindex = bstart; bindex <= bend; bindex++) {
		dput(unionfs_lower_dentry_idx(dentry, bindex));
		unionfs_set_lower_dentry_idx(dentry, bindex, NULL);
		/* NULL lower mnt is ok if this is a negative dentry */
		if (!dentry->d_inode && !unionfs_lower_mnt_idx(dentry, bindex))
			continue;
		unionfs_mntput(dentry, bindex);
		unionfs_set_lower_mnt_idx(dentry, bindex, NULL);
	}
	/* free private data (unionfs_dentry_info) here */
	kfree(UNIONFS_D(dentry)->lower_paths);
	UNIONFS_D(dentry)->lower_paths = NULL;

	unionfs_unlock_dentry(dentry);

out:
	free_dentry_private_data(dentry);
	unionfs_read_unlock(dentry->d_sb);
	return;
}

/*
 * Called when we're removing the last reference to our dentry.  So we
 * should drop all lower references too.
 */
static void unionfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	int bindex, rc;

	BUG_ON(!dentry);
	unionfs_read_lock(dentry->d_sb, UNIONFS_SMUTEX_CHILD);
	unionfs_lock_dentry(dentry, UNIONFS_DMUTEX_CHILD);

	if (!UNIONFS_D(dentry) || dbstart(dentry) < 0)
		goto drop_lower_inodes;
	for (bindex = dbstart(dentry); bindex <= dbend(dentry); bindex++) {
		if (unionfs_lower_mnt_idx(dentry, bindex)) {
			unionfs_mntput(dentry, bindex);
			unionfs_set_lower_mnt_idx(dentry, bindex, NULL);
		}
		if (unionfs_lower_dentry_idx(dentry, bindex)) {
			dput(unionfs_lower_dentry_idx(dentry, bindex));
			unionfs_set_lower_dentry_idx(dentry, bindex, NULL);
		}
	}
	set_dbstart(dentry, -1);
	set_dbend(dentry, -1);

drop_lower_inodes:
	rc = atomic_read(&inode->i_count);
	if (rc == 1 && inode->i_nlink == 1 && ibstart(inode) >= 0) {
		/* see Documentation/filesystems/unionfs/issues.txt */
		lockdep_off();
		iput(unionfs_lower_inode(inode));
		lockdep_on();
		unionfs_set_lower_inode(inode, NULL);
		/* XXX: may need to set start/end to -1? */
	}

	iput(inode);

	unionfs_unlock_dentry(dentry);
	unionfs_read_unlock(dentry->d_sb);
}

struct dentry_operations unionfs_dops = {
	.d_revalidate	= unionfs_d_revalidate,
	.d_release	= unionfs_d_release,
	.d_iput		= unionfs_d_iput,
};
