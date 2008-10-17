/*
 * Copyright (C) 2005-2008 Junjiro Okajima
 *
 * This program, aufs is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * dentry private data
 *
 * $Id: dinfo.c,v 1.6 2008/07/14 00:14:33 sfjro Exp $
 */

#include "aufs.h"

int au_alloc_dinfo(struct dentry *dentry)
{
	struct au_dinfo *dinfo;
	struct super_block *sb;
	int nbr;

	LKTRTrace("%.*s\n", AuDLNPair(dentry));
	AuDebugOn(dentry->d_fsdata);

	dinfo = au_cache_alloc_dinfo();
	if (dinfo) {
		sb = dentry->d_sb;
		nbr = au_sbend(sb) + 1;
		if (unlikely(nbr <= 0))
			nbr = 1;
		dinfo->di_hdentry = kcalloc(nbr, sizeof(*dinfo->di_hdentry),
					    GFP_NOFS);
		if (dinfo->di_hdentry) {
			au_h_dentry_init_all(dinfo->di_hdentry, nbr);
			atomic_set(&dinfo->di_generation, au_sigen(sb));
			/* smp_mb(); */ /* atomic_set */
			au_rw_init_wlock_nested(&dinfo->di_rwsem,
						AuLsc_DI_CHILD);
			dinfo->di_bstart = -1;
			dinfo->di_bend = -1;
			dinfo->di_bwh = -1;
			dinfo->di_bdiropq = -1;

			dentry->d_fsdata = dinfo;
			dentry->d_op = &aufs_dop;
			return 0; /* success */
		}
		au_cache_free_dinfo(dinfo);
	}
	AuTraceErr(-ENOMEM);
	return -ENOMEM;
}

struct au_dinfo *au_di(struct dentry *dentry)
{
	struct au_dinfo *dinfo = dentry->d_fsdata;
	AuDebugOn(!dinfo
		 || !dinfo->di_hdentry
		 /* || au_sbi(dentry->d_sb)->si_bend < dinfo->di_bend */
		 || dinfo->di_bend < dinfo->di_bstart
		 /* dbwh can be outside of this range */
		 || (0 <= dinfo->di_bdiropq
		     && (dinfo->di_bdiropq < dinfo->di_bstart
			 /* || dinfo->di_bend < dinfo->di_bdiropq */))
		);
	return dinfo;
}

/* ---------------------------------------------------------------------- */

static void do_ii_write_lock(struct inode *inode, unsigned int lsc)
{
	switch (lsc) {
	case AuLsc_DI_CHILD:
		ii_write_lock_child(inode);
		break;
	case AuLsc_DI_CHILD2:
		ii_write_lock_child2(inode);
		break;
	case AuLsc_DI_CHILD3:
		ii_write_lock_child3(inode);
		break;
	case AuLsc_DI_PARENT:
		ii_write_lock_parent(inode);
		break;
	case AuLsc_DI_PARENT2:
		ii_write_lock_parent2(inode);
		break;
	case AuLsc_DI_PARENT3:
		ii_write_lock_parent3(inode);
		break;
	case AuLsc_DI_PARENT4:
		ii_write_lock_parent4(inode);
		break;
	default:
		BUG();
	}
}

static void do_ii_read_lock(struct inode *inode, unsigned int lsc)
{
	switch (lsc) {
	case AuLsc_DI_CHILD:
		ii_read_lock_child(inode);
		break;
	case AuLsc_DI_CHILD2:
		ii_read_lock_child2(inode);
		break;
	case AuLsc_DI_CHILD3:
		ii_read_lock_child3(inode);
		break;
	case AuLsc_DI_PARENT:
		ii_read_lock_parent(inode);
		break;
	case AuLsc_DI_PARENT2:
		ii_read_lock_parent2(inode);
		break;
	case AuLsc_DI_PARENT3:
		ii_read_lock_parent3(inode);
		break;
	case AuLsc_DI_PARENT4:
		ii_read_lock_parent4(inode);
		break;
	default:
		BUG();
	}
}

void di_read_lock(struct dentry *d, int flags, unsigned int lsc)
{
	LKTRTrace("%.*s, %u\n", AuDLNPair(d), lsc);

	SiMustAnyLock(d->d_sb);
	/* todo: always nested? */
	au_rw_read_lock_nested(&au_di(d)->di_rwsem, lsc);
	if (d->d_inode) {
		if (au_ftest_lock(flags, IW))
			do_ii_write_lock(d->d_inode, lsc);
		else if (au_ftest_lock(flags, IR))
			do_ii_read_lock(d->d_inode, lsc);
	}
}

void di_read_unlock(struct dentry *d, int flags)
{
	LKTRTrace("%.*s\n", AuDLNPair(d));

	SiMustAnyLock(d->d_sb);
	if (d->d_inode) {
		if (au_ftest_lock(flags, IW))
			ii_write_unlock(d->d_inode);
		else if (au_ftest_lock(flags, IR))
			ii_read_unlock(d->d_inode);
	}
	au_rw_read_unlock(&au_di(d)->di_rwsem);
}

void di_downgrade_lock(struct dentry *d, int flags)
{
	SiMustAnyLock(d->d_sb);
	au_rw_dgrade_lock(&au_di(d)->di_rwsem);
	if (d->d_inode && au_ftest_lock(flags, IR))
		ii_downgrade_lock(d->d_inode);
}

void di_write_lock(struct dentry *d, unsigned int lsc)
{
	LKTRTrace("%.*s, %u\n", AuDLNPair(d), lsc);

	SiMustAnyLock(d->d_sb);
	/* todo: always nested? */
	au_rw_write_lock_nested(&au_di(d)->di_rwsem, lsc);
	if (d->d_inode)
		do_ii_write_lock(d->d_inode, lsc);
}

void di_write_unlock(struct dentry *d)
{
	LKTRTrace("%.*s\n", AuDLNPair(d));

	SiMustAnyLock(d->d_sb);
	if (d->d_inode)
		ii_write_unlock(d->d_inode);
	au_rw_write_unlock(&au_di(d)->di_rwsem);
}

void di_write_lock2_child(struct dentry *d1, struct dentry *d2, int isdir)
{
	AuTraceEnter();
	AuDebugOn(d1 == d2
		  || d1->d_inode == d2->d_inode
		  || d1->d_sb != d2->d_sb);

	if (isdir && au_test_subdir(d1, d2)) {
		di_write_lock_child(d1);
		di_write_lock_child2(d2);
	} else {
		/* there should be no races */
		di_write_lock_child(d2);
		di_write_lock_child2(d1);
	}
}

void di_write_lock2_parent(struct dentry *d1, struct dentry *d2, int isdir)
{
	AuTraceEnter();
	AuDebugOn(d1 == d2
		  || d1->d_inode == d2->d_inode
		  || d1->d_sb != d2->d_sb);

	if (isdir && au_test_subdir(d1, d2)) {
		di_write_lock_parent(d1);
		di_write_lock_parent2(d2);
	} else {
		/* there should be no races */
		di_write_lock_parent(d2);
		di_write_lock_parent2(d1);
	}
}

void di_write_unlock2(struct dentry *d1, struct dentry *d2)
{
	di_write_unlock(d1);
	if (d1->d_inode == d2->d_inode)
		au_rw_write_unlock(&au_di(d2)->di_rwsem);
	else
		di_write_unlock(d2);
}

/* ---------------------------------------------------------------------- */

struct dentry *au_h_dptr(struct dentry *dentry, aufs_bindex_t bindex)
{
	struct dentry *d;

	DiMustAnyLock(dentry);
	if (au_dbstart(dentry) < 0 || bindex < au_dbstart(dentry))
		return NULL;
	AuDebugOn(bindex < 0
		  /* || bindex > au_sbend(dentry->d_sb) */);
	d = au_di(dentry)->di_hdentry[0 + bindex].hd_dentry;
	AuDebugOn(d && (atomic_read(&d->d_count) <= 0));
	return d;
}

aufs_bindex_t au_dbtail(struct dentry *dentry)
{
	aufs_bindex_t bend, bwh;

	bend = au_dbend(dentry);
	if (0 <= bend) {
		bwh = au_dbwh(dentry);
		if (!bwh)
			return bwh;
		if (0 < bwh && bwh < bend)
			return bwh - 1;
	}
	return bend;
}

aufs_bindex_t au_dbtaildir(struct dentry *dentry)
{
	aufs_bindex_t bend, bopq;

	AuDebugOn(dentry->d_inode
		  && dentry->d_inode->i_mode
		  && !S_ISDIR(dentry->d_inode->i_mode));

	bend = au_dbtail(dentry);
	if (0 <= bend) {
		bopq = au_dbdiropq(dentry);
		AuDebugOn(bend < bopq);
		if (0 <= bopq && bopq < bend)
			bend = bopq;
	}
	return bend;
}

#if 0 /* reserved for future use */
aufs_bindex_t au_dbtail_generic(struct dentry *dentry)
{
	struct inode *inode;

	inode = dentry->d_inode;
	if (inode && S_ISDIR(inode->i_mode))
		return au_dbtaildir(dentry);
	else
		return au_dbtail(dentry);
}
#endif

/* ---------------------------------------------------------------------- */

void au_set_dbdiropq(struct dentry *dentry, aufs_bindex_t bindex)
{
	DiMustWriteLock(dentry);
	AuDebugOn(au_sbend(dentry->d_sb) < bindex);
	AuDebugOn((bindex >= 0
		   && (bindex < au_dbstart(dentry)
		       || au_dbend(dentry) < bindex))
		  || (dentry->d_inode
		      && dentry->d_inode->i_mode
		      && !S_ISDIR(dentry->d_inode->i_mode)));
	au_di(dentry)->di_bdiropq = bindex;
}

void au_set_h_dptr(struct dentry *dentry, aufs_bindex_t bindex,
		   struct dentry *h_dentry)
{
	struct au_hdentry *hd = au_di(dentry)->di_hdentry + bindex;
	DiMustWriteLock(dentry);
	AuDebugOn(bindex < au_di(dentry)->di_bstart
		  || bindex > au_di(dentry)->di_bend
		  || (h_dentry && atomic_read(&h_dentry->d_count) <= 0)
		  || (h_dentry && hd->hd_dentry)
		);
	if (hd->hd_dentry)
		au_hdput(hd, /*do_free*/0);
	hd->hd_dentry = h_dentry;
}

/* ---------------------------------------------------------------------- */

void au_update_dbrange(struct dentry *dentry, int do_put_zero)
{
	struct au_dinfo *dinfo;
	aufs_bindex_t bindex;
	struct dentry *h_d;

	LKTRTrace("%.*s, %d\n", AuDLNPair(dentry), do_put_zero);
	DiMustWriteLock(dentry);

	dinfo = au_di(dentry);
	if (unlikely(!dinfo) || dinfo->di_bstart < 0)
		return;

	if (do_put_zero) {
		for (bindex = dinfo->di_bstart; bindex <= dinfo->di_bend;
		     bindex++) {
			h_d = dinfo->di_hdentry[0 + bindex].hd_dentry;
			if (h_d && !h_d->d_inode)
				au_set_h_dptr(dentry, bindex, NULL);
		}
	}

	dinfo->di_bstart = -1;
	while (++dinfo->di_bstart <= dinfo->di_bend)
		if (dinfo->di_hdentry[0 + dinfo->di_bstart].hd_dentry)
			break;
	if (dinfo->di_bstart > dinfo->di_bend) {
		dinfo->di_bstart = -1;
		dinfo->di_bend = -1;
		return;
	}

	dinfo->di_bend++;
	while (0 <= --dinfo->di_bend)
		if (dinfo->di_hdentry[0 + dinfo->di_bend].hd_dentry)
			break;
	AuDebugOn(dinfo->di_bstart > dinfo->di_bend || dinfo->di_bend < 0);
}

void au_update_dbstart(struct dentry *dentry)
{
	aufs_bindex_t bindex,
		bstart = au_dbstart(dentry),
		bend = au_dbend(dentry);
	struct dentry *h_dentry;

	LKTRTrace("%.*s\n", AuDLNPair(dentry));
	DiMustWriteLock(dentry);

	for (bindex = bstart; bindex <= bend; bindex++) {
		h_dentry = au_h_dptr(dentry, bindex);
		if (!h_dentry)
			continue;
		if (h_dentry->d_inode) {
			au_set_dbstart(dentry, bindex);
			return;
		}
		au_set_h_dptr(dentry, bindex, NULL);
	}
}

void au_update_dbend(struct dentry *dentry)
{
	aufs_bindex_t bindex,
		bstart = au_dbstart(dentry),
		bend = au_dbend(dentry);
	struct dentry *h_dentry;

	DiMustWriteLock(dentry);
	for (bindex = bend; bindex <= bstart; bindex--) {
		h_dentry = au_h_dptr(dentry, bindex);
		if (!h_dentry)
			continue;
		if (h_dentry->d_inode) {
			au_set_dbend(dentry, bindex);
			return;
		}
		au_set_h_dptr(dentry, bindex, NULL);
	}
}

int au_find_dbindex(struct dentry *dentry, struct dentry *h_dentry)
{
	aufs_bindex_t bindex, bend;

	bend = au_dbend(dentry);
	for (bindex = au_dbstart(dentry); bindex <= bend; bindex++)
		if (au_h_dptr(dentry, bindex) == h_dentry)
			return bindex;
	return -1;
}
