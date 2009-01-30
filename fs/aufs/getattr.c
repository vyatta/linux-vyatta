/*
 * Copyright (C) 2005-2009 Junjiro Okajima
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
 * inode attributes on NFS/FUSE branch or HINOTIFY
 *
 * $Id: getattr.c,v 1.5 2009/01/26 06:24:45 sfjro Exp $
 */

#include "aufs.h"

static struct dentry *
au_h_dget_any(struct dentry *dentry, aufs_bindex_t *bindex)
{
	struct dentry *h_dentry;
	struct inode *inode, *h_inode;
	struct super_block *sb;
	aufs_bindex_t ib, db;

	/* must be positive dentry */
	inode = dentry->d_inode;
	LKTRTrace("%.*s, i%lu\n", AuDLNPair(dentry), inode->i_ino);

	sb = dentry->d_sb;
	db = au_dbstart(dentry);
	ib = au_ibstart(inode);
	if (db == ib) {
		*bindex = db;
		h_dentry = dget(au_h_dptr(dentry, db));
		if (h_dentry)
			goto out; /* success */
	}

	*bindex = ib;
	h_inode = au_h_iptr(inode, ib);
	h_dentry = d_find_alias(h_inode);
	if (h_dentry)
		goto out; /* success */

#if 0
	if (au_opt_test(au_mntflags(sb), PLINK)
	    && au_plink_test(sb, inode)) {
		h_dentry = au_plink_lkup(sb, ib, inode);
		if (IS_ERR(h_dentry))
			goto out;
		AuDebugOn(!h_dentry->d_inode);
		goto out; /* success */
	}
#endif

	h_dentry = dget(au_hi_wh(inode, ib));

 out:
	AuTraceErrPtr(h_dentry);
	return h_dentry;
}

int aufs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *st)
{
	int err;
	unsigned int mnt_flags;
	aufs_bindex_t bindex;
	unsigned char did_lock;
	struct inode *inode;
	struct dentry *h_dentry;
	struct super_block *sb, *h_sb;

	LKTRTrace("%.*s\n", AuDLNPair(dentry));

	err = 0;
	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);
	mnt_flags = au_mntflags(sb);
	if (dentry != sb->s_root) {
		di_read_lock_parent(dentry, AuLock_IR);
		inode = dentry->d_inode;
		did_lock = 1;

		/* todo: test bit inotify option too? */
		bindex = au_ibstart(inode);
		h_sb = au_sbr_sb(sb, bindex);
		/* todo: fix this condition */
		if ((au_opt_test(mnt_flags, PLINK) && au_plink_test(sb, inode))
		    /* au_iigen(inode) == au_sigen(sb) */
		    || (!au_test_fuse(h_sb) && !au_test_nfs(h_sb)))
			goto fill;

		h_dentry = au_h_dget_any(dentry, &bindex);
		err = PTR_ERR(h_dentry);
		if (IS_ERR(h_dentry))
			goto out;
	} else {
		/* lock free root dinfo */
		did_lock = 0;
		bindex = 0;
		inode = dentry->d_inode;
		h_dentry = dget(au_di(dentry)->di_hdentry->hd_dentry);
	}

	err = -EIO;
	if (h_dentry && h_dentry->d_inode)
		err = vfsub_getattr(au_sbr_mnt(sb, bindex), h_dentry, st,
				    au_test_dlgt(mnt_flags));
	dput(h_dentry);
	if (!err) {
		/* todo: I don't like this approach */
		au_cpup_attr_all(inode, /*force*/0);
	fill:
		generic_fillattr(inode, st);
	}

 out:
	if (did_lock)
		di_read_unlock(dentry, AuLock_IR);
	si_read_unlock(sb);
	AuTraceErr(err);
	return err;
}
