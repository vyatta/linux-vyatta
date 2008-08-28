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
 * inode attributes on FUSE branch or HINOTIFY
 *
 * $Id: hin_or_fuse.c,v 1.3 2008/08/25 01:49:59 sfjro Exp $
 */

#include "aufs.h"

int aufs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *st)
{
	int err;
	struct inode *inode, *h_inode;
	struct dentry *h_dentry;
	aufs_bindex_t ib, db, bindex;
	struct super_block *sb;

	LKTRTrace("%.*s\n", AuDLNPair(dentry));

	h_dentry = NULL;
	inode = dentry->d_inode;
	sb = dentry->d_sb;
	aufs_read_lock(dentry, AuLock_FLUSH | AuLock_IR);
#if 0
	err = -EIO;
	if (!au_hin_verify_gen(dentry))
		goto out;
#endif

	ib = au_ibstart(inode);
	db = au_dbstart(dentry);
	if (ib == db) {
		bindex = db;
		h_dentry = dget(au_h_dptr(dentry, db));
	} else {
		bindex = ib;
		h_inode = au_h_iptr(inode, ib);
		h_dentry = d_find_alias(h_inode);
	}

	if (unlikely(!h_dentry)) {
		h_dentry = au_hi_wh(inode, ib);
		if (h_dentry) {
			dget(h_dentry);
			if (unlikely(!h_dentry->d_inode)) {
				dput(h_dentry);
				err = -ENOENT;
				goto out;
			}
		}
	}

	err = -EIO;
	if (h_dentry) {
		err = vfsub_getattr(au_sbr_mnt(sb, bindex), h_dentry, st,
				    au_test_dlgt(au_mntflags(sb)));
		dput(h_dentry);
	}
	if (!err) {
		au_cpup_attr_all(inode);
		generic_fillattr(inode, st);
	}

 out:
	aufs_read_unlock(dentry, AuLock_IR);
	AuTraceErr(err);
	return err;
}
