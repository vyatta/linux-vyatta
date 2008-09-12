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
 * export via nfs
 * todo: support anonymous dentry for hardlink
 *
 * $Id: export.c,v 1.13 2008/09/08 02:39:48 sfjro Exp $
 */

#include <linux/exportfs.h>
#include <linux/mnt_namespace.h>
#include "aufs.h"

union conv {
#ifdef CONFIG_AUFS_INO_T_64
	__u32 a[2];
#else
	__u32 a[1];
#endif
	ino_t ino;
};

static ino_t decode_ino(__u32 *a)
{
	union conv u;

	u.a[0] = a[0];
#ifdef CONFIG_AUFS_INO_T_64
	u.a[1] = a[1];
#endif
	return u.ino;
}

static void encode_ino(__u32 *a, ino_t ino)
{
	union conv u;

	u.ino = ino;
	a[0] = u.a[0];
#ifdef CONFIG_AUFS_INO_T_64
	a[1] = u.a[1];
#endif
}

/* NFS file handle */
enum {
	Fh_br_id,
	Fh_sigen,
#ifdef CONFIG_AUFS_INO_T_64
	/* support 64bit inode number */
	Fh_ino1,
	Fh_ino2,
	Fh_dir_ino1,
	Fh_dir_ino2,
	Fh_h_ino1,
	Fh_h_ino2,
#else
	Fh_ino1,
	Fh_dir_ino1,
	Fh_h_ino1,
#endif
	Fh_h_igen,
	Fh_h_type,
	Fh_tail,

	Fh_ino = Fh_ino1,
	Fh_dir_ino = Fh_dir_ino1,
	Fh_h_ino = Fh_h_ino1,
};

static int au_test_anon(struct dentry *dentry)
{
	return !!(dentry->d_flags & DCACHE_DISCONNECTED);
}

/* ---------------------------------------------------------------------- */
#if 0
static struct dentry *au_anon(struct inode *inode)
{
	struct dentry *dentry;
	struct super_block *sb;
	ino_t ino;
	struct inode *i;

	LKTRTrace("i%lu\n", inode->i_ino);
	AuDebugOn(S_ISDIR(inode->i_mode));

	dentry = NULL;
	/* todo: export __d_find_alias() */
	spin_lock(&dcache_lock);
	list_for_each_entry(d, &inode->i_dentry, d_alias)
		if (au_test_anon(d)) {
			dentry = dget(d);
			break;
		}
	spin_unlock(&dcache_lock);
	if (dentry)
		goto out;

	dentry = ERR_PTR(-EIO);
	sb = inode->i_sb;
	ino = au_xino_new_ino(sb);
	if (unlikely(ino))
		goto out;
	i = au_iget_locked(sb, ino);
	dentry = (void *)i;
	if (IS_ERR(i))
		goto out;
	/* todo: necessary? */
	clear_nlink(i);
	AuDbgInode(i);

	dentry = d_alloc_anon(i);
	if (IS_ERR(dentry))
		goto out_i;
	else if (unlikely(!dentry)) {
		dentry = ERR_PTR(-ENOMEM);
		goto out_i;
	}
#if 0
	int err;
	err = au_alloc_dinfo(dentry);
	if (unlikely(err))
		goto out_d;
#endif

	spin_lock(&dcache_lock);
	list_del(&dentry->d_alias);
	dentry->d_inode = au_igrab(inode);
	list_add(&d->d_alias, &inode->i_dentry);
	spin_unlock(&dcache_lock);
	goto out_i; /* success */

 out_d:
	dput(dentry);
	dentry = ERR_PTR(err);
 out_i:
	iput(i);
 out:
	AuTraceErrPtr(dentry);
	return dentry;
}
#endif

static struct dentry *decode_by_ino(struct super_block *sb, ino_t ino,
				    ino_t dir_ino)
{
	struct dentry *dentry, *parent;
	struct inode *inode;

	LKTRTrace("i%lu, diri%lu\n",
		  (unsigned long)ino, (unsigned long)dir_ino);

	dentry = NULL;
	inode = ilookup(sb, ino);
	if (unlikely(!inode))
		goto out;

	dentry = ERR_PTR(-ESTALE);
	if (unlikely(is_bad_inode(inode)))
		goto out_iput;

	dentry = NULL;
	if (!S_ISDIR(inode->i_mode)) {
		struct dentry *d;
		spin_lock(&dcache_lock);
		list_for_each_entry(d, &inode->i_dentry, d_alias)
			if (!au_test_anon(d)
			    && d->d_parent->d_inode->i_ino == dir_ino) {
				dentry = dget_locked(d);
				break;
			}
		spin_unlock(&dcache_lock);
	} else {
		dentry = d_find_alias(inode);
		if (dentry && !au_test_anon(dentry)) {
			int same_ino;
			parent = dget_parent(dentry);
			same_ino = (parent->d_inode->i_ino == dir_ino);
			dput(parent);
			if (same_ino)
				goto out_iput; /* success */
		}

		dput(dentry);
		dentry = NULL;
	}

 out_iput:
	iput(inode);
 out:
	AuTraceErrPtr(dentry);
	return dentry;
}

/* ---------------------------------------------------------------------- */

/* todo: dirty? */
/*
 * when you mntput() for the return value of this function,
 * you have to store it to your local var.
 * ie. never mntput si_mntcache directly.
 */
static struct vfsmount *au_do_mnt_get(struct super_block *sb)
{
	struct mnt_namespace *ns;
	struct vfsmount *pos, *mnt;

	AuTraceEnter();

	/* vfsmount_lock is not exported */
	/* no get/put ?? */
	AuDebugOn(!current->nsproxy);
	ns = current->nsproxy->mnt_ns;
	AuDebugOn(!ns);
	mnt = NULL;
	/* the order (reverse) will not be a problem */
	list_for_each_entry(pos, &ns->list, mnt_list)
		if (pos->mnt_sb == sb) {
			mnt = pos;
			break;
		}
	AuDebugOn(!mnt);

	return mntget(mnt);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static struct vfsmount *au_mnt_get(struct super_block *sb)
{
	struct au_sbinfo *sbinfo;
	struct vfsmount *mnt;

	sbinfo = au_sbi(sb);
	spin_lock(&sbinfo->si_mntcache_lock);
	if (sbinfo->si_mntcache)
		mnt = mntget(sbinfo->si_mntcache);
	else {
		sbinfo->si_mntcache = au_do_mnt_get(sb);
		mnt = sbinfo->si_mntcache;
	}
	spin_unlock(&sbinfo->si_mntcache_lock);
	return mnt;
}
#else
static struct vfsmount *au_mnt_get(struct super_block *sb)
{
	return au_do_mnt_get(sb);
}
#endif

struct find_name_by_ino {
	int called, found;
	ino_t ino;
	char *name;
	int namelen;
};

static int
find_name_by_ino(void *arg, const char *name, int namelen, loff_t offset,
		 u64 ino, unsigned int d_type)
{
	struct find_name_by_ino *a = arg;

	a->called++;
	if (a->ino != ino)
		return 0;

	memcpy(a->name, name, namelen);
	a->namelen = namelen;
	a->found = 1;
	return 1;
}

static /* noinline_for_stack */
struct dentry *decode_by_dir_ino(struct super_block *sb, ino_t ino,
				 ino_t dir_ino)
{
	struct dentry *dentry, *parent;
	struct inode *dir;
	struct find_name_by_ino arg;
	struct file *file;
	int err;

	LKTRTrace("i%lu, diri%lu\n",
		  (unsigned long)ino, (unsigned long)dir_ino);

	dentry = NULL;
	dir = ilookup(sb, dir_ino);
	if (unlikely(!dir))
		goto out;

	dentry = ERR_PTR(-ESTALE);
	if (unlikely(is_bad_inode(dir)))
		goto out_iput;

	dentry = NULL;
	parent = d_find_alias(dir);
	if (parent) {
		if (unlikely(au_test_anon(parent))) {
			dput(parent);
			goto out_iput;
		}
	} else
		goto out_iput;

	file = dentry_open(parent, au_mnt_get(sb), au_dir_roflags);
	dentry = (void *)file;
	if (IS_ERR(file))
		goto out_iput;

	dentry = ERR_PTR(-ENOMEM);
	arg.name = __getname();
	if (unlikely(!arg.name))
		goto out_fput;
	arg.ino = ino;
	arg.found = 0;
	do {
		arg.called = 0;
		/* smp_mb(); */
		err = vfsub_readdir(file, find_name_by_ino, &arg, /*dlgt*/0);
	} while (!err && !arg.found && arg.called);
	if (!err) {
		if (arg.found) {
			/* do not call au_lkup_one(), nor dlgt */
			mutex_lock(&dir->i_mutex);
			dentry = vfsub_lookup_one_len(arg.name, parent, arg.namelen);
			mutex_unlock(&dir->i_mutex);
			AuTraceErrPtr(dentry);
		} else
			dentry = ERR_PTR(-ENOENT);
	} else
		dentry = ERR_PTR(err);
	__putname(arg.name);

 out_fput:
	fput(file);
 out_iput:
	iput(dir);
 out:
	AuTraceErrPtr(dentry);
	return dentry;
}

/* ---------------------------------------------------------------------- */

struct append_name {
	int found, called, len;
	char *h_path;
	ino_t h_ino;
};

static int append_name(void *arg, const char *name, int len, loff_t pos,
		       u64 ino, unsigned int d_type)
{
	struct append_name *a = arg;
	char *p;

	a->called++;
	if (ino != a->h_ino)
		return 0;

	AuDebugOn(len == 1 && *name == '.');
	AuDebugOn(len == 2 && name[0] == '.' && name[1] == '.');
	if (unlikely(a->len + len + 2 > PATH_MAX))
		return -ENAMETOOLONG;

	memmove(a->h_path - len - 1, a->h_path, a->len);
	a->h_path -= len + 1;
	p = a->h_path + a->len;
	*p++ = '/';
	memcpy(p, name, len);
	a->len += 1 + len;
	a->found++;
	return 1;
}

static int h_acceptable(void *expv, struct dentry *dentry)
{
	return 1;
}

static char *au_build_path(struct super_block *sb, __u32 *fh, char *path,
			     struct vfsmount *h_mnt, struct dentry *h_root,
			     struct dentry *h_parent)
{
	char *ret;
	int err, len;
	struct file *h_file;
	struct append_name arg;
	struct path dm_path = {
		.mnt	= h_mnt,
		.dentry	= h_root
	};

	AuTraceEnter();

	arg.h_path = d_path(&dm_path, path, PATH_MAX);
	ret = arg.h_path;
	if (IS_ERR(arg.h_path))
		goto out;

	len = strlen(arg.h_path);
	dm_path.dentry = h_parent;
	arg.h_path = d_path(&dm_path, path, PATH_MAX);
	ret = arg.h_path;
	if (IS_ERR(arg.h_path))
		goto out;
	LKTRTrace("%s\n", arg.h_path);
	if (len != 1)
		arg.h_path += len;
	LKTRTrace("%p, %s, %ld\n",
		  arg.h_path, arg.h_path, (long)(arg.h_path - path));

	/* cf. fs/exportfs/expfs.c */
	h_file = dentry_open(dget(h_parent), mntget(h_mnt), au_dir_roflags);
	ret = (void *)h_file;
	if (IS_ERR(h_file))
		goto out;

	arg.len = strlen(arg.h_path);
	arg.found = 0;
	arg.h_ino = decode_ino(fh + Fh_h_ino);
	do {
		arg.called = 0;
		err = vfsub_readdir(h_file, append_name, &arg, /*dlgt*/0);
	} while (!err && !arg.found && arg.called);
	LKTRTrace("%p, %s, %d\n", arg.h_path, arg.h_path, arg.len);
	fput(h_file);
	ret = ERR_PTR(err);
	if (unlikely(err))
		goto out;
	ret = ERR_PTR(-ENOENT);
	if (unlikely(!arg.found))
		goto out;

	dm_path.mnt = au_mnt_get(sb);
	dm_path.dentry = sb->s_root;
	ret = d_path(&dm_path, path, PATH_MAX - arg.len);
	mntput(dm_path.mnt);
	if (IS_ERR(ret))
		goto out;
	ret[strlen(ret)] = '/';
	LKTRTrace("%s\n", ret);

 out:
	AuTraceErrPtr(ret);
	return ret;
}

static noinline_for_stack
struct dentry *decode_by_path(struct super_block *sb, aufs_bindex_t bindex,
			      __u32 *fh, int fh_len, void *context)
{
	struct dentry *dentry, *h_parent, *root, *h_root;
	struct super_block *h_sb;
	char *path, *p;
	struct vfsmount *h_mnt;
	int err;
	struct nameidata nd;
	struct au_branch *br;

	LKTRTrace("b%d\n", bindex);
	SiMustAnyLock(sb);

	br = au_sbr(sb, bindex);
	/* au_br_get(br); */
	h_mnt = br->br_mnt;
	h_sb = h_mnt->mnt_sb;
	LKTRTrace("%s, h_decode_fh\n", au_sbtype(h_sb));
	/* in linux-2.6.24, it takes struct fid * as file handle */
	/* todo: call lower fh_to_dentry()? fh_to_parent()? */
	h_parent = exportfs_decode_fh(h_mnt, (void *)(fh + Fh_tail),
				      fh_len - Fh_tail, fh[Fh_h_type],
				      h_acceptable, /*context*/NULL);
	dentry = h_parent;
	if (unlikely(!h_parent || IS_ERR(h_parent))) {
		//AuWarn1("%s decode_fh failed\n", au_sbtype(h_sb));
		goto out;
	}
	dentry = NULL;
	if (unlikely(au_test_anon(h_parent))) {
		AuWarn1("%s decode_fh returned a disconnected dentry\n",
			au_sbtype(h_sb));
		dput(h_parent);
		goto out;
	}

	dentry = ERR_PTR(-ENOMEM);
	path = __getname();
	if (unlikely(!path)) {
		dput(h_parent);
		goto out;
	}

	root = sb->s_root;
	di_read_lock_parent(root, !AuLock_IR);
	h_root = au_h_dptr(root, bindex);
	di_read_unlock(root, !AuLock_IR);
	p = au_build_path(sb, fh, path, h_mnt, h_root, h_parent);
	dput(h_parent);
	dentry = (void *)p;
	if (IS_ERR(p))
		goto out_putname;

	err = vfsub_path_lookup(p, LOOKUP_FOLLOW, &nd);
	dentry = ERR_PTR(err);
	if (!err) {
		dentry = dget(nd.path.dentry);
		if (unlikely(au_test_anon(dentry))) {
			dput(dentry);
			dentry = ERR_PTR(-ESTALE);
		}
		path_put(&nd.path);
	}

 out_putname:
	__putname(path);
 out:
	/* au_br_put(br); */
	AuTraceErrPtr(dentry);
	return dentry;
}

/* ---------------------------------------------------------------------- */

static struct dentry *
aufs_decode_fh(struct super_block *sb, __u32 *fh, int fh_len, int fh_type,
	       int (*acceptable)(void *context, struct dentry *de),
	       void *context)
{
	struct dentry *dentry;
	ino_t ino, dir_ino;
	aufs_bindex_t bindex, br_id;
	struct inode *inode, *h_inode;
	au_gen_t sigen;

	LKTRTrace("%d, fh{br_id %u, sigen %u, i%u, diri%u, hi%u}\n",
		  fh_type, fh[Fh_br_id], fh[Fh_sigen], fh[Fh_ino],
		  fh[Fh_dir_ino], fh[Fh_h_ino]);
	AuDebugOn(fh_len < Fh_tail);

	si_read_lock(sb, AuLock_FLUSH);
	lockdep_off();

	/* branch id may be wrapped around */
	dentry = ERR_PTR(-ESTALE);
	br_id = fh[Fh_br_id];
	sigen = fh[Fh_sigen];
	bindex = au_br_index(sb, br_id);
	LKTRTrace("b%d\n", bindex);
	if (unlikely(bindex < 0
		     || (0 && sigen != au_sigen(sb))
		     || (1 && sigen + AUFS_BRANCH_MAX <= au_sigen(sb))
		    ))
		goto out;

	/* is this inode still cached? */
	ino = decode_ino(fh + Fh_ino);
	dir_ino = decode_ino(fh + Fh_dir_ino);
	dentry = decode_by_ino(sb, ino, dir_ino);
	if (IS_ERR(dentry))
		goto out;
	if (dentry)
		goto accept;

	/* is the parent dir cached? */
	dentry = decode_by_dir_ino(sb, ino, dir_ino);
	if (IS_ERR(dentry))
		goto out;
	if (dentry)
		goto accept;

	/* lookup path */
	dentry = decode_by_path(sb, bindex, fh, fh_len, context);
	if (IS_ERR(dentry))
		goto out;
	if (unlikely(!dentry))
		goto out_stale;
	if (unlikely(dentry->d_inode->i_ino != ino)) {
		LKTRTrace("ino %lu\n", ino);
		AuDbgDentry(dentry);
		AuDbgInode(dentry->d_inode);
		goto out_dput;
	}

 accept:
	LKTRLabel(accept);
	inode = dentry->d_inode;
#if 0
	/* support branch manupilation and udba on nfs server */
	sigen = au_sigen(sb);
	if (unlikely(au_digen(dentry) != sigen
		     || au_iigen(inode) != sigen)) {
		int err;

		//lktr_set_pid(current->pid, LktrArrayPid);
		//au_fset_si(au_sbi(dentry->d_sb), FAILED_REFRESH_DIRS);
		di_write_lock_child(dentry);
		err = au_reval_dpath(dentry, sigen);
		di_write_unlock(dentry);
		//lktr_clear_pid(current->pid, LktrArrayPid);
		if (unlikely(err < 0))
			goto out_dput;
	}
#endif

	h_inode = NULL;
	ii_read_lock_child(inode);
	if (au_ibstart(inode) <= bindex && bindex <= au_ibend(inode))
		h_inode = au_h_iptr(inode, bindex);
	ii_read_unlock(inode);
#if 0
	/* support silly-rename */
	if (h_inode
	    && h_inode->i_generation != fh[Fh_h_igen])
		goto out_dput;
	if (acceptable(context, dentry))
		goto out; /* success */
#else
	if (h_inode
	    && h_inode->i_generation == fh[Fh_h_igen]
	    && acceptable(context, dentry))
		goto out; /* success */
#endif

 out_dput:
	LKTRLabel(out_dput);
	dput(dentry);
 out_stale:
	LKTRLabel(out_stale);
	dentry = ERR_PTR(-ESTALE);
 out:
	LKTRLabel(out);
	lockdep_on();
	si_read_unlock(sb);
	AuTraceErrPtr(dentry);
	return dentry;
}

static struct dentry *
aufs_fh_to_dentry(struct super_block *sb, struct fid *fid, int fh_len,
		  int fh_type)
{
	return aufs_decode_fh(sb, fid->raw, fh_len, fh_type, h_acceptable,
			      /*context*/NULL);
}

#if 0 /* reserved for future use */
/* support subtreecheck option */
static struct dentry *au_fh_to_parent(struct super_block *sb, struct fid *fid,
				      int fh_len, int fh_type)
{
}
#endif

/* ---------------------------------------------------------------------- */

static int aufs_encode_fh(struct dentry *dentry, __u32 *fh, int *max_len,
			  int connectable)
{
	int err;
	struct super_block *sb, *h_sb;
	struct inode *inode, *h_inode, *dir;
	aufs_bindex_t bindex;
	union conv u;
	struct dentry *parent, *h_parent;

	BUILD_BUG_ON(sizeof(u.ino) != sizeof(u.a));
	LKTRTrace("%.*s, max %d, conn %d\n",
		  AuDLNPair(dentry), *max_len, connectable);
	AuDebugOn(au_test_anon(dentry));
	inode = dentry->d_inode;
	AuDebugOn(!inode);
	parent = dget_parent(dentry);
	AuDebugOn(au_test_anon(parent));

	err = -ENOSPC;
	if (unlikely(*max_len <= Fh_tail)) {
		AuWarn1("NFSv2 client (max_len %d)?\n", *max_len);
		goto out;
	}

	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);
	di_read_lock_child(dentry, AuLock_IR);
	di_read_lock_parent(parent, AuLock_IR);
#ifdef CONFIG_AUFS_DEBUG
	if (unlikely(!au_opt_test_xino(au_mntflags(sb))))
		AuWarn1("NFS-exporting requires xino\n");
#endif

	err = -EPERM;
	bindex = au_dbstart(dentry);
	h_sb = au_sbr_sb(sb, bindex);
	if (unlikely(!h_sb->s_export_op)) {
		AuErr1("%s branch is not exportable\n", au_sbtype(h_sb));
		goto out_unlock;
	}

	fh[Fh_br_id] = au_sbr_id(sb, bindex);
	fh[Fh_sigen] = au_sigen(sb);
	encode_ino(fh + Fh_ino, inode->i_ino);
	dir = parent->d_inode;
	encode_ino(fh + Fh_dir_ino, dir->i_ino);
	h_inode = au_h_dptr(dentry, bindex)->d_inode;
	encode_ino(fh + Fh_h_ino, h_inode->i_ino);
	fh[Fh_h_igen] = h_inode->i_generation;

	*max_len -= Fh_tail;
	h_parent = au_h_dptr(parent, bindex);
	AuDebugOn(au_test_anon(h_parent));
	/* in linux-2.6.24, it takes struct fid * as file handle */
	fh[Fh_h_type] = exportfs_encode_fh(h_parent, (void *)(fh + Fh_tail),
					   max_len, connectable);
	err = fh[Fh_h_type];
	*max_len += Fh_tail;
	/* todo: macros? */
	if (err != 255)
		err = 2;
	else
		AuWarn1("%s encode_fh failed\n", au_sbtype(h_sb));

 out_unlock:
	di_read_unlock(parent, AuLock_IR);
	aufs_read_unlock(dentry, AuLock_IR);
 out:
	dput(parent);
	AuTraceErr(err);
	if (unlikely(err < 0))
		err = 255;
	return err;
}

/* ---------------------------------------------------------------------- */

struct export_operations aufs_export_op = {
	.fh_to_dentry	= aufs_fh_to_dentry,
	.encode_fh	= aufs_encode_fh
};
