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
 * external inode number translation table and bitmap
 *
 * $Id: xino.c,v 1.15 2008/09/08 02:40:21 sfjro Exp $
 */

#include <linux/uaccess.h>
#include "aufs.h"

/* ---------------------------------------------------------------------- */

static ssize_t xino_fread(au_readf_t func, struct file *file, void *buf,
			  size_t size, loff_t *pos)
{
	ssize_t err;
	mm_segment_t oldfs;

	LKTRTrace("%.*s, sz %lu, *pos %lld\n",
		  AuDLNPair(file->f_dentry), (unsigned long)size, *pos);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	do {
		/* todo: signal_pending? */
		err = func(file, (char __user *)buf, size, pos);
	} while (err == -EAGAIN || err == -EINTR);
	set_fs(oldfs);

#if 0 /* reserved for future use */
	if (err > 0)
		fsnotify_access(file->f_dentry);
#endif

	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

static ssize_t do_xino_fwrite(au_writef_t func, struct file *file, void *buf,
			      size_t size, loff_t *pos)
{
	ssize_t err;
	mm_segment_t oldfs;

	lockdep_off();
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	do {
		/* todo: signal_pending? */
		err = func(file, (const char __user *)buf, size, pos);
	} while (err == -EAGAIN || err == -EINTR);
	set_fs(oldfs);
	lockdep_on();

	if (err >= 0)
		au_update_fuse_h_inode(file->f_vfsmnt, file->f_dentry);
	/*ignore*/

#if 0 /* reserved for future use */
	if (err > 0)
		fsnotify_modify(file->f_dentry);
#endif

	AuTraceErr(err);
	return err;
}

struct do_xino_fwrite_args {
	ssize_t *errp;
	au_writef_t func;
	struct file *file;
	void *buf;
	size_t size;
	loff_t *pos;
};

static void call_do_xino_fwrite(void *args)
{
	struct do_xino_fwrite_args *a = args;
	*a->errp = do_xino_fwrite(a->func, a->file, a->buf, a->size, a->pos);
}

static ssize_t xino_fwrite(au_writef_t func, struct file *file, void *buf,
			   size_t size, loff_t *pos)
{
	ssize_t err;

	LKTRTrace("%.*s, sz %lu, *pos %lld\n",
		  AuDLNPair(file->f_dentry), (unsigned long)size, *pos);

	/* todo: signal block and no wkq? */
	/*
	 * it breaks RLIMIT_FSIZE and normal user's limit,
	 * users should care about quota and real 'filesystem full.'
	 */
	if (!au_test_wkq(current)) {
		int wkq_err;
		struct do_xino_fwrite_args args = {
			.errp	= &err,
			.func	= func,
			.file	= file,
			.buf	= buf,
			.size	= size,
			.pos	= pos
		};
		wkq_err = au_wkq_wait(call_do_xino_fwrite, &args, /*dlgt*/0);
		if (unlikely(wkq_err))
			err = wkq_err;
	} else
		err = do_xino_fwrite(func, file, buf, size, pos);

	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

struct xino_do_trunc_args {
	struct super_block *sb;
	struct au_branch *br;
};

static void xino_do_trunc(void *_args)
{
	struct xino_do_trunc_args *args = _args;
	struct super_block *sb;
	aufs_bindex_t bindex;
	int err;
	struct file *file;
	struct inode *dir;
	struct au_sbinfo *sbinfo;
	struct kobject *kobj;

	err = 0;
	sb = args->sb;
	dir = sb->s_root->d_inode;
	si_noflush_write_lock(sb);
	ii_read_lock_parent(dir);
	bindex = au_br_index(sb, args->br->br_id);
	AuDebugOn(bindex < 0);
	err = au_xino_trunc(sb, bindex);
	if (unlikely(err))
		goto out;

	file = args->br->br_xino.xi_file;
	au_update_fuse_h_inode(args->br->br_mnt, file->f_dentry); /*ignore*/
	if (file->f_dentry->d_inode->i_blocks >= args->br->br_xino_upper)
		args->br->br_xino_upper += AUFS_XINO_TRUNC_STEP;

 out:
	ii_read_unlock(dir);
	if (unlikely(err))
		AuWarn("err b%d, (%d)\n", bindex, err);
	atomic_dec_return(&args->br->br_xino_running);
	au_br_put(args->br);
	sbinfo = au_sbi(sb);
	kobj = &sbinfo->si_kobj;
	au_nwt_done(&sbinfo->si_nowait);
	si_write_unlock(sb);
	kobject_put(kobj);
	kfree(args);
}

static void xino_try_trunc(struct super_block *sb, struct au_branch *br)
{
	struct xino_do_trunc_args *args;
	struct au_sbinfo *sbinfo;
	struct file *file = br->br_xino.xi_file;
	int wkq_err;

	au_update_fuse_h_inode(br->br_mnt, file->f_dentry); /*ignore*/
	if (file->f_dentry->d_inode->i_blocks < br->br_xino_upper)
		return;
	if (atomic_inc_return(&br->br_xino_running) > 1)
		goto out;

	/* lock and kfree() will be called in trunc_xino() */
	args = kmalloc(sizeof(*args), GFP_NOFS);
	if (unlikely(!args)) {
		AuErr1("no memory\n");
		goto out_args;
	}

	sbinfo = au_sbi(sb);
	kobject_get(&sbinfo->si_kobj);
	au_br_get(br);
	args->sb = sb;
	args->br = br;
	wkq_err = au_wkq_nowait(xino_do_trunc, args, sb, /*dlgt*/0);
	if (!wkq_err)
		return; /* success */

	AuErr("wkq %d\n", wkq_err);
	au_br_put(br);
	kobject_put(&sbinfo->si_kobj);

 out_args:
	kfree(args);
 out:
	atomic_dec_return(&br->br_xino_running);
}

/* ---------------------------------------------------------------------- */

#define Au_LOFF_MAX	((loff_t)LLONG_MAX)

static int au_xino_do_write(au_writef_t write, struct file *file,
			    ino_t h_ino, struct au_xino_entry *xinoe)
{
	loff_t pos;
	ssize_t sz;

	AuTraceEnter();

	pos = h_ino;
	if (unlikely(Au_LOFF_MAX / sizeof(*xinoe) - 1 < pos)) {
		AuIOErr1("too large hi%lu\n", (unsigned long)h_ino);
		return -EFBIG;
	}
	pos *= sizeof(*xinoe);
	sz = xino_fwrite(write, file, xinoe, sizeof(*xinoe), &pos);
	if (sz == sizeof(*xinoe))
		return 0; /* success */

	AuIOErr("write failed (%ld)\n", (long)sz);
	return -EIO;
}

/*
 * write @ino to the xinofile for the specified branch{@sb, @bindex}
 * at the position of @_ino.
 * when @ino is zero, it is written to the xinofile and means no entry.
 */
int au_xino_write(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
		  struct au_xino_entry *xinoe)
{
	int err;
	struct file *file;
	struct au_branch *br;
	unsigned int mnt_flags;

	LKTRTrace("b%d, hi%lu, i%lu\n",
		  bindex, (unsigned long)h_ino, (unsigned long)xinoe->ino);
	BUILD_BUG_ON(sizeof(long long) != sizeof(Au_LOFF_MAX)
		     || ((loff_t)-1) > 0);

	mnt_flags = au_mntflags(sb);
	if (unlikely(!au_opt_test_xino(mnt_flags)))
		return 0;

	br = au_sbr(sb, bindex);
	file = br->br_xino.xi_file;
	AuDebugOn(!file);

	err = au_xino_do_write(au_sbi(sb)->si_xwrite, file, h_ino, xinoe);
	if (!err) {
		if (unlikely(au_opt_test(mnt_flags, TRUNC_XINO)
			     && au_test_trunc_xino(br->br_mnt->mnt_sb)))
			xino_try_trunc(sb, br);
		return 0; /* success */
	}

	AuIOErr("write failed (%d)\n", err);
	return -EIO;
}

/* ---------------------------------------------------------------------- */

static const int page_bits = (int)PAGE_SIZE * BITS_PER_BYTE;
static ino_t xib_calc_ino(unsigned long pindex, int bit)
{
	ino_t ino;

	AuDebugOn(bit < 0 || page_bits <= bit);
	ino = AUFS_FIRST_INO + pindex * page_bits + bit;
	return ino;
}

static void xib_calc_bit(ino_t ino, unsigned long *pindex, int *bit)
{
	AuDebugOn(ino < AUFS_FIRST_INO);
	ino -= AUFS_FIRST_INO;
	*pindex = ino / page_bits;
	*bit = ino % page_bits;
}

static int xib_pindex(struct super_block *sb, unsigned long pindex)
{
	int err;
	struct au_sbinfo *sbinfo;
	loff_t pos;
	ssize_t sz;
	struct file *xib;
	unsigned long *p;

	LKTRTrace("pindex %lu\n", pindex);
	sbinfo = au_sbi(sb);
	MtxMustLock(&sbinfo->si_xib_mtx);
	AuDebugOn(pindex > ULONG_MAX / PAGE_SIZE
		  || !au_opt_test_xino(sbinfo->si_mntflags));

	if (pindex == sbinfo->si_xib_last_pindex)
		return 0;

	xib = sbinfo->si_xib;
	p = sbinfo->si_xib_buf;
	pos = sbinfo->si_xib_last_pindex;
	pos *= PAGE_SIZE;
	sz = xino_fwrite(sbinfo->si_xwrite, xib, p, PAGE_SIZE, &pos);
	if (unlikely(sz != PAGE_SIZE))
		goto out;

	pos = pindex;
	pos *= PAGE_SIZE;
	if (i_size_read(xib->f_dentry->d_inode) >= pos + PAGE_SIZE)
		sz = xino_fread(sbinfo->si_xread, xib, p, PAGE_SIZE, &pos);
	else {
		memset(p, 0, PAGE_SIZE);
		sz = xino_fwrite(sbinfo->si_xwrite, xib, p, PAGE_SIZE, &pos);
	}
	if (sz == PAGE_SIZE) {
		sbinfo->si_xib_last_pindex = pindex;
		return 0; /* success */
	}

 out:
	AuIOErr1("write failed (%ld)\n", (long)sz);
	err = sz;
	if (sz >= 0)
		err = -EIO;
	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

int au_xino_write0(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
		   ino_t ino)
{
	int err, bit;
	unsigned long pindex;
	struct au_sbinfo *sbinfo;
	struct au_xino_entry xinoe = {
		.ino	= 0
	};

	LKTRTrace("b%d, hi%lu, i%lu\n",
		  bindex, (unsigned long)h_ino, (unsigned long)ino);

	if (unlikely(!au_opt_test_xino(au_mntflags(sb))))
		return 0;

	err = 0;
	sbinfo = au_sbi(sb);
	if (unlikely(ino)) {
		AuDebugOn(ino < AUFS_FIRST_INO);
		xib_calc_bit(ino, &pindex, &bit);
		AuDebugOn(page_bits <= bit);
		mutex_lock(&sbinfo->si_xib_mtx);
		err = xib_pindex(sb, pindex);
		if (!err) {
			clear_bit(bit, sbinfo->si_xib_buf);
			sbinfo->si_xib_next_bit = bit;
		}
		mutex_unlock(&sbinfo->si_xib_mtx);
	}

	if (!err)
		err = au_xino_write(sb, bindex, h_ino, &xinoe);
	return err;
}

ino_t au_xino_new_ino(struct super_block *sb)
{
	ino_t ino;
	struct au_sbinfo *sbinfo;
	int free_bit, err;
	unsigned long *p, pindex, ul, pend;
	struct file *file;

	AuTraceEnter();

	if (unlikely(!au_opt_test_xino(au_mntflags(sb))))
		return iunique(sb, AUFS_FIRST_INO);

	sbinfo = au_sbi(sb);
	mutex_lock(&sbinfo->si_xib_mtx);
	p = sbinfo->si_xib_buf;
	free_bit = sbinfo->si_xib_next_bit;
	if (free_bit < page_bits && !test_bit(free_bit, p))
		goto out; /* success */
	free_bit = find_first_zero_bit(p, page_bits);
	if (free_bit < page_bits)
		goto out; /* success */

	pindex = sbinfo->si_xib_last_pindex;
	for (ul = pindex - 1; ul < ULONG_MAX; ul--) {
		err = xib_pindex(sb, ul);
		if (unlikely(err))
			goto out_err;
		free_bit = find_first_zero_bit(p, page_bits);
		if (free_bit < page_bits)
			goto out; /* success */
	}

	file = sbinfo->si_xib;
	pend = i_size_read(file->f_dentry->d_inode) / PAGE_SIZE;
	for (ul = pindex + 1; ul <= pend; ul++) {
		err = xib_pindex(sb, ul);
		if (unlikely(err))
			goto out_err;
		free_bit = find_first_zero_bit(p, page_bits);
		if (free_bit < page_bits)
			goto out; /* success */
	}
	BUG();

 out:
	set_bit(free_bit, p);
	sbinfo->si_xib_next_bit++;
	pindex = sbinfo->si_xib_last_pindex;
	mutex_unlock(&sbinfo->si_xib_mtx);
	ino = xib_calc_ino(pindex, free_bit);
	LKTRTrace("i%lu\n", (unsigned long)ino);
	return ino;
 out_err:
	mutex_unlock(&sbinfo->si_xib_mtx);
	LKTRTrace("i0\n");
	return 0;
}

/*
 * read @ino from xinofile for the specified branch{@sb, @bindex}
 * at the position of @h_ino.
 * if @ino does not exist and @do_new is true, get new one.
 */
int au_xino_read(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
		 struct au_xino_entry *xinoe)
{
	int err;
	struct file *file;
	loff_t pos;
	ssize_t sz;
	struct au_sbinfo *sbinfo;

	LKTRTrace("b%d, hi%lu\n", bindex, (unsigned long)h_ino);

	xinoe->ino = 0;
	if (unlikely(!au_opt_test_xino(au_mntflags(sb))))
		return 0; /* no ino */

	err = 0;
	sbinfo = au_sbi(sb);
	pos = h_ino;
	if (unlikely(Au_LOFF_MAX / sizeof(*xinoe) - 1 < pos)) {
		AuIOErr1("too large hi%lu\n", (unsigned long)h_ino);
		return -EFBIG;
	}
	pos *= sizeof(*xinoe);

	file = au_sbr(sb, bindex)->br_xino.xi_file;
	AuDebugOn(!file);
	if (i_size_read(file->f_dentry->d_inode) < pos + sizeof(*xinoe))
		return 0; /* no ino */

	sz = xino_fread(sbinfo->si_xread, file, xinoe, sizeof(*xinoe), &pos);
	if (sz == sizeof(*xinoe))
		return 0; /* success */

	err = sz;
	if (unlikely(sz >= 0)) {
		err = -EIO;
		AuIOErr("xino read error (%ld)\n", (long)sz);
	}

	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

struct file *au_xino_create(struct super_block *sb, char *fname, int silent)
{
	struct file *file;
	int err;
	struct dentry *h_parent;
	struct inode *h_dir;
	struct vfsub_args vargs;

	LKTRTrace("%s\n", fname);

	/*
	 * at mount-time, and the xino file is the default path,
	 * hinotify is disabled so we have no inotify events to ignore.
	 * when a user specified the xino, we cannot get au_hdir to be ignored.
	 */
	vfsub_args_init(&vargs, /*ign*/NULL, /*dlgt*/0, 0);
	file = vfsub_filp_open(fname, O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE,
			       S_IRUGO | S_IWUGO);
	if (IS_ERR(file)) {
		if (!silent)
			AuErr("open %s(%ld)\n", fname, PTR_ERR(file));
		return file;
	}

	/* keep file count */
	h_parent = dget_parent(file->f_dentry);
	h_dir = h_parent->d_inode;
	mutex_lock_nested(&h_dir->i_mutex, AuLsc_I_PARENT);
	err = vfsub_unlink(h_dir, file->f_dentry, &vargs);
	mutex_unlock(&h_dir->i_mutex);
	dput(h_parent);
	if (unlikely(err)) {
		if (!silent)
			AuErr("unlink %s(%d)\n", fname, err);
		goto out;
	}

	if (sb != file->f_dentry->d_sb)
		return file; /* success */

	if (!silent)
		AuErr("%s must be outside\n", fname);
	err = -EINVAL;

 out:
	fput(file);
	file = ERR_PTR(err);
	return file;
}

/*
 * find another branch who is on the same filesystem of the specified
 * branch{@btgt}. search until @bend.
 */
static int is_sb_shared(struct super_block *sb, aufs_bindex_t btgt,
			aufs_bindex_t bend)
{
	aufs_bindex_t bindex;
	struct super_block *tgt_sb = au_sbr_sb(sb, btgt);

	for (bindex = 0; bindex < btgt; bindex++)
		if (unlikely(tgt_sb == au_sbr_sb(sb, bindex)))
			return bindex;
	for (bindex++; bindex <= bend; bindex++)
		if (unlikely(tgt_sb == au_sbr_sb(sb, bindex)))
			return bindex;
	return -1;
}

/*
 * create a new xinofile at the same place/path as @base_file.
 */
static
struct file *au_xino_create2(struct super_block *sb, struct file *base_file,
			     struct file *copy_src)
{
	struct file *file;
	int err;
	struct dentry *base, *dentry, *parent;
	struct inode *dir, *inode;
	struct qstr *name;
	struct au_hinode *hdir;
	struct au_branch *br;
	aufs_bindex_t bindex;
	struct au_hin_ignore ign;
	struct vfsub_args vargs;
	struct au_ndx ndx = {
		.nfsmnt	= NULL,
		.flags	= 0,
		.nd	= NULL,
		/* .br	= NULL */
	};

	base = base_file->f_dentry;
	LKTRTrace("%.*s\n", AuDLNPair(base));
	parent = base->d_parent; /* dir inode is locked */
	dir = parent->d_inode;
	IMustLock(dir);

	file = ERR_PTR(-EINVAL);
	if (unlikely(au_test_nfs(parent->d_sb)))
		goto out;

	/* do not superio, nor NFS. */
	name = &base->d_name;
	dentry = au_lkup_one(name->name, parent, name->len, &ndx);
	if (IS_ERR(dentry)) {
		file = (void *)dentry;
		AuErr("%.*s lookup err %ld\n", AuLNPair(name), PTR_ERR(dentry));
		goto out;
	}

	hdir = NULL;
	br = au_xino_def_br(au_sbi(sb));
	if (br) {
		bindex = au_find_bindex(sb, br);
		if (bindex >= 0)
			hdir = au_hi(sb->s_root->d_inode, bindex);
	}
	vfsub_args_init(&vargs, &ign, 0, 0);
	vfsub_ign_hinode(&vargs, IN_CREATE, hdir);
	err = vfsub_create(dir, dentry, S_IRUGO | S_IWUGO, NULL, &vargs);
	if (unlikely(err)) {
		file = ERR_PTR(err);
		AuErr("%.*s create err %d\n", AuLNPair(name), err);
		goto out_dput;
	}
	file = dentry_open(dget(dentry), mntget(base_file->f_vfsmnt),
			   O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE);
	if (IS_ERR(file)) {
		AuErr("%.*s open err %ld\n", AuLNPair(name), PTR_ERR(file));
		goto out_dput;
	}
	vfsub_args_reinit(&vargs);
	vfsub_ign_hinode(&vargs, IN_DELETE, hdir);
	err = vfsub_unlink(dir, dentry, &vargs);
	if (unlikely(err)) {
		AuErr("%.*s unlink err %d\n", AuLNPair(name), err);
		goto out_fput;
	}

	if (copy_src) {
		inode = copy_src->f_dentry->d_inode;
		err = au_copy_file(file, copy_src, i_size_read(inode),
				   hdir, sb, &vargs);
		if (unlikely(err)) {
			AuErr("%.*s copy err %d\n", AuLNPair(name), err);
			goto out_fput;
		}
	}
	goto out_dput; /* success */

 out_fput:
	fput(file);
	file = ERR_PTR(err);
 out_dput:
	dput(dentry);
 out:
	AuTraceErrPtr(file);
	return file;
}

/* ---------------------------------------------------------------------- */

/*
 * initialize the xinofile for the specified branch{@sb, @bindex}
 * at the place/path where @base_file indicates.
 * test whether another branch is on the same filesystem or not,
 * if @do_test is true.
 */
int au_xino_br(struct super_block *sb, struct au_branch *br, ino_t h_ino,
	       struct file *base_file, int do_test)
{
	int err;
	struct au_branch *shared_br;
	aufs_bindex_t bshared, bend, bindex;
	unsigned char do_create;
	struct inode *dir;
	struct au_xino_entry xinoe;
	struct dentry *parent;
	struct file *file;
	struct super_block *tgt_sb;

	LKTRTrace("base_file %p, do_test %d\n", base_file, do_test);
	SiMustWriteLock(sb);
	AuDebugOn(!au_opt_test_xino(au_mntflags(sb)));
	AuDebugOn(br->br_xino.xi_file);

	do_create = 1;
	bshared = -1;
	shared_br = NULL;
	bend = au_sbend(sb);
	if (do_test) {
		tgt_sb = br->br_mnt->mnt_sb;
		for (bindex = 0; bindex <= bend; bindex++)
			if (unlikely(tgt_sb == au_sbr_sb(sb, bindex))) {
				bshared = bindex;
				break;
			}
	}
	if (unlikely(bshared >= 0)) {
		shared_br = au_sbr(sb, bshared);
		do_create = !shared_br->br_xino.xi_file;
	}

	if (do_create) {
		parent = dget_parent(base_file->f_dentry);
		dir = parent->d_inode;
		mutex_lock_nested(&dir->i_mutex, AuLsc_I_PARENT);
		file = au_xino_create2(sb, base_file, NULL);
		mutex_unlock(&dir->i_mutex);
		dput(parent);
		err = PTR_ERR(file);
		if (IS_ERR(file))
			goto out;
		br->br_xino.xi_file = file;
	} else {
		br->br_xino.xi_file = shared_br->br_xino.xi_file;
		get_file(br->br_xino.xi_file);
	}

	xinoe.ino = AUFS_ROOT_INO;
#if 0 /* reserved for future use */
	xinoe.h_gen = h_inode->i_generation;
	WARN_ON(xinoe.h_gen == AuXino_INVALID_HGEN);
#endif
	err = au_xino_do_write(au_sbi(sb)->si_xwrite, br->br_xino.xi_file,
			       h_ino, &xinoe);
	if (!err)
		return 0; /* success */


 out:
	AuTraceErr(err);
	return err;
}

/* too slow */
static int do_xib_restore(struct super_block *sb, struct file *file, void *page)
{
	int err, bit;
	struct au_sbinfo *sbinfo;
	au_readf_t func;
	loff_t pos, pend;
	ssize_t sz;
	struct au_xino_entry *xinoe;
	unsigned long pindex;

	AuTraceEnter();
	SiMustWriteLock(sb);

	err = 0;
	sbinfo = au_sbi(sb);
	func = sbinfo->si_xread;
	pend = i_size_read(file->f_dentry->d_inode);
#ifdef CONFIG_AUFS_DEBUG
	if (unlikely(pend > (1 << 22)))
		AuWarn("testing a large xino file %lld\n", (long long)pend);
#endif
	pos = 0;
	while (pos < pend) {
		sz = xino_fread(func, file, page, PAGE_SIZE, &pos);
		err = sz;
		if (unlikely(sz <= 0))
			goto out;

		err = 0;
		for (xinoe = page; sz > 0; xinoe++, sz -= sizeof(xinoe)) {
			if (unlikely(xinoe->ino < AUFS_FIRST_INO))
				continue;

			xib_calc_bit(xinoe->ino, &pindex, &bit);
			AuDebugOn(page_bits <= bit);
			err = xib_pindex(sb, pindex);
			if (!err)
				set_bit(bit, sbinfo->si_xib_buf);
			else
				goto out;
		}
	}

 out:
	AuTraceErr(err);
	return err;
}

static int xib_restore(struct super_block *sb)
{
	int err;
	aufs_bindex_t bindex, bend;
	void *page;

	AuTraceEnter();

	err = -ENOMEM;
	page = (void *)__get_free_page(GFP_NOFS);
	if (unlikely(!page))
		goto out;

	err = 0;
	bend = au_sbend(sb);
	for (bindex = 0; !err && bindex <= bend; bindex++)
		if (!bindex || is_sb_shared(sb, bindex, bindex - 1) < 0)
			err = do_xib_restore
				(sb, au_sbr(sb, bindex)->br_xino.xi_file, page);
		else
			LKTRTrace("b%d\n", bindex);
	free_page((unsigned long)page);

 out:
	AuTraceErr(err);
	return err;
}

int au_xib_trunc(struct super_block *sb)
{
	int err;
	struct au_sbinfo *sbinfo;
	unsigned long *p;
	loff_t pos;
	ssize_t sz;
	struct dentry *parent;
	struct inode *dir;
	struct file *file;
	unsigned int mnt_flags;

	AuTraceEnter();
	SiMustWriteLock(sb);

	mnt_flags = au_mntflags(sb);
	if (unlikely(!au_opt_test_xino(mnt_flags)))
		return 0;

	sbinfo = au_sbi(sb);
	parent = dget_parent(sbinfo->si_xib->f_dentry);
	dir = parent->d_inode;
	mutex_lock_nested(&dir->i_mutex, AuLsc_I_PARENT);
	file = au_xino_create2(sb, sbinfo->si_xib, NULL);
	mutex_unlock(&dir->i_mutex);
	dput(parent);
	err = PTR_ERR(file);
	if (IS_ERR(file))
		goto out;
	fput(sbinfo->si_xib);
	sbinfo->si_xib = file;

	p = sbinfo->si_xib_buf;
	memset(p, 0, PAGE_SIZE);
	pos = 0;
	sz = xino_fwrite(sbinfo->si_xwrite, sbinfo->si_xib, p, PAGE_SIZE, &pos);
	if (unlikely(sz != PAGE_SIZE)) {
		err = sz;
		AuIOErr("err %d\n", err);
		if (sz >= 0)
			err = -EIO;
		goto out;
	}

	if (au_opt_test_xino(mnt_flags)) {
		mutex_lock(&sbinfo->si_xib_mtx);
		err = xib_restore(sb);
		mutex_unlock(&sbinfo->si_xib_mtx);
#if 0 /* reserved for future use */
	} else {
		/* is it really safe? */
		/* dont trust BKL */
		AuDebugOn(!kernel_locked());
		ino = AUFS_FIRST_INO;
		list_for_each_entry(inode, &sb->s_inodes, i_sb_list)
			if (ino < inode->i_ino)
				ino = inode->i_ino;

		/* make iunique to return larger than active max inode number */
		iunique(sb, ino);
		err = 0;
#endif
	}

out:
	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

/*
 * xino mount option handlers
 */
static au_readf_t find_readf(struct file *h_file)
{
	const struct file_operations *fop = h_file->f_op;

	if (fop) {
		if (fop->read)
			return fop->read;
		if (fop->aio_read)
			return do_sync_read;
	}
	return ERR_PTR(-ENOSYS);
}

static au_writef_t find_writef(struct file *h_file)
{
	const struct file_operations *fop = h_file->f_op;

	if (fop) {
		if (fop->write)
			return fop->write;
		if (fop->aio_write)
			return do_sync_write;
	}
	return ERR_PTR(-ENOSYS);
}

/* xino bitmap */
static void xino_clear_xib(struct super_block *sb)
{
	struct au_sbinfo *sbinfo;

	AuTraceEnter();
	SiMustWriteLock(sb);

	sbinfo = au_sbi(sb);
	sbinfo->si_xread = NULL;
	sbinfo->si_xwrite = NULL;
	if (sbinfo->si_xib)
		fput(sbinfo->si_xib);
	sbinfo->si_xib = NULL;
	free_page((unsigned long)sbinfo->si_xib_buf);
	sbinfo->si_xib_buf = NULL;
}

static int au_xino_set_xib(struct super_block *sb, struct file *base)
{
	int err;
	struct au_sbinfo *sbinfo;
	struct file *file;
	loff_t pos;

	LKTRTrace("%.*s\n", AuDLNPair(base->f_dentry));
	SiMustWriteLock(sb);

	sbinfo = au_sbi(sb);
	file = au_xino_create2(sb, base, sbinfo->si_xib);
	err = PTR_ERR(file);
	if (IS_ERR(file))
		goto out;
	if (sbinfo->si_xib)
		fput(sbinfo->si_xib);
	sbinfo->si_xib = file;
	sbinfo->si_xread = find_readf(file);
	AuDebugOn(IS_ERR(sbinfo->si_xread));
	sbinfo->si_xwrite = find_writef(file);
	AuDebugOn(IS_ERR(sbinfo->si_xwrite));

	err = -ENOMEM;
	if (!sbinfo->si_xib_buf)
		sbinfo->si_xib_buf = (void *)get_zeroed_page(GFP_NOFS);
	if (unlikely(!sbinfo->si_xib_buf))
		goto out_unset;

	sbinfo->si_xib_last_pindex = 0;
	sbinfo->si_xib_next_bit = 0;

	/* no need to lock for i_size_read() */
	if (i_size_read(file->f_dentry->d_inode) < PAGE_SIZE) {
		pos = 0;
		err = xino_fwrite(sbinfo->si_xwrite, file, sbinfo->si_xib_buf,
				  PAGE_SIZE, &pos);
		if (unlikely(err != PAGE_SIZE))
			goto out_free;
	}
	err = 0;
	goto out; /* success */

 out_free:
	free_page((unsigned long)sbinfo->si_xib_buf);
	sbinfo->si_xib_buf = NULL;
	if (err >= 0)
		err = -EIO;
 out_unset:
	fput(sbinfo->si_xib);
	sbinfo->si_xib = NULL;
	sbinfo->si_xread = NULL;
	sbinfo->si_xwrite = NULL;
 out:
	AuTraceErr(err);
	return err;
}

/* xino for each branch */
static void xino_clear_br(struct super_block *sb)
{
	aufs_bindex_t bindex, bend;
	struct au_branch *br;

	AuTraceEnter();
	SiMustWriteLock(sb);

	bend = au_sbend(sb);
	for (bindex = 0; bindex <= bend; bindex++) {
		br = au_sbr(sb, bindex);
		if (unlikely(!br || !br->br_xino.xi_file))
			continue;

		fput(br->br_xino.xi_file);
		br->br_xino.xi_file = NULL;
	}
}

static int au_xino_set_br(struct super_block *sb, struct file *base)
{
	int err;
	aufs_bindex_t bindex, bend, bshared;
	struct {
		struct file *old, *new;
	} *fpair, *p;
	struct au_branch *br;
	struct au_xino_entry xinoe;
	struct inode *inode;
	au_writef_t writef;

	LKTRTrace("%.*s\n", AuDLNPair(base->f_dentry));
	SiMustWriteLock(sb);

	err = -ENOMEM;
	bend = au_sbend(sb);
	fpair = kcalloc(bend + 1, sizeof(*fpair), GFP_NOFS);
	if (unlikely(!fpair))
		goto out;

	inode = sb->s_root->d_inode;
	xinoe.ino = AUFS_ROOT_INO;
	writef = au_sbi(sb)->si_xwrite;
	for (bindex = 0, p = fpair; bindex <= bend; bindex++, p++) {
		br = au_sbr(sb, bindex);
		bshared = is_sb_shared(sb, bindex, bindex - 1);
		if (bshared >= 0) {
			/* shared xino */
			*p = fpair[bshared];
			get_file(p->new);
		}

		if (!p->new) {
			/* new xino */
			p->old = br->br_xino.xi_file;
			p->new = au_xino_create2(sb, base, br->br_xino.xi_file);
			err = PTR_ERR(p->new);
			if (IS_ERR(p->new)) {
				p->new = NULL;
				goto out_pair;
			}
		}

		err = au_xino_do_write(writef, p->new,
				       au_h_iptr(inode, bindex)->i_ino, &xinoe);
		if (unlikely(err))
			goto out_pair;
	}

	for (bindex = 0, p = fpair; bindex <= bend; bindex++, p++) {
		br = au_sbr(sb, bindex);
		AuDebugOn(p->old != br->br_xino.xi_file);
		if (br->br_xino.xi_file)
			fput(br->br_xino.xi_file);
		get_file(p->new);
		br->br_xino.xi_file = p->new;
	}

 out_pair:
	for (bindex = 0, p = fpair; bindex <= bend; bindex++, p++)
		if (p->new)
			fput(p->new);
		else
			break;
	kfree(fpair);
 out:
	AuTraceErr(err);
	return err;
}

void au_xino_clr(struct super_block *sb)
{
	struct au_sbinfo *sbinfo;

	AuTraceEnter();
	SiMustWriteLock(sb);

	xino_clear_xib(sb);
	xino_clear_br(sb);
	sbinfo = au_sbi(sb);
	/* lvalue, do not call au_mntflags() */
	au_opt_clr(sbinfo->si_mntflags, XINO);
	au_xino_def_br_set(NULL, sbinfo);
}

int au_xino_set(struct super_block *sb, struct au_opt_xino *xino, int remount)
{
	int err, skip;
	struct dentry *parent, *cur_parent;
	struct qstr *dname, *cur_name;
	struct file *cur_xino;
	struct inode *dir;
	struct au_sbinfo *sbinfo;

	LKTRTrace("remount %d\n", remount);
	SiMustWriteLock(sb);

	err = 0;
	sbinfo = au_sbi(sb);
	parent = dget_parent(xino->file->f_dentry);
	if (remount) {
		skip = 0;
		dname = &xino->file->f_dentry->d_name;
		cur_xino = sbinfo->si_xib;
		if (cur_xino) {
			cur_parent = dget_parent(cur_xino->f_dentry);
			cur_name = &cur_xino->f_dentry->d_name;
			skip = (cur_parent == parent
				&& dname->len == cur_name->len
				&& !memcmp(dname->name, cur_name->name,
					   dname->len));
			dput(cur_parent);
		}
		if (skip)
			goto out;
	}

	au_opt_set(sbinfo->si_mntflags, XINO);
	au_xino_def_br_set(NULL, sbinfo);
	dir = parent->d_inode;
	mutex_lock_nested(&dir->i_mutex, AuLsc_I_PARENT);
	err = au_xino_set_xib(sb, xino->file);
	if (!err)
		err = au_xino_set_br(sb, xino->file);
	mutex_unlock(&dir->i_mutex);
	if (!err)
		goto out; /* success */

	/* reset all */
	AuIOErr("failed creating xino(%d).\n", err);

 out:
	dput(parent);
	AuTraceErr(err);
	return err;
}

int au_xino_trunc(struct super_block *sb, aufs_bindex_t bindex)
{
	int err;
	struct au_branch *br;
	struct file *new_xino;
	struct super_block *h_sb;
	aufs_bindex_t bi, bend;
	struct dentry *parent;
	struct inode *dir;

	LKTRTrace("b%d\n", bindex);
	SiMustWriteLock(sb);

	err = -EINVAL;
	bend = au_sbend(sb);
	if (unlikely(bindex < 0 || bend < bindex))
		goto out;
	br = au_sbr(sb, bindex);
	if (unlikely(!br->br_xino.xi_file))
		goto out;

	parent = dget_parent(br->br_xino.xi_file->f_dentry);
	dir = parent->d_inode;
	mutex_lock_nested(&dir->i_mutex, AuLsc_I_PARENT);
	new_xino = au_xino_create2(sb, br->br_xino.xi_file,
				   br->br_xino.xi_file);
	mutex_unlock(&dir->i_mutex);
	dput(parent);
	err = PTR_ERR(new_xino);
	if (IS_ERR(new_xino))
		goto out;
	err = 0;
	fput(br->br_xino.xi_file);
	br->br_xino.xi_file = new_xino;

	h_sb = br->br_mnt->mnt_sb;
	for (bi = 0; bi <= bend; bi++) {
		if (unlikely(bi == bindex))
			continue;
		br = au_sbr(sb, bi);
		if (br->br_mnt->mnt_sb != h_sb)
			continue;

		fput(br->br_xino.xi_file);
		br->br_xino.xi_file = new_xino;
		get_file(new_xino);
	}

 out:
	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

/*
 * create a xinofile at the default place/path.
 */
struct file *au_xino_def(struct super_block *sb)
{
	struct file *file;
	aufs_bindex_t bend, bindex, bwr;
	char *page, *p;
	struct path path;
	struct dentry *root;

	AuTraceEnter();

	root = sb->s_root;
	bend = au_sbend(sb);
	bwr = -1;
	for (bindex = 0; bindex <= bend; bindex++)
		if (au_br_writable(au_sbr_perm(sb, bindex))
		    && !au_test_nfs(au_h_dptr(root, bindex)->d_sb)) {
			bwr = bindex;
			break;
		}

	if (bwr >= 0) {
		file = ERR_PTR(-ENOMEM);
		page = __getname();
		if (unlikely(!page))
			goto out;
		path.mnt = au_sbr_mnt(sb, bwr);
		path.dentry = au_h_dptr(root, bwr);
		p = d_path(&path, page, PATH_MAX - sizeof(AUFS_XINO_FNAME));
		file = (void *)p;
		if (!IS_ERR(p)) {
			strcat(p, "/" AUFS_XINO_FNAME);
			LKTRTrace("%s\n", p);
			file = au_xino_create(sb, p, /*silent*/0);
			if (!IS_ERR(file))
				au_xino_def_br_set(au_sbr(sb, bwr), au_sbi(sb));
		}
		__putname(page);
	} else {
		file = au_xino_create(sb, AUFS_XINO_DEFPATH, /*silent*/0);
		if (unlikely(au_test_nfs(file->f_dentry->d_sb))) {
			AuErr("xino or noxino option is required "
			      "since %s is NFS\n", AUFS_XINO_DEFPATH);
			fput(file);
			file = ERR_PTR(-EINVAL);
		}
		if (!IS_ERR(file))
			au_xino_def_br_set(NULL, au_sbi(sb));
	}

 out:
	AuTraceErrPtr(file);
	return file;
}
