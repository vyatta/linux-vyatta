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
 * workqueue for asynchronous/super-io/delegated operations
 *
 * $Id: wkq.c,v 1.12 2008/09/08 02:40:15 sfjro Exp $
 */

#include <linux/module.h>
#include "aufs.h"

struct au_wkq *au_wkq;

struct au_cred {
#ifdef CONFIG_AUFS_DLGT
	int umask;
	uid_t fsuid;
	gid_t fsgid;
	kernel_cap_t cap_effective, cap_inheritable, cap_permitted;
#if 0 /* reserved for future use */
	unsigned keep_capabilities:1;
	struct user_struct *user;
	struct fs_struct *fs;
	struct nsproxy *nsproxy;
#endif
#endif
};

struct au_wkinfo {
	struct work_struct wk;
	struct super_block *sb;

	unsigned int flags;
	struct au_cred cred;

	au_wkq_func_t func;
	void *args;

	atomic_t *busyp;
	struct completion *comp;
};

/* ---------------------------------------------------------------------- */

#ifdef CONFIG_AUFS_DLGT
static void cred_store(struct au_cred *cred)
{
	cred->umask = current->fs->umask;
	cred->fsuid = current->fsuid;
	cred->fsgid = current->fsgid;
	cred->cap_effective = current->cap_effective;
	cred->cap_inheritable = current->cap_inheritable;
	cred->cap_permitted = current->cap_permitted;
}

static void cred_revert(struct au_cred *cred)
{
	AuDebugOn(!au_test_wkq(current));
	current->fs->umask = cred->umask;
	current->fsuid = cred->fsuid;
	current->fsgid = cred->fsgid;
	current->cap_effective = cred->cap_effective;
	current->cap_inheritable = cred->cap_inheritable;
	current->cap_permitted = cred->cap_permitted;
}

static void cred_switch(struct au_cred *old, struct au_cred *new)
{
	cred_store(old);
	cred_revert(new);
}

static void dlgt_cred_store(unsigned int flags, struct au_wkinfo *wkinfo)
{
	if (unlikely(au_ftest_wkq(flags, DLGT)))
		cred_store(&wkinfo->cred);
}

static void dlgt_func(struct au_wkinfo *wkinfo)
{
	if (!au_ftest_wkq(wkinfo->flags, DLGT))
		wkinfo->func(wkinfo->args);
	else {
		struct au_cred cred;
		cred_switch(&cred, &wkinfo->cred);
		wkinfo->func(wkinfo->args);
		cred_revert(&cred);
	}
}
#else
static void dlgt_cred_store(unsigned int flags, struct au_wkinfo *wkinfo)
{
	/* empty */
}

static void dlgt_func(struct au_wkinfo *wkinfo)
{
	wkinfo->func(wkinfo->args);
}
#endif /* CONFIG_AUFS_DLGT */

/* ---------------------------------------------------------------------- */

static void update_busy(struct au_wkq *wkq, struct au_wkinfo *wkinfo)
{
#ifdef CONFIG_AUFS_STAT
	unsigned int new, old;

	do {
		new = atomic_read(wkinfo->busyp);
		old = wkq->max_busy;
		if (new <= old)
			break;
	} while (cmpxchg(&wkq->max_busy, old, new) == old);
#endif
}

static int enqueue(struct au_wkq *wkq, struct au_wkinfo *wkinfo)
{
	AuTraceEnter();

	wkinfo->busyp = &wkq->busy;
	update_busy(wkq, wkinfo);
	if (au_ftest_wkq(wkinfo->flags, WAIT))
		return !queue_work(wkq->q, &wkinfo->wk);
	else
		return !schedule_work(&wkinfo->wk);
}

static void do_wkq(struct au_wkinfo *wkinfo)
{
	unsigned int idle, n;
	int i, idle_idx;

	AuTraceEnter();

	while (1) {
		if (au_ftest_wkq(wkinfo->flags, WAIT)) {
			idle_idx = 0;
			idle = UINT_MAX;
			for (i = 0; i < aufs_nwkq; i++) {
				n = atomic_inc_return(&au_wkq[i].busy);
				if (n == 1 && !enqueue(au_wkq + i, wkinfo))
					return; /* success */

				if (n < idle) {
					idle_idx = i;
					idle = n;
				}
				atomic_dec_return(&au_wkq[i].busy);
			}
		} else
			idle_idx = aufs_nwkq;

		atomic_inc_return(&au_wkq[idle_idx].busy);
		if (!enqueue(au_wkq + idle_idx, wkinfo))
			return; /* success */

		/* impossible? */
		AuWarn1("failed to queue_work()\n");
		yield();
	}
}

static void wkq_func(struct work_struct *wk)
{
	struct au_wkinfo *wkinfo = container_of(wk, struct au_wkinfo, wk);

	LKTRTrace("wkinfo{0x%x, %p, %p, %p}\n",
		  wkinfo->flags, wkinfo->func, wkinfo->busyp, wkinfo->comp);

	dlgt_func(wkinfo);
	atomic_dec_return(wkinfo->busyp);
	if (au_ftest_wkq(wkinfo->flags, WAIT))
		complete(wkinfo->comp);
	else {
		kobject_put(&au_sbi(wkinfo->sb)->si_kobj);
		module_put(THIS_MODULE);
		kfree(wkinfo);
	}
}

#if defined(CONFIG_4KSTACKS) || defined(Test4KSTACKS)
#define AuWkqCompDeclare(name)	struct completion *comp = NULL

static int au_wkq_comp_alloc(struct au_wkinfo *wkinfo, struct completion **comp)
{
	*comp = kmalloc(sizeof(**comp), GFP_NOFS);
	if (*comp) {
		init_completion(*comp);
		wkinfo->comp = *comp;
		return 0;
	}
	return -ENOMEM;
}

static void au_wkq_comp_free(struct completion *comp)
{
	kfree(comp);
}

#else

#define AuWkqCompDeclare(name) \
	DECLARE_COMPLETION_ONSTACK(_ ## name); \
	struct completion *comp = &_ ## name

static int au_wkq_comp_alloc(struct au_wkinfo *wkinfo, struct completion **comp)
{
	wkinfo->comp = *comp;
	return 0;
}

static void au_wkq_comp_free(struct completion *comp)
{
	/* empty */
}
#endif /* 4KSTACKS */

int au_wkq_run(au_wkq_func_t func, void *args, struct super_block *sb,
	       unsigned int flags)
{
	int err;
	AuWkqCompDeclare(comp);
	struct au_wkinfo _wkinfo = {
		.flags	= flags,
		.func	= func,
		.args	= args
	}, *wkinfo = &_wkinfo;
	const unsigned char do_wait = au_ftest_wkq(flags, WAIT);

	LKTRTrace("0x%x\n", flags);
#if 1 /* tmp debug */
	if (au_test_wkq(current))
		au_dbg_blocked();
#endif
	AuDebugOn(au_test_wkq(current));

	if (do_wait) {
		err = au_wkq_comp_alloc(wkinfo, &comp);
		if (unlikely(err))
			goto out;
	} else {
		AuDebugOn(!sb);
		/*
		 * wkq_func() must free this wkinfo.
		 * it highly depends upon the implementation of workqueue.
		 */
		err = -ENOMEM;
		wkinfo = kmalloc(sizeof(*wkinfo), GFP_NOFS);
		if (unlikely(!wkinfo))
			goto out;

		err = 0;
		wkinfo->sb = sb;
		wkinfo->flags = flags;
		wkinfo->func = func;
		wkinfo->args = args;
		wkinfo->comp = NULL;
		kobject_get(&au_sbi(sb)->si_kobj);
		__module_get(THIS_MODULE);
	}

	INIT_WORK(&wkinfo->wk, wkq_func);
	dlgt_cred_store(flags, wkinfo);
	do_wkq(wkinfo);
	if (do_wait) {
		/* no timeout, no interrupt */
		wait_for_completion(wkinfo->comp);
		au_wkq_comp_free(comp);
	}
 out:
	AuTraceErr(err);
	return err;
}

int au_wkq_nowait(au_wkq_func_t func, void *args, struct super_block *sb,
		  int dlgt)
{
	int err;
	unsigned int flags = !AuWkq_WAIT;

	AuTraceEnter();

	if (unlikely(dlgt))
		au_fset_wkq(flags, DLGT);
	atomic_inc_return(&au_sbi(sb)->si_nowait.nw_len);
	err = au_wkq_run(func, args, sb, flags);
	if (unlikely(err))
		atomic_dec_return(&au_sbi(sb)->si_nowait.nw_len);

	return err;
}

/* ---------------------------------------------------------------------- */

void au_wkq_fin(void)
{
	int i;

	AuTraceEnter();

	for (i = 0; i < aufs_nwkq; i++)
		if (au_wkq[i].q && !IS_ERR(au_wkq[i].q))
			destroy_workqueue(au_wkq[i].q);
	kfree(au_wkq);
}

int __init au_wkq_init(void)
{
	int err, i;
	struct au_wkq *nowaitq;

	LKTRTrace("%d\n", aufs_nwkq);

	/* '+1' is for accounting  of nowait queue */
	err = -ENOMEM;
	au_wkq = kcalloc(aufs_nwkq + 1, sizeof(*au_wkq), GFP_NOFS);
	if (unlikely(!au_wkq))
		goto out;

	err = 0;
	for (i = 0; i < aufs_nwkq; i++) {
		au_wkq[i].q = create_singlethread_workqueue(AUFS_WKQ_NAME);
		if (au_wkq[i].q && !IS_ERR(au_wkq[i].q)) {
			atomic_set(&au_wkq[i].busy, 0);
			au_wkq_max_busy_init(au_wkq + i);
			continue;
		}

		err = PTR_ERR(au_wkq[i].q);
		au_wkq_fin();
		break;
	}

	/* nowait accounting */
	nowaitq = au_wkq + aufs_nwkq;
	atomic_set(&nowaitq->busy, 0);
	au_wkq_max_busy_init(nowaitq);
	nowaitq->q = NULL;
	/* smp_mb(); */ /* atomic_set */

 out:
	AuTraceErr(err);
	return err;
}
