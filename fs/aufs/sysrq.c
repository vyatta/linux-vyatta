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
 * magic sysrq hanlder
 *
 * $Id: sysrq.c,v 1.14 2009/01/26 06:24:45 sfjro Exp $
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
/* #include <linux/sysrq.h> */
#include "aufs.h"

#ifdef CONFIG_AUFS_DEBUG_LOCK
struct au_dbg_lock {
	struct list_head list;
	union {
		struct super_block	*sb;
		struct dentry		*dentry;
		struct inode		*inode;
		void			*any;
	};
	int flags;
	unsigned int lsc;
	pid_t pid;
};

static void au_dbg_reg(struct au_splhead *spl, void *any, int flags,
		       unsigned int lsc)
{
	struct au_dbg_lock *p = kmalloc(sizeof(*p), GFP_NOFS);

	if (p) {
		p->any = any;
		p->flags = flags;
		p->lsc = lsc;
		p->pid = current->pid;
		spin_lock(&spl->spin);
		list_add(&p->list, &spl->head);
		spin_unlock(&spl->spin);
	}
	WARN_ON(!p);
}

static void au_dbg_unreg(struct au_splhead *spl, void *any, int flags)
{
	struct au_dbg_lock *p, *tmp, *found;
	struct list_head *head = &spl->head;
	const pid_t pid = current->pid;

	found = NULL;
	spin_lock(&spl->spin);
	list_for_each_entry_safe(p, tmp, head, list)
		if (p->any == any && p->pid == pid) {
			list_del(&p->list);
			found = p;
			break;
		}
	spin_unlock(&spl->spin);
	kfree(found);
	WARN_ON(!found);
}

/* ---------------------------------------------------------------------- */

void au_dbg_locking_si_reg(struct super_block *sb, int flags)
{
	au_dbg_reg(au_sbi(sb)->si_dbg_lock + AuDbgLock_SI_LOCKING, sb, flags,
		   -1);
}

void au_dbg_locking_si_unreg(struct super_block *sb, int flags)
{
	au_dbg_unreg(au_sbi(sb)->si_dbg_lock + AuDbgLock_SI_LOCKING, sb, flags);
}

void au_dbg_locked_si_reg(struct super_block *sb, int flags)
{
	au_dbg_reg(au_sbi(sb)->si_dbg_lock + AuDbgLock_SI_LOCKED, sb, flags,
		   -1);
}

void au_dbg_locked_si_unreg(struct super_block *sb, int flags)
{
	au_dbg_unreg(au_sbi(sb)->si_dbg_lock + AuDbgLock_SI_LOCKED, sb, flags);
}

void au_dbg_locking_di_reg(struct dentry *d, int flags, unsigned int lsc)
{
	au_dbg_reg(au_sbi(d->d_sb)->si_dbg_lock + AuDbgLock_DI_LOCKING, d,
		   flags, lsc);
}

void au_dbg_locking_di_unreg(struct dentry *d, int flags)
{
	au_dbg_unreg(au_sbi(d->d_sb)->si_dbg_lock + AuDbgLock_DI_LOCKING, d,
		     flags);
}

void au_dbg_locked_di_reg(struct dentry *d, int flags, unsigned int lsc)
{
	au_dbg_reg(au_sbi(d->d_sb)->si_dbg_lock + AuDbgLock_DI_LOCKED, d, flags,
		   lsc);
}

void au_dbg_locked_di_unreg(struct dentry *d, int flags)
{
	au_dbg_unreg(au_sbi(d->d_sb)->si_dbg_lock + AuDbgLock_DI_LOCKED, d,
		     flags);
}

void au_dbg_locking_ii_reg(struct inode *i, int flags, unsigned int lsc)
{
	au_dbg_reg(au_sbi(i->i_sb)->si_dbg_lock + AuDbgLock_II_LOCKING, i,
		   flags, lsc);
}

void au_dbg_locking_ii_unreg(struct inode *i, int flags)
{
	au_dbg_unreg(au_sbi(i->i_sb)->si_dbg_lock + AuDbgLock_II_LOCKING, i,
		     flags);
}

void au_dbg_locked_ii_reg(struct inode *i, int flags, unsigned int lsc)
{
	au_dbg_reg(au_sbi(i->i_sb)->si_dbg_lock + AuDbgLock_II_LOCKED, i, flags,
		   lsc);
}

void au_dbg_locked_ii_unreg(struct inode *i, int flags)
{
	au_dbg_unreg(au_sbi(i->i_sb)->si_dbg_lock + AuDbgLock_II_LOCKED, i,
		     flags);
}
#endif /* CONFIG_AUFS_DEBUG_LOCK */

/* ---------------------------------------------------------------------- */

static void sysrq_sb(struct super_block *sb)
{
	char *plevel;
	struct inode *i;
	struct au_sbinfo *sbinfo;
	struct file *file;

	plevel = au_plevel;
	au_plevel = KERN_WARNING;
	au_debug_on();

	sbinfo = au_sbi(sb);
	pr_warning("si=%lx\n", au_si_mask ^ (unsigned long)sbinfo);
	pr_warning(AUFS_NAME ": superblock\n");
	au_dpri_sb(sb);
	pr_warning(AUFS_NAME ": root dentry\n");
	au_dpri_dentry(sb->s_root);
	pr_warning(AUFS_NAME ": root inode\n");
	au_dpri_inode(sb->s_root->d_inode);
	pr_warning(AUFS_NAME ": isolated inode\n");
	list_for_each_entry(i, &sb->s_inodes, i_sb_list)
		if (list_empty(&i->i_dentry))
			au_dpri_inode(i);
	pr_warning(AUFS_NAME ": files\n");
	list_for_each_entry(file, &sb->s_files, f_u.fu_list)
		if (au_test_aufs_file(file))
			au_dpri_file(file);

#ifdef CONFIG_AUFS_DEBUG_LOCK
	{
		struct au_dbg_lock *p;
		struct list_head *head;

		pr_warning(AUFS_NAME ": locking si\n");
		head = &sbinfo->si_dbg_lock[AuDbgLock_SI_LOCKING].head;
		list_for_each_entry(p, head, list)
			pr_warning("pid: %d, 0x%x\n", p->pid, p->flags);
		pr_warning(AUFS_NAME ": locked si\n");
		head = &sbinfo->si_dbg_lock[AuDbgLock_SI_LOCKED].head;
		list_for_each_entry(p, head, list)
			pr_warning("pid: %d, 0x%x\n", p->pid, p->flags);
		pr_warning(AUFS_NAME ": locking di\n");
		head = &sbinfo->si_dbg_lock[AuDbgLock_DI_LOCKING].head;
		list_for_each_entry(p, head, list) {
			pr_warning("pid: %d, 0x%x, %d\n",
				   p->pid, p->flags, p->lsc);
			au_dpri_dentry(p->dentry);
		}
		pr_warning(AUFS_NAME ": locked di\n");
		head = &sbinfo->si_dbg_lock[AuDbgLock_DI_LOCKED].head;
		list_for_each_entry(p, head, list) {
			pr_warning("pid: %d, 0x%x, %d\n",
				   p->pid, p->flags, p->lsc);
			au_dpri_dentry(p->dentry);
		}
		pr_warning(AUFS_NAME ": locking ii\n");
		head = &sbinfo->si_dbg_lock[AuDbgLock_II_LOCKING].head;
		list_for_each_entry(p, head, list) {
			pr_warning("pid: %d, %d\n", p->pid, p->lsc);
			au_dpri_inode(p->inode);
		}
		pr_warning(AUFS_NAME ": locked ii\n");
		head = &sbinfo->si_dbg_lock[AuDbgLock_II_LOCKED].head;
		list_for_each_entry(p, head, list) {
			pr_warning("pid: %d, %d\n", p->pid, p->lsc);
			au_dpri_inode(p->inode);
		}
	}
#endif

	au_plevel = plevel;
	au_debug_off();
}

/* ---------------------------------------------------------------------- */

/* module parameter */
static char *aufs_sysrq_key = "a";
module_param_named(sysrq, aufs_sysrq_key, charp, S_IRUGO);
MODULE_PARM_DESC(sysrq, "MagicSysRq key for " AUFS_NAME);

static void au_sysrq(int key, struct tty_struct *tty)
{
	struct kobject *kobj;
	struct au_sbinfo *sbinfo;

	/* spin_lock(&au_kset->list_lock); */
	list_for_each_entry(kobj, &au_kset->list, entry) {
		sbinfo = container_of(kobj, struct au_sbinfo, si_kobj);
		sysrq_sb(sbinfo->si_sb);
	}
	/* spin_unlock(&au_kset->list_lock); */
}

static struct sysrq_key_op au_sysrq_op = {
	.handler	= au_sysrq,
	.help_msg	= "Aufs",
	.action_msg	= "Aufs",
	/* todo: test mask? */
	.enable_mask	= SYSRQ_ENABLE_DUMP
};

/* ---------------------------------------------------------------------- */

int __init au_sysrq_init(void)
{
	int err;
	char key;

	err = -1;
	key = *aufs_sysrq_key;
	if ('a' <= key && key <= 'z')
		err = register_sysrq_key(key, &au_sysrq_op);
	if (unlikely(err))
		AuErr("err %d, sysrq=%c\n", err, key);
	return err;
}

void au_sysrq_fin(void)
{
	int err;
	err = unregister_sysrq_key(*aufs_sysrq_key, &au_sysrq_op);
	if (unlikely(err))
		AuErr("err %d (ignored)\n", err);
}
