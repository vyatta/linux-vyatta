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
 * main header files
 *
 * $Id: aufs.h,v 1.6 2009/01/26 06:24:45 sfjro Exp $
 */

#ifndef __AUFS_H__
#define __AUFS_H__

#ifdef __KERNEL__

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#error you got wrong version
#endif

/* introduced in linux-2.6.27 */
#include <linux/bug.h>
#ifndef WARN_ONCE
#define WARN_ONCE(cond, fmt ...) WARN_ON(cond)
#endif

/* ---------------------------------------------------------------------- */

#include "debug.h"

#include "branch.h"
#include "cpup.h"
#include "dcsub.h"
#include "dentry.h"
#include "dir.h"
#include "file.h"
#include "hinode.h"
#include "inode.h"
#include "misc.h"
#include "module.h"
#include "opts.h"
#include "super.h"
#include "sysaufs.h"
#include "vfsub.h"
#include "whout.h"
#include "wkq.h"
/* reserved for future use */
/* #include "xattr.h" */

#ifdef AuNoInlineForStack
#undef noinline_for_stack
#define noinline_for_stack /* */
#endif

#endif /* __KERNEL__ */
#endif /* __AUFS_H__ */
