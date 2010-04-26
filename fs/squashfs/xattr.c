/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2010
 * Helge Bahmann <helge.bahmann@secunet.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * xattr.c
 */

/*
 * This file implements code to handle extended attributes.
 *
 * Extended attributes are stored in a fashion similar to directories: packed
 * into compressed metadata blocks, stored in the xattr table. Extended
 * attributes are located in this table using the start address of the
 * metablock containing the first byte of the attribute, as well as
 * the offset of the first byte. The tuple (<block, offset>) is encoded
 * into a single 32-bit quantity, using the upper 19 bits for the block
 * and the lower 13 bits for the offset.
 *
 * Each set of extended attributes associated with a file is stored as a
 * 32-bit length marker, followed by all name/value pairs forming the
 * attribute set. The attribute names must follow the common linux convention
 * using "user.", "security." etc. as prefix respectively.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <linux/xattr.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs_fs_i.h"
#include "squashfs.h"

struct squashfs_xattr_iterator {
	unsigned int name_len, value_len;
	char *name;
	void *value;

	struct super_block *sb;
	u64 block;
	int offset;

	unsigned int remaining_bytes;
};

static void
_squashfs_xattr_iterator_release_buffer(struct squashfs_xattr_iterator *iter)
{
	kfree(iter->name);
	kfree(iter->value);
	iter->name = 0;
	iter->value = 0;
}

static int
_squashfs_xattr_iterator_read_next(struct squashfs_xattr_iterator *iter)
{
	int err;
	int total_len;
	struct squashfs_xattr_entry_header header;

	if (iter->remaining_bytes == 0)
		return 0;

	if (iter->remaining_bytes < sizeof(struct squashfs_xattr_entry_header))
		return -EIO;

	err = squashfs_read_metadata(iter->sb, &header, &iter->block,
		&iter->offset, sizeof(header));
	if (err < 0)
		return err;
	if (err < sizeof(header))
		return 0;
	iter->remaining_bytes -= sizeof(header);

	iter->name_len = le32_to_cpu(header.name_len);
	iter->value_len = le32_to_cpu(header.value_len);
	if (iter->name_len > 4096 || iter->value_len > 65536)
		return -EIO;
	total_len = iter->name_len + iter->value_len;
	if (total_len > iter->remaining_bytes)
		return -EIO;

	iter->name = kmalloc(iter->name_len+1, GFP_KERNEL);
	if (!iter->name)
		return -ENOMEM;
	iter->value = kmalloc(iter->value_len, GFP_KERNEL);
	if (!iter->value)
		return -ENOMEM;

	err = squashfs_read_metadata(iter->sb, iter->name, &iter->block,
		&iter->offset, iter->name_len);
	if (err < 0)
		return err;
	if (err < iter->name_len)
		return -EIO;
	iter->name[iter->name_len] = 0;

	err = squashfs_read_metadata(iter->sb, iter->value, &iter->block,
		&iter->offset, iter->value_len);
	if (err < 0)
		return err;
	if (err < iter->value_len)
		return -EIO;

	iter->remaining_bytes -= total_len;

	return 1;
}

static int
squashfs_xattr_iterator_start(struct squashfs_xattr_iterator *iter,
			      struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	int xattr = squashfs_i(inode)->xattr;
	struct squashfs_xattr_header xattr_header;
	int err;

	iter->sb = sb;
	iter->name = 0;
	iter->value = 0;

	if (xattr == -1 || msblk->xattr_table == -1)
		return 0;

	iter->block = msblk->xattr_table + (xattr >> 13);
	iter->offset = xattr & 8191;

	err = squashfs_read_metadata(iter->sb, &xattr_header, &iter->block,
		&iter->offset, sizeof(xattr_header));
	if (err < 0)
		return err;
	if (err < 4)
		return -EIO;

	iter->remaining_bytes = le32_to_cpu(xattr_header.size) - 4;

	return _squashfs_xattr_iterator_read_next(iter);
}

static int
squashfs_xattr_iterator_next(struct squashfs_xattr_iterator *iter)
{
	_squashfs_xattr_iterator_release_buffer(iter);
	return _squashfs_xattr_iterator_read_next(iter);
}

static void
squashfs_xattr_iterator_end(struct squashfs_xattr_iterator *iter)
{
	_squashfs_xattr_iterator_release_buffer(iter);
}

static inline int filtered(const char *name)
{
	if (capable(CAP_SYS_ADMIN))
		return 0;
	return strncmp(XATTR_TRUSTED_PREFIX, name,
		       XATTR_TRUSTED_PREFIX_LEN) == 0;
}

ssize_t
squashfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct squashfs_xattr_iterator iter;
	int next_xattr;
	ssize_t xattr_names_size = 0;

	next_xattr = squashfs_xattr_iterator_start(&iter, dentry->d_inode);

	while (next_xattr == 1) {
		if (!filtered(iter.name)) {
			xattr_names_size += iter.name_len;
			if (size) {
				size_t to_copy = size > (iter.name_len + 1) ?
					(iter.name_len + 1) : size;
				memcpy(buffer, iter.name, to_copy);
				buffer += to_copy;
				size -= to_copy;
			}
		}
		next_xattr = squashfs_xattr_iterator_next(&iter);
	}

	squashfs_xattr_iterator_end(&iter);

	if (next_xattr < 0)
		return next_xattr;
	else
		return xattr_names_size;
}

ssize_t
squashfs_getxattr(struct dentry *dentry, const char *name,
		  void *buffer, size_t size)
{
	struct squashfs_xattr_iterator iter;
	int next_xattr;

	next_xattr = squashfs_xattr_iterator_start(&iter, dentry->d_inode);

	while (next_xattr == 1) {
		if (strcmp(name, iter.name) == 0) {
			if (buffer) {
				if (size >= iter.value_len) {
					memcpy(buffer, iter.value,
					       iter.value_len);
					next_xattr = iter.value_len;
				} else
					next_xattr = -ERANGE;
			} else
				next_xattr = iter.value_len;
			break;
		}
		next_xattr = squashfs_xattr_iterator_next(&iter);
	}

	squashfs_xattr_iterator_end(&iter);

	if (next_xattr == 0)
		next_xattr = -ENODATA;

	return next_xattr;
}
