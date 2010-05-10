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
xattr_iterator_release_buffer(struct squashfs_xattr_iterator *iter)
{
	kfree(iter->name);
	iter->name = NULL;
	kfree(iter->value);
	iter->value = NULL;
}

static int
xattr_iterator_read_next(struct squashfs_xattr_iterator *iter)
{
	int err;
	unsigned int total_len;
	struct squashfs_xattr_entry entry;

	if (iter->remaining_bytes == 0)
		return 0;

	if (iter->remaining_bytes < sizeof(struct squashfs_xattr_entry))
		return -EIO;

	err = squashfs_read_metadata(iter->sb, &entry, &iter->block,
				     &iter->offset, sizeof(entry));
	if (err < 0) {
		ERROR("Xattr read entry failed\n");
		return err;
	}

	if (err < sizeof(entry)) {
		ERROR("Xattr entry too short\n");
		return 0;
	}

	iter->remaining_bytes -= sizeof(entry);
	iter->name_len = le32_to_cpu(entry.name_len);
	iter->value_len = le32_to_cpu(entry.value_len);
	if (iter->name_len > 4096 || iter->value_len > 65536) {
		ERROR("Xattr entry length %d:%d  \n",
		      iter->name_len, iter->value_len);
		return -EIO;
	}

	total_len = iter->name_len + iter->value_len;
	if (total_len > iter->remaining_bytes) {
		ERROR("Xattr length %d > remaining %u\n",
		      total_len, iter->remaining_bytes);
		return -EIO;
	}

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
	u32 xattr = squashfs_i(inode)->xattr;
	struct squashfs_xattr_header xattr_header;
	int err;

	if (msblk->xattr_table == SQUASHFS_INVALID_BLK)
		return 0;	/* no attributes in filesystem image */
 
	if (xattr == SQUASHFS_INVALID_FRAG)
		return 0;	/* no attributes on file */

	memset(iter, 0, sizeof(struct squashfs_xattr_iterator));
	iter->sb = sb;
	iter->block = msblk->xattr_table + (xattr >> SQUASHFS_METADATA_LOG);
	iter->offset = xattr & (SQUASHFS_METADATA_SIZE -1);

	err = squashfs_read_metadata(iter->sb, &xattr_header, &iter->block,
		&iter->offset, sizeof(xattr_header));
	if (err < 0) {
		ERROR("Failed to read xattr header @ %#llx:%#x\n",
		      msblk->xattr_table, xattr);
 		return err;
	}
	if (err < sizeof(xattr_header)) {
		ERROR("Xattr header to short\n");
		return -EIO;
	}

	iter->remaining_bytes = le32_to_cpu(xattr_header.size)
		- sizeof(xattr_header);

	TRACE("Xattr header bytes %u\n", iter->remaining_bytes);
	return 1;
}

static int
squashfs_xattr_iterator_next(struct squashfs_xattr_iterator *iter)
{
	xattr_iterator_release_buffer(iter);
	return xattr_iterator_read_next(iter);
}

static void
squashfs_xattr_iterator_end(struct squashfs_xattr_iterator *iter)
{
	xattr_iterator_release_buffer(iter);
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
	int err;
	ssize_t xattr_names_size = 0;

	err = squashfs_xattr_iterator_start(&iter, dentry->d_inode);
	if (err <= 0)
		return err;

	while ((err = squashfs_xattr_iterator_next(&iter)) == 1) {
		size_t name_size = iter.name_len + 1;
		if (filtered(iter.name))
			continue;

		TRACE("Listxattr %.*s", (int)iter.name_len, iter.name);

		xattr_names_size += name_size;
		if (!buffer)
			continue;

		if (size < name_size) {
			err = -ERANGE;
			break;
 		}
		memcpy(buffer, iter.name, iter.name_len);
		buffer[iter.name_len] = '\0';
		buffer += name_size;
		size -= name_size;
	}

	squashfs_xattr_iterator_end(&iter);

	return (err < 0) ? err : xattr_names_size;
}

ssize_t
squashfs_getxattr(struct dentry *dentry, const char *name,
		  void *buffer, size_t size)
{
	struct squashfs_xattr_iterator iter;
	int err;

	err = squashfs_xattr_iterator_start(&iter, dentry->d_inode);
	if (err < 0)
		return err;
	if (err == 0)
		return -ENODATA;

	while ((err = squashfs_xattr_iterator_next(&iter)) == 1) {
		if (strcmp(name, iter.name))
			continue;

		TRACE("Getxattr %s length %u\n", name, iter.value_len);
		err = iter.value_len;
		if (buffer) {
			if (size < iter.value_len)
				err = -ERANGE;
			else
				memcpy(buffer, iter.value, iter.value_len);
 		}
		goto found;
	}
	err = -ENODATA;
 found:
	squashfs_xattr_iterator_end(&iter);

	return err;
}
