/*
 *   prlfs/file.c
 *
 *   Copyright (C) 1999-2016 Parallels International GmbH
 *   Author: Vasily Averin <vvs@parallels.com>
 *
 *   Parallels Linux shared folders filesystem
 *
 *   File related functions and definitions
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/backing-dev.h>
#include "prlfs.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
inline struct radix_tree_root *prlfs_page_cache_get_locked(
		struct address_space *mapping)
{
	xa_lock(&mapping->i_pages);
	return &mapping->i_pages;
}
inline void prlfs_page_cache_unlock(struct address_space *mapping)
{
	xa_unlock(&mapping->i_pages);
}
#else
inline struct radix_tree_root *prlfs_page_cache_get_locked(
		struct address_space *mapping)
{
	spin_lock(&mapping->tree_lock);
	return &mapping->page_tree;
}
inline void prlfs_page_cache_unlock(struct address_space *mapping)
{
	spin_unlock(&mapping->tree_lock);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
#define prlfs_page_cache_invalid_entry(x) xa_is_value(x)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0) || \
                            defined(PRLFS_RHEL_6_2_GE)
#define prlfs_page_cache_invalid_entry(x) radix_tree_exceptional_entry(x)
#else
#define prlfs_page_cache_invalid_entry(x) 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
static int prlfs_mapping_update(struct file *filp)
{
	struct address_space *mapping = filp->f_mapping;
	struct radix_tree_iter iter;
	void **slot;
	struct radix_tree_root *pages;

	pages = prlfs_page_cache_get_locked(mapping);
	radix_tree_for_each_slot(slot, pages, &iter, 0) {
		struct page *cur_page = radix_tree_deref_slot(slot);
		if (!cur_page) {
			DPRINTK("NULL page in mapping tree\n");
			continue;
		}
		if (prlfs_page_cache_invalid_entry(cur_page))
			continue;
		ClearPageUptodate(cur_page);
	}
	prlfs_page_cache_unlock(mapping);
	return 0;
}

#else
static int prlfs_mapping_update(struct file *filp)
{
	struct inode *inode = FILE_DENTRY(filp)->d_inode;
	struct address_space *mapping = filp->f_mapping;
	struct radix_tree_root *pages;
	unsigned int i, found_pages = 0;
	unsigned int max_pages = (inode->i_size / PAGE_SIZE) + 1;
	void ***slots = kzalloc(max_pages * sizeof(void**), GFP_KERNEL);
	if (!slots)
		return -ENOMEM;

	pages = prlfs_page_cache_get_locked(mapping);
	found_pages = radix_tree_gang_lookup_slot(pages,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0) || defined(PRLFS_RHEL_6_2_GE)
				slots, NULL, 0, max_pages);
#else
				slots, 0, max_pages);
#endif

	for (i = 0; i < found_pages; i++) {
		struct page *cur_page = radix_tree_deref_slot(slots[i]);
		if (!cur_page) {
			DPRINTK("NULL page in mapping tree\n");
			continue;
		}
		if (prlfs_page_cache_invalid_entry(cur_page))
			continue;
		ClearPageUptodate(cur_page);
	}
	prlfs_page_cache_unlock(mapping);
	kfree(slots);
	return 0;
}
#endif

static int prlfs_check_open_flags(const struct file *filp, const struct prlfs_fd *pfd)
{
	if (pfd->f_flags == O_RDWR)
		return 0;
	if ((O_ACCMODE & filp->f_flags) == pfd->f_flags)
		return 0;
	return 1;
}

static int prlfs_open(struct inode *inode, struct file *filp)
{
	char *buf, *p;
	int buflen, ret = 0;
	unsigned int open_flags;
	struct super_block *sb = inode->i_sb;
	struct dentry *dentry = FILE_DENTRY(filp);
	struct prlfs_file_info pfi;
	struct prlfs_fd *pfd = inode_get_pfd(inode);

	DPRINTK("ENTER\n");
	if (IS_ERR(pfd)) {
		ret = PTR_ERR(pfd);
		goto out_nolock;
	}

	prlfs_inode_lock(inode);

	//If we already opened this file, we shouldn't send TG request
	//to host
	if (pfd->f_counter) {
		if (prlfs_check_open_flags(filp, pfd)) {
			DPRINTK("Access denied. File mode: %o\n", pfd->f_flags);
			ret = -EACCES;
		} else
			pfd->f_counter++;
		goto out;
	}

	//Get file path
	buflen = PATH_MAX;
	buf = kmalloc(buflen, GFP_KERNEL);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	memset(buf, 0, buflen);
	p = prlfs_get_path(dentry, buf, &buflen);
	if (IS_ERR(p)) {
		ret = PTR_ERR(p);
		goto out_free_buf;
	}

	// Here we set full access to file for first open try.
	open_flags = (filp->f_flags | O_RDWR) & ~O_WRONLY;
	// We send file read/write offset to host, so we don't
	// need to send O_APPEND flag.
	open_flags &= ~O_APPEND;
retry:
	init_pfi(&pfi, NULL, 0, open_flags);

	DPRINTK("file %s\n", p);
	DPRINTK("flags %x\n", pfi.flags);

	ret = host_request_open(sb, &pfi, p, buflen);
	if (ret < 0) {
		if (ret == -EPERM) {
			// IF we can't open host file with O_RDWR, try to
			// open it with O_RDONLY
			if(open_flags & O_RDWR) {
				open_flags &= ~O_RDWR;
				goto retry;
			// If we can't open host file with O_RDONLY and
			// O_RDWR, try to do it with O_WRONLY
			} else if (!(open_flags & (O_RDWR|O_WRONLY))) {
				open_flags |= O_WRONLY;
				goto retry;
			}
		}
		DPRINTK("host_request_open return error %d\n", ret);
		goto out_free_buf;
	}
	pfd->fd = pfi.fd;
	pfd->sfid = pfi.sfid;
	pfd->f_counter = 1;
	pfd->f_flags = open_flags & O_ACCMODE;
	dentry->d_time = 0;
	ret = prlfs_mapping_update(filp);
	if (ret < 0)
		DPRINTK("prlfs_mapping_update return error %d\n", ret);
out_free_buf:
	kfree(buf);
out:
	prlfs_inode_unlock(inode);
out_nolock:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int writeback_inode(struct inode *inode)
{
	return filemap_fdatawrite(inode->i_mapping);
}

static int prlfs_release(struct inode *inode, struct file *filp)
{
	struct super_block *sb = inode->i_sb;
	struct prlfs_file_info pfi;
	struct prlfs_fd *pfd = inode_get_pfd(inode);
	int ret = 0;

	DPRINTK("ENTER\n");
	writeback_inode(inode);

	prlfs_inode_lock(inode);
	BUG_ON(!pfd->f_counter);
	if (pfd->f_counter == 1) {
		init_pfi(&pfi, inode, 0, 0);
		ret = host_request_release(sb, &pfi);
		if (ret < 0)
			printk(KERN_ERR "prlfs_release returns error (%d)\n", ret);
	}

	pfd->f_counter--;
	prlfs_inode_unlock(inode);
	DPRINTK("EXIT returning %d f_counter %llu\n", ret, pfd->f_counter);
	return ret;
}

static unsigned char prlfs_filetype_table[PRLFS_FILE_TYPE_MAX] = {
	DT_UNKNOWN,
	DT_REG,
	DT_DIR,
	DT_LNK,
};

static int prlfs_fill_dir(struct file *filp,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
					struct dir_context *ctx,
#else
					void *dirent, filldir_t filldir,
#endif
					loff_t *pos, void *buf, int buflen)
{
	struct super_block *sb;
	prlfs_dirent *de;
	int offset, ret, name_len, rec_len;
	u64 ino;
	u8 type;

	DPRINTK("ENTER\n");
	assert(FILE_DENTRY(filp));
	assert(FILE_DENTRY(filp)->d_sb);
	sb = FILE_DENTRY(filp)->d_sb;
	offset = 0;
	ret = 0;

	while (1) {
		de = (prlfs_dirent *)(buf + offset);
		if (offset + sizeof(prlfs_dirent) > buflen)
			goto out;

		name_len = de->name_len;
		if (name_len == 0)
			goto out;

		rec_len = PRLFS_DIR_REC_LEN(name_len);
		if (rec_len + offset > buflen) {
			printk(PFX "invalid rec_len %d "
			       "(name_len %d offset %d buflen %d)\n",
				rec_len, name_len, offset, buflen);
			ret = -EINVAL;
			goto out;
		}
		if (de->name[name_len] != 0) {
			printk(PFX "invalid file name "
			       "(name_len %d offset %d buflen %d)\n",
				name_len, offset, buflen);
			ret = -EINVAL;
			goto out;
		}
		type = de->file_type;
		if (type >= PRLFS_FILE_TYPE_MAX) {
			printk(PFX "invalid file type: %x, "
				"use UNKNOWN type instead "
				"(name_len %d offset %d buflen %d)\n",
				type, name_len, offset, buflen);
			type = PRLFS_FILE_TYPE_UNKNOWN;
		}
		type = prlfs_filetype_table[type];
		ino = iunique(sb, PRLFS_GOOD_INO);
		DPRINTK("filldir: name %s len %d, offset %lld, "
						"de->type %d -> type %d\n",
			 de->name, name_len, (*pos), de->file_type, type);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
		if (!dir_emit(ctx, de->name, name_len, ino, type))
#else
		if (filldir(dirent, de->name, name_len, (*pos), ino, type) < 0)
#endif
			goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
		ctx->pos++;
#endif
		offset += rec_len;
		(*pos)++;
	}
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
static int prlfs_readdir(struct file *filp, struct dir_context *ctx)
#else
static int prlfs_readdir(struct file *filp, void *dirent, filldir_t filldir)
#endif
{
	struct prlfs_file_info pfi;
	struct super_block *sb;
	struct inode *inode;
	int ret, len, buflen;
	void *buf;
	off_t prev_offset;

	DPRINTK("ENTER\n");
	ret = 0;
	assert(FILE_DENTRY(filp));
	inode = FILE_DENTRY(filp)->d_inode;
	init_pfi(&pfi, inode,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
		ctx->pos,
#else
		filp->f_pos,
#endif
		0);
	assert(FILE_DENTRY(filp)->d_sb);
	sb = FILE_DENTRY(filp)->d_sb;
	buflen = PAGE_SIZE;
	buf = kmalloc(buflen, GFP_KERNEL);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	while (pfi.flags == 0) {
		len = buflen;
		memset(buf, 0, len);
		ret = host_request_readdir(sb, &pfi, buf, &len);
		if (ret < 0)
			break;

		prev_offset = pfi.offset;
		ret = prlfs_fill_dir(filp,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
					ctx,
#else
					dirent, filldir,
#endif
					&pfi.offset, buf, len);
		if (ret < 0)
			break;
		if (pfi.offset == prev_offset)
			break;
	}
	kfree(buf);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
	ctx->pos = pfi.offset;
#else
	filp->f_pos = pfi.offset;
#endif
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

ssize_t prlfs_rw(struct inode *inode, char *buf, size_t size,
			loff_t *off, unsigned int rw, int user, int flags)
{
	ssize_t ret;
	struct super_block *sb;
	struct prlfs_file_info pfi;
	struct buffer_descriptor bd;

	DPRINTK("ENTER\n");
	if (rw >= 2) {
		printk(PFX "Incorrect rw operation %d\n", rw);
		BUG();
	}
	ret = 0;
	init_pfi(&pfi, inode, *off, rw);

	if (size == 0)
		goto out;

	sb = inode->i_sb;
	init_buffer_descriptor(&bd, buf, size,(rw == 0) ? 1 : 0,
						(user == 0) ? 0 : 1);
	bd.flags = flags;
	ret = host_request_rw(sb, &pfi, &bd);
	if (ret < 0)
		goto out;

	size = bd.len;
	(*off) += size;
	ret = size;
out:
	DPRINTK("EXIT returning %lld\n", (long long)ret);
	return ret;
}

static ssize_t prlfs_read(struct file *filp, char *buf, size_t size,
								loff_t *off)
{
	struct dentry *dentry = FILE_DENTRY(filp);
	struct inode *inode = dentry->d_inode;

	return prlfs_rw(inode, buf, size, off, 0, 1, TG_REQ_COMMON);
}

static ssize_t prlfs_write(struct file *filp, const char *buf, size_t size,
								 loff_t *off)
{
	ssize_t ret;
	struct dentry *dentry = FILE_DENTRY(filp);
	struct inode *inode = dentry->d_inode;
	loff_t real_off;

	// Check O_APPEND flag before send TG request to host
	if (filp->f_flags & O_APPEND)
		real_off = inode->i_size;
	else
		real_off = *off;

	prlfs_inode_lock(inode);
	ret = prlfs_rw(inode, (char *)buf, size, &real_off, 1, 1, TG_REQ_COMMON);
	dentry->d_time = 0;
	if (ret < 0)
		goto out;

	if (inode->i_size < real_off)
		inode->i_size = real_off;
	// For linux kernel we should return relative offset in off parameter
	if (filp->f_flags & O_APPEND)
		*off += size;
	else
		*off = real_off;
out:
	prlfs_inode_unlock(inode);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#ifdef PRL_SIMPLE_SYNC_FILE
int simple_sync_file(struct file *filp, struct dentry *dentry, int datasync)
{
	return 0;
}
#endif
#endif

struct file_operations prlfs_file_fops = {
	.open		= prlfs_open,
	.read           = prlfs_read,
	.write		= prlfs_write,
	.llseek         = generic_file_llseek,
	.release	= prlfs_release,
	.mmap		= generic_file_mmap,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	.fsync		= noop_fsync,
#else
	.fsync		= simple_sync_file,
#endif
};

struct file_operations prlfs_dir_fops = {
	.open		= prlfs_open,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
	.iterate	= prlfs_readdir,
#else
	.readdir	= prlfs_readdir,
#endif
	.release	= prlfs_release,
	.read		= generic_read_dir,
	.llseek		= generic_file_llseek,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	.fsync		= noop_fsync,
#else
	.fsync		= simple_sync_file,
#endif
};
