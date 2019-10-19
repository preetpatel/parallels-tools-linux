/*
 *   prlfs/inode.c
 *
 *   Copyright (C) 1999-2016 Parallels International GmbH
 *   Author: Vasily Averin <vvs@parallels.com>
 *
 *   Parallels linux shared folders filesystem
 *
 *   Inode related functions
 */

#include <linux/module.h>
#include <linux/fs.h>
#include "prlfs.h"
#include <linux/ctype.h>
#include <linux/pagemap.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#include <linux/cred.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/namei.h>
#else
#include <asm/namei.h>
#endif

extern struct file_operations prlfs_file_fops;
extern struct file_operations prlfs_dir_fops;
extern struct inode *prlfs_iget(struct super_block *sb, ino_t ino);

struct inode *prlfs_get_inode(struct super_block *sb,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
			umode_t mode
#else
			int mode
#endif
);
struct dentry_operations prlfs_dentry_ops;

#define PRLFS_UID_NOBODY  65534
#define PRLFS_GID_NOGROUP 65534

static inline int prlfs_uid_valid(kuid_t uid)
{
	return !uid_eq(uid, prl_make_kuid(PRLFS_UID_NOBODY));
}

static inline int prlfs_gid_valid(kgid_t gid)
{
	return !gid_eq(gid, prl_make_kgid(PRLFS_GID_NOGROUP));
}

unsigned long *prlfs_dfl( struct dentry *de)
{
	return (unsigned long *)&(de->d_fsdata);
}

void init_buffer_descriptor(struct buffer_descriptor *bd, void *buf,
			    unsigned long long len, int write, int user)
{
	bd->buf = buf;
	bd->len = len;
	bd->write = (write == 0) ? 0 : 1;
	bd->user = (user == 0) ? 0 : segment_eq(get_fs(), USER_DS) ? 1 : 0;
	bd->flags = TG_REQ_COMMON;
}

static int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

void *prlfs_get_path(struct dentry *dentry, void *buf, int *plen)
{
	int len;
	char *p;
	int ret;

	DPRINTK("ENTER\n");
	len = *plen;
	p = buf;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
	if ((dentry->d_name.len > NAME_MAX) || (len < 2)) {
		p = ERR_PTR(-ENAMETOOLONG);
		goto out;
	}
	p += --len;
	*p = '\0';
	spin_lock(&dcache_lock);
	while (!IS_ROOT(dentry)) {
		int nlen;
		struct dentry *parent;

                parent = dentry->d_parent;
		prefetch(parent);
		/* TODO Use prepend() here as well. */
		nlen = dentry->d_name.len;
		if (len < nlen + 1) {
			p = ERR_PTR(-ENAMETOOLONG);
			goto out_lock;
		}
		len -= nlen + 1;
		p -= nlen;
		memcpy(p, dentry->d_name.name, nlen);
		*(--p) = '/';
		dentry = parent;
	}
	if (*p != '/') {
		*(--p) = '/';
		--len;
	}
out_lock:
	spin_unlock(&dcache_lock);
	if (!IS_ERR(p))
		*plen -= len;
#else
	p = dentry_path_raw(dentry, p, len);
#endif
	ret = prepend(&p, &len,
		PRLFS_SB(dentry->d_sb)->name,
		strlen(PRLFS_SB(dentry->d_sb)->name));
	if (0 == ret)
		ret = prepend(&p, &len, "/", 1);
	if (0 == ret)
		*plen = strnlen(p, PAGE_SIZE-1) + 1;
	else
		p = ERR_PTR(ret);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
out:
#endif
	DPRINTK("EXIT returning %p\n", p);
	return p;
}

#define PRLFS_STD_INODE_HEAD(d)			\
	char *buf, *p;				\
	int buflen, ret;			\
	struct super_block *sb;			\
						\
	DPRINTK("ENTER\n");			\
	buflen = PATH_MAX;			\
	buf = kmalloc(buflen, GFP_KERNEL);	\
	if (buf == NULL) {			\
		ret = -ENOMEM;			\
		goto out;			\
	}					\
	memset(buf, 0, buflen);			\
	p = prlfs_get_path((d), buf, &buflen);	\
	if (IS_ERR(p)) {			\
		ret = PTR_ERR(p);		\
		goto out_free;			\
	}					\
	sb = (d)->d_sb;

#define PRLFS_STD_INODE_TAIL			\
out_free:					\
	kfree(buf);				\
out:						\
	DPRINTK("EXIT returning %d\n", ret);	\
	return ret;

static int prlfs_inode_open(struct dentry *dentry, int mode)
{
	struct prlfs_file_info pfi;
	PRLFS_STD_INODE_HEAD(dentry)
	init_pfi(&pfi, NULL, mode, O_CREAT | O_RDWR);
	ret = host_request_open(sb, &pfi, p, buflen);
	PRLFS_STD_INODE_TAIL
}

static int prlfs_delete(struct dentry *dentry)
{
	PRLFS_STD_INODE_HEAD(dentry)
	ret = host_request_remove(dentry->d_sb, p, buflen);
	PRLFS_STD_INODE_TAIL
}

static int do_prlfs_getattr(struct dentry *dentry, struct prlfs_attr *attr)
{
	struct buffer_descriptor bd;
	PRLFS_STD_INODE_HEAD(dentry)
	init_buffer_descriptor(&bd, attr, PATTR_STRUCT_SIZE, 1, 0);
	ret = host_request_attr(sb, p, buflen, &bd);
	PRLFS_STD_INODE_TAIL
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define SET_INODE_TIME(t, time)	do { (t) = (time); } while (0)
#define GET_INODE_TIME(t)	(t)
static inline void i_size_write(struct inode *inode, loff_t size)
{
	inode->i_size = size;
}
#else
#define SET_INODE_TIME(t, time)	do { (t).tv_sec = (time); } while (0)
#define GET_INODE_TIME(t)	(t).tv_sec
#endif

static void prlfs_change_attributes(struct inode *inode,
				    struct prlfs_attr *attr)
{
	struct prlfs_sb_info *sbi = PRLFS_SB(inode->i_sb);

	if (attr->valid & _PATTR_SIZE)
		i_size_write(inode, attr->size);
	if (attr->valid & _PATTR_ATIME)
		SET_INODE_TIME(inode->i_atime, attr->atime);
	if (attr->valid & _PATTR_MTIME)
		SET_INODE_TIME(inode->i_mtime, attr->mtime);
	if (attr->valid & _PATTR_CTIME)
		SET_INODE_TIME(inode->i_ctime, attr->ctime);
	if (attr->valid & _PATTR_MODE)
		inode->i_mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	if ((attr->valid & _PATTR_UID) &&
	    (sbi->plain || sbi->share || attr->uid == -1)) {
		if (sbi->share && attr->uid == -1)
			inode->i_uid = prl_make_kuid(PRLFS_UID_NOBODY);
		else
			inode->i_uid = prl_make_kuid(attr->uid);
	}
	if ((attr->valid & _PATTR_GID) &&
	    (sbi->plain || sbi->share || attr->gid == -1)) {
		if (sbi->share && attr->gid == -1)
			inode->i_gid = prl_make_kgid(PRLFS_GID_NOGROUP);
		else
			inode->i_gid = prl_make_kgid(attr->gid);
	}
	return;
}

static int attr_to_pattr(struct iattr *attr, struct prlfs_attr *pattr)
{
	int ret;

	DPRINTK("ENTER\n");
	ret = 0;
	DPRINTK("ia_valid %x\n", attr->ia_valid);
	memset(pattr, 0, sizeof(struct prlfs_attr));
	if (attr->ia_valid & ATTR_SIZE) {
		pattr->size = attr->ia_size;
		pattr->valid |= _PATTR_SIZE;
	}
	if ((attr->ia_valid & (ATTR_ATIME | ATTR_MTIME)) ==
					(ATTR_ATIME | ATTR_MTIME)) {
		pattr->atime = GET_INODE_TIME(attr->ia_atime);
		pattr->mtime = GET_INODE_TIME(attr->ia_mtime);
		pattr->valid |= _PATTR_ATIME | _PATTR_MTIME;
	}
	if (attr->ia_valid & ATTR_CTIME) {
		pattr->ctime = GET_INODE_TIME(attr->ia_ctime);
		pattr->valid |= _PATTR_CTIME;
	}
	if (attr->ia_valid & ATTR_MODE) {
		pattr->mode = (attr->ia_mode & 07777);
		pattr->valid |= _PATTR_MODE;
	}
	if (attr->ia_valid & ATTR_UID) {
		pattr->uid = prl_from_kuid(attr->ia_uid);
		pattr->valid = _PATTR_UID;
	}
	if (attr->ia_valid & ATTR_GID) {
		pattr->gid = prl_from_kgid(attr->ia_gid);
		pattr->valid = _PATTR_GID;
	}
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_mknod(struct inode *dir, struct dentry *dentry, int mode)
{
	struct inode * inode;
	int ret;

	DPRINTK("ENTER\n");
	ret = 0;
	dentry->d_time = 0;
	inode = prlfs_get_inode(dir->i_sb, mode);
	if (inode)
		d_instantiate(dentry, inode);
         else
		ret = -ENOSPC;
	DPRINTK("EXIT returning %d\n", ret);
        return ret;
}

static int prlfs_create(struct inode *dir, struct dentry *dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
			umode_t mode
#else
			int mode
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
			, bool excl
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
			, struct nameidata *nd
#endif
	)
{
	int ret;

	DPRINTK("ENTER\n");
	ret = prlfs_inode_open(dentry, mode | S_IFREG);
	if (ret == 0)
		ret = prlfs_mknod(dir, dentry, mode | S_IFREG);
	DPRINTK("EXIT returning %d\n", ret);
        return ret;
}

static struct dentry *prlfs_lookup(struct inode *dir, struct dentry *dentry
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
			, unsigned int flags
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
			, struct nameidata *nd
#endif
	)
{
	int ret;
	struct prlfs_attr *attr = 0;
	struct inode *inode;

	DPRINTK("ENTER\n");
	DPRINTK("dir ino %lld entry name \"%s\"\n",
		 (u64)dir->i_ino, dentry->d_name.name);
	attr = kmalloc(sizeof(struct prlfs_attr), GFP_KERNEL);
	if (!attr) {
		ret = -ENOMEM;
		goto out;
	}
	ret = do_prlfs_getattr(dentry, attr);
	if (ret < 0 ) {
		if (ret == -ENOENT) {
			inode = NULL;
			ret = 0;
		} else
			goto out_free;
	} else {
		inode = prlfs_get_inode(dentry->d_sb, attr->mode);
		if (inode)
			prlfs_change_attributes(inode, attr);
	}
	dentry->d_time = jiffies;
	d_add(dentry, inode);
	d_set_d_op(dentry, &prlfs_dentry_ops);
out_free:
	kfree(attr);
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ERR_PTR(ret);
}

static int prlfs_unlink(struct inode *dir, struct dentry *dentry)
{
        int ret;
	unsigned long *dfl = prlfs_dfl(dentry);

	DPRINTK("ENTER\n");
	ret = prlfs_delete(dentry);
	if (!ret)
		 *dfl |= PRL_DFL_UNLINKED;
	DPRINTK("EXIT returning %d\n", ret);
        return ret;
}

static int prlfs_mkdir(struct inode *dir, struct dentry *dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
			umode_t mode
#else
			int mode
#endif
			)
{
        int ret;

	DPRINTK("ENTER\n");
	ret = prlfs_inode_open(dentry, mode | S_IFDIR);
	if (ret == 0)
		ret = prlfs_mknod(dir, dentry, mode | S_IFDIR);
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_rmdir(struct inode *dir, struct dentry *dentry)
{
        int ret;
	unsigned long *dfl = prlfs_dfl(dentry);

	DPRINTK("ENTER\n");
	ret = prlfs_delete(dentry);
	if (!ret)
		*dfl |= PRL_DFL_UNLINKED;
	DPRINTK("EXIT returning %d\n", ret);
        return ret;
}

static int prlfs_rename(struct inode *old_dir, struct dentry *old_de,
			struct inode *new_dir, struct dentry *new_de)
{
	void *np, *nbuf;
	int nbuflen;
	PRLFS_STD_INODE_HEAD(old_de)
	nbuflen = PATH_MAX;
	nbuf = kmalloc(nbuflen, GFP_KERNEL);
	if (nbuf == NULL) {
		ret = -ENOMEM;
		goto out_free;
	}
	memset(nbuf, 0, nbuflen);
	np = prlfs_get_path(new_de, nbuf, &nbuflen);
	if (IS_ERR(np)) {
		ret = PTR_ERR(np);
		goto out_free_nbuf;
	}
	ret = host_request_rename(sb, p, buflen, np, nbuflen);
	old_de->d_time = 0;
	new_de->d_time = 0;
out_free_nbuf:
	kfree(nbuf);
	PRLFS_STD_INODE_TAIL
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
static int prlfs_rename2(struct inode *old_dir, struct dentry *old_de,
			struct inode *new_dir, struct dentry *new_de, unsigned int flags)
{
	if (flags)
		return -EINVAL;
	return prlfs_rename(old_dir, old_de, new_dir, new_de);
}
#endif

/*
 * FIXME: Move fs specific data to inode.
 * Current implementation used full path to as a reference to opened file.
 * So {set,get}attr result access to another not unlinked file with the same
 * path.
 */
static int check_dentry(struct dentry *dentry)
{
	return *prlfs_dfl(dentry) & PRL_DFL_UNLINKED;
}

static int prlfs_inode_setattr(struct inode *inode, struct iattr *attr)
{
	int ret = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	ret = inode_setattr(inode, attr);
#else
	if ((attr->ia_valid & ATTR_SIZE &&
			attr->ia_size != i_size_read(inode))) {
		ret = inode_newsize_ok(inode, attr->ia_size);
		if (ret)
			goto out;
		truncate_setsize(inode, attr->ia_size);
	}
	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
out:
#endif
	return ret;
}

static int prlfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct prlfs_attr *pattr;
	struct buffer_descriptor bd;
	PRLFS_STD_INODE_HEAD(dentry)
	pattr = kmalloc(sizeof(struct prlfs_attr), GFP_KERNEL);
	if (!pattr) {
		ret = -ENOMEM;
		goto out_free;
	}
	ret = attr_to_pattr(attr, pattr);
	if (ret < 0)
		goto out_free_pattr;

	if (check_dentry(dentry)) {
		ret = - ESTALE;
		goto out_free_pattr;
	}
	init_buffer_descriptor(&bd, pattr, PATTR_STRUCT_SIZE, 0, 0);
	ret = host_request_attr(sb, p, buflen, &bd);
	if (ret == 0)
		ret = prlfs_inode_setattr(dentry->d_inode, attr);
	dentry->d_time = 0;
out_free_pattr:
	kfree(pattr);
	PRLFS_STD_INODE_TAIL
}

static int prlfs_i_revalidate(struct dentry *dentry)
{
	struct prlfs_attr *attr = 0;
	struct inode *inode;
	int ret;

	DPRINTK("ENTER\n");
	if (!dentry || !dentry->d_inode) {
		ret = -ENOENT;
		goto out;
	}
	if (dentry->d_time != 0 &&
	    jiffies - dentry->d_time < PRLFS_SB(dentry->d_sb)->ttl) {
		ret = 0;
		goto out;
	}
	attr = kmalloc(sizeof(struct prlfs_attr), GFP_KERNEL);
	if (!attr) {
		ret = -ENOMEM;
		goto out;
	}
	inode = dentry->d_inode;
	ret = do_prlfs_getattr(dentry, attr);
	if (ret < 0)
		goto out_free;

	if ((inode->i_mode ^ attr->mode) & S_IFMT) {
		DPRINTK("inode <%p> i_mode %x attr->mode %x\n", inode, inode->i_mode,
				attr->mode);
		make_bad_inode(inode);
		ret = -EIO;
	} else {
		prlfs_change_attributes(inode, attr);
	}
	dentry->d_time = jiffies;
out_free:
	kfree(attr);
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_d_revalidate(struct dentry *dentry,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
					int flags
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
					struct nameidata *nd
#else
					unsigned int flags
#endif
	)
{
	int ret;

	DPRINTK("ENTER\n");
	ret = (prlfs_i_revalidate(dentry) == 0) ? 1 : 0;
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

struct dentry_operations prlfs_dentry_ops = {
	.d_revalidate = prlfs_d_revalidate,
};


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)

inline int __prlfs_getattr(struct dentry *dentry, struct kstat *stat)
{
	int ret;
	DPRINTK("ENTER\n");
	if (check_dentry(dentry)) {
		ret = - ESTALE;
		goto out;
	}

	ret = prlfs_i_revalidate(dentry);
	if (ret < 0)
		goto out;

	generic_fillattr(dentry->d_inode, stat);
	if (PRLFS_SB(dentry->d_sb)->share) {
		if (prlfs_uid_valid(stat->uid))
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
			stat->uid = current->fsuid;
#else
			stat->uid = current->cred->fsuid;
#endif
		if (prlfs_gid_valid(stat->gid))
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
			stat->gid = current->fsgid;
#else
			stat->gid = current->cred->fsgid;
#endif
	}
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static int prlfs_getattr(const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int query_flags)
{
	return __prlfs_getattr(path->dentry, stat);
}
#else
static int prlfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		 struct kstat *stat)
{
	return __prlfs_getattr(dentry, stat);
}
#endif

#endif // KERNEL_VERSION(2, 6, 0)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,40)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0))
/* Fedora 15 uses 2.6.4x kernel version enumeration instead of 3.x */
#define MINOR_3X_LINUX_VERSION	LINUX_VERSION_CODE - KERNEL_VERSION(2,6,40)
#define REAL_LINUX_VERSION_CODE	KERNEL_VERSION(3,MINOR_3X_LINUX_VERSION,0)
#else
#define REAL_LINUX_VERSION_CODE	LINUX_VERSION_CODE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
/* 2.4.x */
static int prlfs_permission(struct inode *inode, int mask)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
/* 2.6.0 ... 2.6.26 */
static int prlfs_permission(struct inode *inode, int mask, struct nameidata *nd)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
/* 2.6.27 ... 2.6.37 */
static int prlfs_permission(struct inode *inode, int mask)
#elif REAL_LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
/* 2.6.38 ... 3.0 */
static int prlfs_permission(struct inode *inode, int mask, unsigned int flags)
#define PERMISSION_PRECHECK	(flags & IPERM_FLAG_RCU)
#else
/* 3.1 ... ? */
static int prlfs_permission(struct inode *inode, int mask)
#define PERMISSION_PRECHECK	(mask & MAY_NOT_BLOCK)
#endif
{
	int isdir, mode;

	DPRINTK("ENTER\n");
#ifdef PERMISSION_PRECHECK
	if (PERMISSION_PRECHECK)
		return -ECHILD;
#endif
	mode = inode->i_mode;
	isdir = S_ISDIR(mode);

	if (prlfs_uid_valid(inode->i_uid))
		mode = mode >> 6;
	else if (prlfs_gid_valid(inode->i_gid))
		mode = mode >> 3;
	mode &= 0007;
	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;

	DPRINTK("mask 0x%x mode %o\n", mask, mode);

	if ((mask & ~mode) == 0)
		return 0;

	if (!(mask & MAY_EXEC) || (isdir || (mode & S_IXUGO)))
		if (capable(CAP_DAC_OVERRIDE))
			return 0;

	 if (mask == MAY_READ || (isdir && !(mask & MAY_WRITE)))
		if (capable(CAP_DAC_READ_SEARCH))
			return 0;

	DPRINTK("EXIT returning EACCES\n");
	return -EACCES;
}

static char *do_read_symlink(struct dentry *dentry)
{
	char *buf, *src_path, *tgt_path;
	int src_len, tgt_len, ret;

	tgt_path = NULL;
	src_len = tgt_len = PATH_MAX;
	buf = kmalloc(src_len, GFP_KERNEL);
	if (buf == NULL) {
		tgt_path = ERR_PTR(-ENOMEM);
		goto out;
	}
	memset(buf, 0, src_len);
	src_path = prlfs_get_path(dentry, buf, &src_len);
	if (IS_ERR(src_path)) {
		tgt_path = src_path;
		goto out_free;
	}

	tgt_path = kmalloc(tgt_len, GFP_KERNEL);
	if (IS_ERR(tgt_path))
		goto out_free;
	DPRINTK("src '%s'\n", src_path);
	ret = host_request_readlink(dentry->d_sb, src_path, src_len, tgt_path, tgt_len);
	if (ret < 0) {
		kfree(tgt_path);
		tgt_path = ERR_PTR(ret);
	} else
		DPRINTK("tgt '%s'\n", tgt_path);
out_free:
	kfree(buf);
out:
	return tgt_path;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 13)
static void prlfs_put_link(struct dentry *d, struct nameidata *nd, void *cookie)
#else
static void prlfs_put_link(struct dentry *d, struct nameidata *nd)
#endif
{
	char *s = nd_get_link(nd);
	if (!IS_ERR(s))
		kfree(s);
}
#else // >= KERNEL_VERSION(3, 13, 0)
#define prlfs_put_link kfree_put_link
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
static const char *prlfs_get_link(struct dentry *dentry, struct inode *inode,
                                  struct delayed_call *dc)
{
	char *symlink;
	if (!dentry)
		return ERR_PTR(-ECHILD);
	symlink = do_read_symlink(dentry);
	set_delayed_call(dc, kfree_link, symlink);
	return symlink;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static const char *prlfs_follow_link(struct dentry *dentry, void **cookie)
{
	char *symlink = do_read_symlink(dentry);
	*cookie = symlink;
	return symlink;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 13)
static void *prlfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *symlink = do_read_symlink(dentry);
	nd_set_link(nd, symlink);
	return symlink;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
static int prlfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, do_read_symlink(dentry));
	return 0;
}
#else
static int prlfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	return vfs_follow_link(nd, do_read_symlink(dentry));
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static int prlfs_readlink(struct dentry *dentry, char *buf, int buflen)
{
	return vfs_readlink(dentry, buf, buflen, do_read_symlink(dentry));
}
#endif

static int prlfs_symlink(struct inode *dir, struct dentry *dentry,
                         const char *symname)
{
	PRLFS_STD_INODE_HEAD(dentry)
	DPRINTK("ENTER symname = '%s'\n", symname);
	ret = host_request_symlink(sb, p, buflen, symname, strlen(symname) + 1);
	if (ret == 0)
		ret = prlfs_mknod(dir, dentry, S_IFLNK);
	PRLFS_STD_INODE_TAIL
	return ret;
}

struct inode_operations prlfs_file_iops = {
	.setattr	= prlfs_setattr,
	.permission	= prlfs_permission,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	.revalidate	= prlfs_i_revalidate,
#else
        .getattr	= prlfs_getattr,
#endif
};

struct inode_operations prlfs_dir_iops = {
	.create		= prlfs_create,
	.lookup		= prlfs_lookup,
	.unlink		= prlfs_unlink,
	.mkdir		= prlfs_mkdir,
	.rmdir		= prlfs_rmdir,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	.rename		= prlfs_rename2,
#else
	.rename		= prlfs_rename,
#endif
	.setattr	= prlfs_setattr,
	.symlink	= prlfs_symlink,
	.permission	= prlfs_permission,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	.revalidate	= prlfs_i_revalidate,
#else
        .getattr	= prlfs_getattr,
#endif
};

struct inode_operations prlfs_symlink_iops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
	.readlink = prlfs_readlink,
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	.readlink = generic_readlink,
	.getattr  = prlfs_getattr,
	.follow_link = prlfs_follow_link,
	.put_link = prlfs_put_link,
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	.readlink = generic_readlink,
	.getattr  = prlfs_getattr,
	.get_link = prlfs_get_link,
#else
	.getattr  = prlfs_getattr,
	.get_link = prlfs_get_link,
#endif
};

ssize_t prlfs_rw(struct inode *inode, char *buf, size_t size,
		                loff_t *off, unsigned int rw, int user, int flags);


int prlfs_readpage(struct file *file, struct page *page) {
	char *buf;
	ssize_t ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	struct inode *inode = file->f_inode;
#else
	struct inode *inode = file->f_dentry->d_inode;
#endif
	loff_t off = page->index << PAGE_SHIFT;

	if (!file) {
		unlock_page(page);
		return -EINVAL;
	}

	if (!PageUptodate(page)) {
		buf = kmap(page);
		ret = prlfs_rw(inode, buf, PAGE_SIZE, &off, 0, 0, TG_REQ_PF_CTX);
		if (ret < 0) {
			kunmap(page);
			unlock_page(page);
			return -EIO;
		}
		if (ret < PAGE_SIZE)
			memset(buf + ret, 0, PAGE_SIZE - ret);
		kunmap(page);
		flush_dcache_page(page);
		SetPageUptodate(page);
	}
	unlock_page(page);
	return 0;
}

int prlfs_writepage(struct page *page, struct writeback_control *wbc) {
	struct inode *inode = page->mapping->host;
	loff_t i_size = inode->i_size;
	char *buf;
	ssize_t ret;
	int rc = 0;
	loff_t off = page->index << PAGE_SHIFT;
	loff_t w_remainder = i_size - off;

	prlfs_inode_lock(inode);
	buf = kmap(page);
	ret = prlfs_rw(inode, buf,
		       w_remainder < PAGE_SIZE ? w_remainder : PAGE_SIZE,
		       &off, 1, 0, TG_REQ_COMMON);
	kunmap(page);
	if (ret < 0)
		rc =  -EIO;

	prlfs_inode_unlock(inode);
	unlock_page(page);
	return rc;
}

static const struct address_space_operations prlfs_aops = {
	.readpage		= prlfs_readpage,
	.writepage		= prlfs_writepage,
};



static int prlfs_root_revalidate(struct dentry *dentry,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
					int flags
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
					struct nameidata *nd
#else
					unsigned int flags
#endif
	)
{
	return 1;
}

struct dentry_operations prlfs_root_dops = {
	.d_revalidate = prlfs_root_revalidate,
};

struct inode_operations prlfs_root_iops = {
	.lookup		= prlfs_lookup,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define SET_INODE_INO(inode) do { } while (0)
#else
#define SET_INODE_INO(inode) do { (inode)->i_ino = get_next_ino(); } while (0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
#define prlfs_current_time(inode) current_time(inode)
#else
#define prlfs_current_time(inode) CURRENT_TIME
#endif

struct inode *prlfs_get_inode(struct super_block *sb,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
			umode_t mode
#else
			int mode
#endif
			)
{
	struct inode * inode;
	struct prlfs_fd* pfd;

	DPRINTK("ENTER\n");
	inode = new_inode(sb);
	if (inode) {
		inode->i_mode = mode;
		inode->i_blocks = 0;
		inode->i_ctime = prlfs_current_time(inode);
		inode->i_atime = inode->i_mtime = inode->i_ctime;
		inode->i_uid = PRLFS_SB(sb)->uid;
		inode->i_gid = PRLFS_SB(sb)->gid;
		inode->i_mapping->a_ops = &prlfs_aops;

		pfd = kmalloc(sizeof(struct prlfs_fd), GFP_KERNEL);
		if (pfd != NULL)
			memset(pfd, 0, sizeof(struct prlfs_fd));
		else
			pfd = ERR_PTR(-ENOMEM);
		inode_set_pfd(inode, pfd);

		SET_INODE_INO(inode);
		switch (mode & S_IFMT) {
		case S_IFDIR:
			inode->i_op = &prlfs_dir_iops;
			inode->i_fop = &prlfs_dir_fops;
			break;
		case 0: case S_IFREG:
			prlfs_hlist_init(inode);
			inode->i_op = &prlfs_file_iops;
			inode->i_fop =  &prlfs_file_fops;
			break;
		case S_IFLNK:
			inode->i_op = &prlfs_symlink_iops;
			inode->i_fop = &prlfs_file_fops;
			break;
		}
	}
	DPRINTK("EXIT returning %p\n", inode);
	return inode;
}

void prlfs_read_inode(struct inode *inode)
{
	ino_t ino = inode->i_ino;
	struct super_block *sb = inode->i_sb;
	struct prlfs_fd *pfd;

	inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO | S_IWUSR;
	inode->i_ctime = prlfs_current_time(inode);
	inode->i_atime = inode->i_mtime = inode->i_ctime;
	inode->i_uid = PRLFS_SB(sb)->uid;
	inode->i_gid = PRLFS_SB(sb)->gid;

	if (!inode_get_pfd(inode)) {
		pfd = kmalloc(sizeof(struct prlfs_fd), GFP_KERNEL);
		if (pfd != NULL)
			memset(pfd, 0, sizeof(struct prlfs_fd));
		else
			pfd = ERR_PTR(-ENOMEM);
		inode_set_pfd(inode, pfd);
	}

	if (ino == PRLFS_ROOT_INO) {
		inode->i_op = &prlfs_dir_iops;
		inode->i_fop = &prlfs_dir_fops;
	}
}
