/*
 * Copyright (C) 1999-2016 Parallels International GmbH. All Rights Reserved.
 * Parallels linux shared folders filesystem definitions
 */

#ifndef __PRL_FS_H__
#define __PRL_FS_H__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/param.h>
#include <linux/pagemap.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <uapi/linux/mount.h>
#include <linux/fcntl.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#include <linux/backing-dev-defs.h>
#else
#include <linux/backing-dev.h>
#endif
#include <asm/uaccess.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#include <linux/uidgid.h>
#endif

#include "SharedFolders/Interfaces/sf_lin.h"
#include "Toolgate/Interfaces/Tg.h"
#include "Toolgate/Guest/Linux/Interfaces/prltg_call.h"
#include "Toolgate/Guest/Interfaces/tgreq.h"

#define PRLFS_MAGIC	0x7C7C6673 /* "||fs" */


#ifdef RHEL_RELEASE_CODE
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 2)
#define PRLFS_RHEL_6_2_GE
#endif
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 3)
#define PRLFS_RHEL_7_3_GE
#endif
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)

typedef uid_t kuid_t;
typedef gid_t kgid_t;

#define prl_make_kuid(x) ((kuid_t)x)
#define prl_make_kgid(x) ((kgid_t)x)
#define prl_from_kuid(x) ((uid_t)x)
#define prl_from_kgid(x) ((gid_t)x)

#define uid_eq(x, y) (x == y)
#define gid_eq(x, y) (x == y)

#else

#define prl_make_kuid(x) make_kuid(current_user_ns(), x)
#define prl_make_kgid(x) make_kgid(current_user_ns(), x)
#define prl_from_kuid(x) from_kuid(current_user_ns(), x)
#define prl_from_kgid(x) from_kgid(current_user_ns(), x)

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#define FILE_DENTRY(f) ((f)->f_path.dentry)
#else
#define FILE_DENTRY(f) ((f)->f_dentry)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)

#define prlfs_inode_lock(i) inode_lock(i)
#define prlfs_inode_unlock(i) inode_unlock(i)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)

#define prlfs_inode_lock(i) mutex_lock(&(i)->i_mutex)
#define prlfs_inode_unlock(i) mutex_unlock(&(i)->i_mutex)

#else

#define prlfs_inode_lock(i) down(&(i)->i_sem)
#define prlfs_inode_unlock(i) up(&(i)->i_sem)

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
#define prlfs_hlist_init(inode) hlist_add_fake(&(inode)->i_hash)
#else
#define prlfs_hlist_init(inode) do { (inode)->i_hash.pprev = &(inode)->i_hash.next; } while (0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#define prlfs_bdi_init(bdi) bdi_init(bdi)
#else
#define prlfs_bdi_init(bdi) (0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#define prlfs_bdi_register(sb, bdi, sfid, dev) super_setup_bdi_name(sb, "prlfs_%u_%u", sfid, dev)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#define prlfs_bdi_register(sb, bdi, sfid, dev) bdi_register(bdi, NULL, "prlfs_%u_%u", sfid, dev)
#else
#define prlfs_bdi_register(sb, bdi, sfid, dev) (0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#define prlfs_bdi_destroy(bdi) bdi_destroy(bdi)
#else
#define prlfs_bdi_destroy(bdi) do { } while (0)
#endif

struct prlfs_sb_info {
	struct backing_dev_info bdi;
	struct	pci_dev *pdev;
	unsigned sfid;
	unsigned ttl;
	kuid_t uid;
	kgid_t gid;
	int readonly;
	int share;
	int plain;
	char nls[LOCALE_NAME_LEN];
	char name[NAME_MAX];
};

struct prlfs_fd {
	unsigned long long	fd;
	unsigned int		sfid;
	unsigned long long	f_counter;
	unsigned int		f_flags;
};

#ifdef RHEL_RELEASE_CODE
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5, 0) && LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18)
#define _PRLFS_INODE_I_PRIVATE
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19) || defined(_PRLFS_INODE_I_PRIVATE)

#define inode_get_pfd(inode)  ((struct prlfs_fd *)(inode)->i_private)
static inline void inode_set_pfd(struct inode *inode, struct prlfs_fd *pfd)
{
	inode->i_private = (void *)pfd;
}

#else

#define inode_get_pfd(inode)  ((struct prlfs_fd *)(inode)->u.generic_ip)
static inline void inode_set_pfd(struct inode *inode, struct prlfs_fd *pfd)
{
	inode->u.generic_ip = (void *)pfd;
}

#endif

static inline void init_pfi(struct prlfs_file_info *pfi, struct inode *inode, 
				unsigned long long offset, unsigned int flags)
{
	if(inode) {
		pfi->fd = inode_get_pfd(inode)->fd;
		pfi->sfid = inode_get_pfd(inode)->sfid;
	} else {
		pfi->fd = 0;
		pfi->sfid = 0;
	}
	pfi->offset = offset;
	pfi->flags = flags;
}

struct buffer_descriptor {
	void *buf;
	unsigned long long len;
	int write;
	int user;
	int flags;
};

void init_buffer_descriptor(struct buffer_descriptor *bd, void *buf,
			    unsigned long long len, int write, int user);

void *prlfs_get_path(struct dentry *dentry, void *buf, int *plen);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define	PRLFS_ALLOC_SB_INFO(sb) \
do {				\
	sb->s_fs_info = kmalloc(sizeof(struct prlfs_sb_info), GFP_KERNEL); \
} while (0)

static inline struct prlfs_sb_info * PRLFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}
#else
#define PRLFS_ALLOC_SB_INFO(sb) \
do {				\
	sb->u.generic_sbp = kmalloc(sizeof(struct prlfs_sb_info), GFP_KERNEL);\
} while (0)
static inline struct prlfs_sb_info * PRLFS_SB(struct super_block *sb)
{
	return (struct prlfs_sb_info *)(sb->u.generic_sbp);
}
#endif

void prlfs_read_inode(struct inode *inode);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#define d_set_d_op(_dentry, _d_op)	do { _dentry->d_op = _d_op; } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
typedef long compat_statfs_block;
#else
typedef u64 compat_statfs_block;
#endif

int host_request_get_sf_list(struct pci_dev *pdev, void *data, int size);
int host_request_sf_param(struct pci_dev *pdev, void *data, int size,
					 struct prlfs_sf_parameters *psp);
int host_request_attr (struct super_block *sb, const char *path, int psize,
						struct buffer_descriptor *bd);
int host_request_mount(struct super_block *sb,
				 struct prlfs_sf_parameters *psp);
int host_request_open(struct super_block *sb, struct prlfs_file_info *pfi,
						const char *p, int plen);
int host_request_release(struct super_block *sb, struct prlfs_file_info *pfi);
int host_request_readdir(struct super_block *sb, struct prlfs_file_info *pfi,
						 void *buf, int *buflen);
int host_request_rw(struct super_block *sb, struct prlfs_file_info *pfi,
						 struct buffer_descriptor *bd);
int host_request_remove(struct super_block *sb, void *buf, int buflen);
int host_request_rename(struct super_block *sb, void *buf, size_t buflen,
				void *nbuf, size_t nlen);
int host_request_statfs(struct super_block *sb, long *bsize,
						compat_statfs_block *blocks, compat_statfs_block *bfree);
int host_request_readlink(struct super_block *sb, void *src_path, int src_len,
                                                  void *tgt_path, int tgt_len);
int host_request_symlink(struct super_block *sb, const void *src_path, int src_len,
                         const void *tgt_path, int tgt_len);

/* define to 1 to enable copious debugging info */
#undef DRV_DEBUG

/* define to 1 to disable lightweight runtime debugging checks */
#undef DRV_NDEBUG

#ifdef DRV_DEBUG
/* note: prints function name for you */
#  define DPRINTK(fmt, args...) printk(KERN_DEBUG "%s: " fmt, __FUNCTION__ , ## args)
#else
#  define DPRINTK(fmt, args...)
#endif

#ifdef DRV_NDEBUG
#  define assert(expr) do {} while (0)
#else
#  define assert(expr) \
	if(!(expr)) {					\
	printk( "Assertion failed! %s,%s,%s,line=%d\n",	\
	#expr,__FILE__,__FUNCTION__,__LINE__);		\
	}
#endif

#define MODNAME		"prlfs"
#define DRV_VERSION	"1.5.5"
#define PFX		MODNAME ": "

#define PRLFS_ROOT_INO 2
#define PRLFS_GOOD_INO 8
#define ID_STR_LEN 16

#ifndef PCI_VENDOR_ID_PARALLELS
#define PCI_VENDOR_ID_PARALLELS		0x1ab8
#endif
#ifndef PCI_DEVICE_ID_TOOLGATE
#define PCI_DEVICE_ID_TOOLGATE		0x4000
#endif

/* Dentry prlfs speciffic flags stored in dentry->d_fsdata */
enum {
	PRL_DFL_TAG = 0x1UL, /* tagged detnry, used for debuging purposes */
	PRL_DFL_UNLINKED = 0x2UL, /* Unlinked dentry. */
};

unsigned long *prlfs_dfl( struct dentry *de);
#endif /* __PRL_FS_H__ */
