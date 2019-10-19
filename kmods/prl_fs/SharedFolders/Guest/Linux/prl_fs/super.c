/*
 *	prlfs/super.c
 *
 *	Copyright (C) 1999-2016 Parallels International GmbH
 *	Author: Vasily Averin <vvs@parallels.com>
 *
 *	Parallels Linux shared folders filesystem
 */

#include <linux/init.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ctype.h>
#include <linux/vfs.h>
#include <linux/backing-dev.h>
#include "prlfs.h"
#include "prlfs_compat.h"

#define DRIVER_LOAD_MSG	"Parallels Linux shared folders filesystem driver "\
							 DRV_VERSION " loaded"

static char version[] = KERN_INFO DRIVER_LOAD_MSG "\n";

static struct pci_dev *tg_dev;

extern struct file_operations prlfs_names_fops;
extern struct inode_operations prlfs_names_iops;

static int prlfs_strtoui(char *cp, unsigned *result){
	int ret = 0;
	unsigned ui = 0;
	unsigned digit;

	if (!cp || (*cp == 0))
		return -EINVAL;

	while (*cp) {
		if (isdigit(*cp)) {
			digit = *cp - '0';
		} else {
			ret = -EINVAL;
			break;
		}
		if (ui > ui * 10U + digit)
			return -EINVAL;
		ui = ui * 10U + digit;
		cp++;
	}

	if (ret == 0)
		*result = ui;

	return ret;
}

static int
prlfs_parse_mount_options(char *options, struct prlfs_sb_info *sbi)
{
	int ret = 0;
	char *opt, *val;

	DPRINTK("ENTER\n");
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	sbi->uid = current->uid;
	sbi->gid = current->gid;
#else
	sbi->uid = current->cred->uid;
	sbi->gid = current->cred->gid;
#endif
	sbi->ttl = HZ;

	if (!options)
	       goto out;

	while (!ret && (opt = strsep(&options, ",")) != NULL)
	{
		if (!*opt)
			continue;

		val = strchr(opt, '=');
		if (val) {
			*(val++) = 0;
			if (strlen(val) == 0)
				val = NULL;
		}
		if (!strcmp(opt, "ttl") && val)
			ret = prlfs_strtoui(val, &sbi->ttl);
		else if (!strcmp(opt, "uid") && val) {
			uid_t uid_arg = -1;
			ret = prlfs_strtoui(val, &uid_arg);
			sbi->uid = prl_make_kuid(uid_arg);
		}
		else if (!strcmp(opt, "gid") && val) {
			gid_t gid_arg = -1;
			ret = prlfs_strtoui(val, &gid_arg);
			sbi->gid = prl_make_kgid(gid_arg);
		}
		else if (!strcmp(opt, "nls") && val)
			strncpy(sbi->nls, val, LOCALE_NAME_LEN - 1);
		else if (!strcmp(opt, "share"))
			sbi->share = 1;
		else if (!strcmp(opt, "plain"))
			sbi->plain = 1;
		else if (!strcmp(opt, "sf") && val)
			strncpy(sbi->name, val, sizeof(sbi->name));
		else
			ret = -EINVAL;
	}
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_remount(struct super_block *sb, int *flags, char *data)
{
	int ret = 0;
	DPRINTK("ENTER\n");
	if ( (!((*flags) & MS_RDONLY) && PRLFS_SB(sb)->readonly) ||
	       ((*flags) & MS_MANDLOCK) )
			ret = -EINVAL;

	*flags |= MS_SYNCHRONOUS; /* silently don't drop sync flag */
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static void prlfs_put_super(struct super_block *sb)
{
	struct prlfs_sb_info *prlfs_sb;

	prlfs_sb = PRLFS_SB(sb);
	prlfs_bdi_destroy(&prlfs_sb->bdi);
	kfree(prlfs_sb);
}

struct inode *prlfs_iget(struct super_block *sb, ino_t ino)
{
#ifdef PRLFS_IGET
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (inode && (inode->i_state & I_NEW)) {
		prlfs_read_inode(inode);
		unlock_new_inode(inode);
	}
	return inode;
#else
	return iget(sb, ino);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define COMPAT_STATFS	struct statfs
#else
#define COMPAT_STATFS	struct kstatfs
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
int prlfs_statfs(struct super_block *sb, COMPAT_STATFS *buf)
#else
int prlfs_statfs(struct dentry *de, COMPAT_STATFS *buf)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
	struct super_block *sb = de->d_sb;
#endif
	buf->f_type = PRLFS_MAGIC;
	buf->f_namelen = NAME_MAX;
	buf->f_files = buf->f_ffree = 4096;
	host_request_statfs(sb, &buf->f_bsize,
		&buf->f_blocks, &buf->f_bavail);
	buf->f_bfree = buf->f_bavail;
	DPRINTK("fsstat: bsize=%ld blocks=%llu bfree=%llu bavail=%llu\n",
		buf->f_bsize, buf->f_blocks, buf->f_bfree, buf->f_bavail);
	return 0;
}

static void prlfs_evict_inode(struct inode *inode) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
	truncate_inode_pages_final(&inode->i_data);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) && LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
#ifdef PRLFS_RHEL_7_3_GE
	if (inode->i_data.nrpages || inode->i_data.nrexceptional)
#else
	if (inode->i_data.nrpages)
#endif
		truncate_inode_pages(&inode->i_data, 0);
#else
	truncate_inode_pages(&inode->i_data, 0);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) && LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	end_writeback(inode);
#else
	clear_inode(inode);
#endif
	kfree(inode_get_pfd(inode));
	inode_set_pfd(inode, NULL);
}

struct super_operations prlfs_super_ops = {
#ifndef PRLFS_IGET
	.read_inode	= prlfs_read_inode,
#endif
	.statfs         = prlfs_statfs,
	.remount_fs	= prlfs_remount,
	.put_super	= prlfs_put_super,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	.evict_inode	= prlfs_evict_inode,
#else
	.delete_inode	= prlfs_evict_inode,
#endif
};

static int get_sf_id(struct pci_dev *pdev, const char *sf_name)
{
	struct prlfs_sf_parameters *psp;
	struct prlfs_sf_response *prsp;
	void *p;
	int ret;

	DPRINTK("ENTER\n");
	p = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (p == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	psp = kzalloc(sizeof(struct prlfs_sf_parameters), GFP_KERNEL);
	if (!psp) {
		ret = -ENOMEM;
		goto out_free;
	}

	memset(p, 0, PAGE_SIZE);
	psp->id = GET_SF_ID_BY_NAME;
	prsp = p;
	strncpy(prsp->buf, sf_name, sizeof(prsp->buf) - 1);
	ret = host_request_sf_param(pdev, p, PAGE_SIZE, psp);
	if (ret >= 0)
		ret = psp->index;

	kfree(psp);
out_free:
	kfree(p);
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_bdi_init_and_register(struct super_block *sb, struct prlfs_sb_info *prlfs_sb) {
	int ret = 0;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 11, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	prlfs_sb->bdi.name = "prlfs";
	sb->s_bdi = &prlfs_sb->bdi;
#endif

	ret = prlfs_bdi_init(&prlfs_sb->bdi);
	if (ret)
		goto out;

	ret = prlfs_bdi_register(sb, &prlfs_sb->bdi, prlfs_sb->sfid, sb->s_dev);
out:
	return ret;
}

static int prlfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode * inode;
	struct prlfs_sb_info *prlfs_sb;
	int ret = 0;

	DPRINTK("ENTER\n");
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_flags |= MS_NOATIME | MS_SYNCHRONOUS;
	sb->s_magic = PRLFS_MAGIC;
	sb->s_op = &prlfs_super_ops;
	PRLFS_ALLOC_SB_INFO(sb);
	prlfs_sb = PRLFS_SB(sb);
	if (prlfs_sb == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	memset(prlfs_sb, 0, sizeof(struct prlfs_sb_info));
	prlfs_sb->pdev = tg_dev;
	ret = prlfs_parse_mount_options(data, prlfs_sb);
	if (ret < 0)
		goto out_free;

	ret = get_sf_id(tg_dev, prlfs_sb->name);
	if (ret < 0)
		goto out_free;
	prlfs_sb->sfid = ret;
	ret = prlfs_bdi_init_and_register(sb, prlfs_sb);
	if (ret)
		goto out_bdi;

	DPRINTK("share=%s id=%u\n", prlfs_sb->name, prlfs_sb->sfid);

	inode = prlfs_iget(sb, PRLFS_ROOT_INO);
	if(!inode) {
		ret = -ENOMEM;
		goto out_bdi;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
	sb->s_root = d_make_root(inode);
#else
	sb->s_root = d_alloc_root(inode);
#endif
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto out_iput;
	}
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;

out_iput:
	iput(inode);
out_bdi:
	prlfs_bdi_destroy(&prlfs_sb->bdi);
out_free:
	kfree(prlfs_sb);
	goto out;
}

/* Adds device name as an additional mount option "sf" (shared folder).
 * If kernel passes device as an absolute path function drops everything except
 * basename.
 */
static void *extend_mount_data(void *data, const char *dev_name)
{
	char *ext_data;
	char *dev_name_fixed;
	size_t alloc_sz, sf_str_sz;
	DPRINTK("dev=%s, data=%s\n", dev_name, (const char*)data);
	dev_name_fixed = strrchr(dev_name, '/');
	if (dev_name_fixed)
		dev_name = dev_name_fixed + 1;
	sf_str_sz = sizeof("sf=") + strlen(dev_name);
	alloc_sz = sf_str_sz;
	if (data)
		// 1 - for comma
		alloc_sz += 1 + strlen(data);
	ext_data = kmalloc(alloc_sz, GFP_KERNEL);
	if (NULL == ext_data)
		return NULL;
	sprintf(ext_data, "sf=%s", dev_name);
	if (data)
		sprintf(ext_data + sf_str_sz - 1, ",%s", (const char*)data);
	return ext_data;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
struct super_block * prlfs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	struct super_block *sb;
	void *ext_data;
	ext_data = extend_mount_data(data, dev_name);
	if (NULL == ext_data)
		return ERR_PTR(-ENOMEM);
	sb = get_sb_nodev(fs_type, flags, ext_data, prlfs_fill_super);
	kfree(ext_data);
	return sb;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
int prlfs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	int ret;
	void *ext_data;
	ext_data = extend_mount_data(data, dev_name);
	if (NULL == ext_data)
		return -ENOMEM;
	ret = get_sb_nodev(fs_type, flags, ext_data, prlfs_fill_super, mnt);
	kfree(ext_data);
	return ret;
}
#else
static struct dentry *prlfs_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name,
				  void *raw_data)
{
	struct dentry *de;
	void *ext_data;
	ext_data = extend_mount_data(raw_data, dev_name);
	if (NULL == ext_data)
		return ERR_PTR(-ENOMEM);
	de = mount_nodev(fs_type, flags, ext_data, prlfs_fill_super);
	kfree(ext_data);
	return de;
}
#endif
#else
static struct super_block *prlfs_read_super(struct super_block *sb,
							void *data, int flags)
{
	if (prlfs_fill_super(sb, data, flags) < 0)
		return NULL;

	return sb;
}
#endif
static struct file_system_type prl_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "prl_fs",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	.get_sb		= prlfs_get_sb,
#else
	.mount		= prlfs_mount,
#endif
	.kill_sb	= kill_anon_super,
#else
	.read_super	= prlfs_read_super,
#endif
	/*  .fs_flags */
};

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *proc_prlfs;
static void *seq_sf_start(struct seq_file *s, loff_t *pos)
{
	int ret;
	unsigned int cnt;
	unsigned int *p;

	DPRINTK("ENTER\n");
	s->private = kmalloc(PAGE_SIZE, GFP_KERNEL);
	p = s->private;
	if (p == NULL) {
		p = ERR_PTR(-ENOMEM);
		goto out;
	}
	DPRINTK("pos %lld\n", *pos);
	if (*pos == 0)
		seq_printf(s, "List of shared folders:\n");
	memset(p, 0, PAGE_SIZE);
	ret = host_request_get_sf_list(tg_dev, p, PAGE_SIZE);
	if (ret < 0) {
		p = ERR_PTR(ret);
		goto out;
	}
	cnt = *p;
	if (cnt == 0 || *pos > cnt - 1)
		p = NULL;
	else
		p++;
out:
	DPRINTK("EXIT returning %p\n", p);
	return p;
}

static void *seq_sf_next(struct seq_file *s, void *v, loff_t *pos)
{
	unsigned int *p;
	unsigned cnt;

	DPRINTK("ENTER %lld\n", *pos);
	(*pos)++;
	p = s->private;
	cnt = *(unsigned *)s->private;
	if (*pos >= cnt) {
		p = NULL;
		goto out;
	}
	p = v;
	p++;
out:
	DPRINTK("EXIT returning %p\n", p);
	return p;
}

static void seq_sf_stop(struct seq_file *s, void *v)
{
	DPRINTK("%p\n", v);
	kfree(s->private);
}

static int seq_sf_show(struct seq_file *s, void *v)
{
	struct prlfs_sf_parameters *psp = 0;
	struct prlfs_sf_response *prsp;
	const char *ro[2] = {"ro","rw"};
	void *p;
	int ret;

	DPRINTK("ENTER\n");
	p = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (p == NULL)
		goto out;
	psp = kzalloc(sizeof(struct prlfs_sf_parameters), GFP_KERNEL);
	if (!psp)
		goto out_free;
	memset(p, 0, PAGE_SIZE);
	psp->index = *(unsigned int *)v;
	psp->id = GET_SF_INFO;
	strncpy((char *)psp->locale, "utf-8", LOCALE_NAME_LEN - 1);
	ret = host_request_sf_param(tg_dev, p, PAGE_SIZE, psp);
	if (ret < 0)
		goto out_free;

	prsp = p;
	if (prsp->ret == 0)
		goto out_free;

	*((char *)prsp + PAGE_SIZE - 1) = 0;
	seq_printf(s, "%x: %s ", psp->index, prsp->buf);
	if ( prsp->ret < 3)
		seq_puts(s, ro[prsp->ret - 1]);
	seq_puts(s, "\n");
out_free:
	kfree(psp);
	kfree(p);
out:
	DPRINTK("EXIT\n");
	return 0;
}

static struct seq_operations seq_sf_op = {
	.start	= seq_sf_start,
	.next	= seq_sf_next,
	.stop	= seq_sf_stop,
	.show	= seq_sf_show,
};

static int proc_sf_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &seq_sf_op);
}

static struct file_operations proc_sf_operations = {
	.owner		= THIS_MODULE,
	.open		= proc_sf_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int prlfs_proc_init(void)
{
	int ret = 0;
	struct proc_dir_entry *p;

	proc_prlfs = proc_mkdir("fs/prl_fs", NULL);
	if (proc_prlfs == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	p = prlfs_proc_create("sf_list", S_IFREG | S_IRUGO, proc_prlfs,
		&proc_sf_operations);
	if (p == NULL) {
		remove_proc_entry("fs/prl_fs", NULL);
		ret = -ENOMEM;
		goto out;
	}
out:
	return ret;
}

static void prlfs_proc_clean(void)
{
	remove_proc_entry("sf_list", proc_prlfs);
	remove_proc_entry("fs/prl_fs", NULL);
}
#else
static int  prlfs_proc_init(void) { return 0; }
static void prlfs_proc_clean(void) { return; }
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define pci_get_subsys pci_find_subsys
#define pci_dev_get(a)
#define pci_dev_put(a)
#endif
static int __init init_prlfs(void)
{
	int ret;
	DPRINTK("ENTER\n");
#ifdef MODULE
	printk(version);
#endif

	/* get toolgate device */
	tg_dev = pci_get_subsys(PCI_VENDOR_ID_PARALLELS,
				PCI_DEVICE_ID_TOOLGATE,
				PCI_ANY_ID, PCI_ANY_ID, NULL);
	if (tg_dev == NULL) {
		ret = -ENODEV;
		goto out;
	}
	pci_dev_get(tg_dev);
	ret = prlfs_proc_init();
	if (ret < 0)
		goto out_dev_put;

	ret = register_filesystem(&prl_fs_type);
	if (ret < 0)
		prlfs_proc_clean();
	else
		goto out;

out_dev_put:
	pci_dev_put(tg_dev);
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static void __exit exit_prlfs(void)
{
	DPRINTK("ENTER\n");
	printk(KERN_INFO "unloading " MODNAME "\n");
	unregister_filesystem(&prl_fs_type);
	prlfs_proc_clean();
	pci_dev_put(tg_dev);
	DPRINTK("EXIT\n");
}

module_init(init_prlfs)
module_exit(exit_prlfs)

MODULE_AUTHOR ("Parallels International GmbH");
MODULE_DESCRIPTION ("Parallels linux guest filesystem");
MODULE_LICENSE("Parallels");
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 0)
MODULE_INFO (supported, "external");
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
MODULE_ALIAS_FS("prl_fs");
#endif
