/*
 * Copyright (c) 1999-2016 Parallels International GmbH.
 * All rights reserved.
 * http://www.parallels.com
 */

#ifndef __PRL_FSFREEZE_COMPAT_H__
#define __PRL_FSFREEZE_COMPAT_H__

static struct proc_dir_entry *
prlfs_freeze_proc_create(char *name, umode_t mode,
                         struct proc_dir_entry *parent,
                         struct file_operations *fops)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct proc_dir_entry *p = create_proc_entry(name, mode, parent);
	if (p)
		p->proc_fops = fops;
	return p;
#else
	return proc_create(name, mode, parent, fops);
#endif
}

#endif
