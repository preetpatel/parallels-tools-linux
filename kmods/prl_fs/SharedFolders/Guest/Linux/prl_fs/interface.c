/*
 *	prlfs/interface.c
 *
 *	Copyright (C) 1999-2016 Parallels International GmbH
 *	Author: Vasily Averin <vvs@parallels.com>
 *
 *	Parallels Linux shared folders filesystem
 *
 *	pci toolgate interface functions
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include "prlfs.h"

struct status_table{
	unsigned tg;
	int error;
};
/* toolgate <=> linux error codes matrix */
struct status_table linux_err_tbl[] = {
	{TG_STATUS_SUCCESS,			0},
	{TG_STATUS_PENDING,			EAGAIN},
	{TG_STATUS_CANCELLED,			ERESTARTSYS},
	{TG_STATUS_MALFORMED_REQUEST,		EINVAL},
	{TG_STATUS_INVALID_REQUEST,		EINVAL},
	{TG_STATUS_INVALID_PARAMETER,		EINVAL},
	{TG_STATUS_NO_MEMORY,			ENOMEM},
	{TG_STATUS_NO_RESOURCES,		ENOMEM},
	{TG_STATUS_ACCESS_VIOLATION,		EACCES},
	{TG_STATUS_ACCESS_DENIED,		EPERM},
	{TG_STATUS_BAD_NETWORK_NAME,		ENOENT},
	{TG_STATUS_BUFFER_TOO_SMALL,		EINVAL},
	{TG_STATUS_CANNOT_DELETE,		EPERM},
	{TG_STATUS_DIRECTORY_NOT_EMPTY,		ENOTEMPTY},
	{TG_STATUS_DISK_FULL,			ENOSPC},
	{TG_STATUS_EAS_NOT_SUPPORTED,		ENOTSUPP},
	{TG_STATUS_END_OF_FILE,			EINVAL},
	{TG_STATUS_FILE_DELETED,		ENOENT},
	{TG_STATUS_FILE_IS_A_DIRECTORY,		EISDIR},
	{TG_STATUS_INSUFFICIENT_RESOURCES,	ENOMEM},
	{TG_STATUS_INVALID_HANDLE,		EINVAL},
	{TG_STATUS_NO_MORE_FILES,		ENOENT},
	{TG_STATUS_NO_SUCH_FILE,		ENOENT},
	{TG_STATUS_NOT_A_DIRECTORY,		ENOTDIR},
	{TG_STATUS_NOT_IMPLEMENTED,		ENOTSUPP},
	{TG_STATUS_OBJECT_NAME_COLLISION,	ESTALE},
	{TG_STATUS_OBJECT_NAME_INVALID,		EINVAL},
	{TG_STATUS_OBJECT_NAME_NOT_FOUND,	ENOENT},
	{TG_STATUS_OBJECT_PATH_NOT_FOUND,	ENOENT},
	{TG_STATUS_TOO_MANY_OPENED_FILES,	EMFILE},
	{TG_STATUS_UNSUCCESSFUL,		ENOMEM},
	{TG_STATUS_TOOL_NOT_READY,		ENOMEM},
	{TG_STATUS_REQUEST_ALREADY_EXISTS,	EINVAL},
	{TG_STATUS_INCOMPATIBLE_VERSION,	ENODEV},
	{TG_STATUS_SUSPENDED,			ENODEV},
	{TG_STATUS_NOT_HANDLED,			EINTR},
	{TG_STATUS_STALE_HANDLE,		ESTALE},
	{TG_STATUS_NOT_SAME_DEVICE,		EXDEV},
	{TG_STATUS_STOPPED_ON_SYMLINK,	ELOOP},
};

static int TG_ERR(unsigned status)
{
	static const int sz = sizeof(linux_err_tbl)/sizeof(struct status_table);
	int i;
	for (i = 0; i < sz; i++)
		if (status == linux_err_tbl[i].tg)
			return linux_err_tbl[i].error;
	DPRINTK("prlfs:WARN unknown error status = %d\n", status);
	return -EINVAL;
}

static void init_req_desc(TG_REQ_DESC *sdesc, TG_REQUEST *src,
			  void *idata, TG_BUFFER *sbuf)
{
	sdesc->src = src;
	sdesc->idata = idata;
	sdesc->sbuf = sbuf;
	sdesc->flags = 0;
	sdesc->kernel_bufs = 0;
}

static void init_tg_request(TG_REQUEST *src, unsigned request,
		unsigned short isize, unsigned short bnum)
{
	src->Request = request;
	src->InlineByteCount = isize;
	src->BufferCount = bnum;
}

static void init_tg_buffer(TG_REQ_DESC *sdesc, int bnum, void *buffer,
		size_t size, int write, int user)
{
	TG_BUFFER *sbuf = sdesc->sbuf + bnum;
	sbuf->u.Buffer = buffer;
	sbuf->ByteCount = size;
	sbuf->Writable = (write == 0) ? 0 : 1;
	if (user == 0)
		prltg_buf_set_kernelspace(sdesc, bnum);
}

int host_request_get_sf_list(struct pci_dev *pdev, void *data, int size)
{
	int blen, ret;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer;
	} Req;

	memset(&Req, 0, sizeof(Req));
	blen = sizeof(struct prlfs_sf_parameters);
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_GETSFLIST, 0, 1);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer);
	init_tg_buffer(&sdesc, 0, data, size, 1, 0);
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);
	return ret;
}

int host_request_sf_param(struct pci_dev *pdev, void *data, int size,
					 struct prlfs_sf_parameters *psp)
{
	int blen, ret;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	memset(&Req, 0, sizeof(Req));
	blen = sizeof(struct prlfs_sf_parameters);
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_GETSFPARM, 0, 2);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	init_tg_buffer(&sdesc, 0, (void *)psp, blen, 1, 0);
	init_tg_buffer(&sdesc, 1, data, size, 1, 0);
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);
	return ret;
}

int host_request_attr(struct super_block *sb, const char *path, int psize,
						 struct buffer_descriptor *bd)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_ATTR, 0, 2);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	init_tg_buffer(&sdesc, 0, (void *)path, psize, 0, 0);
	init_tg_buffer(&sdesc, 1, bd->buf, bd->len, bd->write, bd->user);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);
	return ret;
}

int host_request_open(struct super_block *sb, struct prlfs_file_info *pfi,
			const char *p, int plen)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct prlfs_file_desc *pfd;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;
	pfd = kmalloc(sizeof(struct prlfs_file_desc), GFP_KERNEL);
	if (!pfd)
		return -ENOMEM;
	prlfs_file_info_to_desc(pfd, pfi);
	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_OPEN, 0, 2);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	init_tg_buffer(&sdesc, 0, (void *)p, plen, 0, 0);
	init_tg_buffer(&sdesc, 1, (void *)pfd, PFD_LEN, 1, 0);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);

	prlfs_file_desc_to_info(pfi, pfd);
	kfree(pfd);
	return ret;
}

int host_request_release(struct super_block *sb, struct prlfs_file_info *pfi)
{
	int ret;
	int retry = 1000;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct prlfs_file_desc *pfd;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer;
	} Req;
	pfd = kmalloc(sizeof(struct prlfs_file_desc), GFP_KERNEL);
	if (!pfd)
		return -ENOMEM;
retry:
	prlfs_file_info_to_desc(pfd, pfi);
	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_RELEASE, 0, 1);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer);
	init_tg_buffer(&sdesc, 0, (void *)pfd, PFD_LEN, 0, 0);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS)) {
		if (Req.Req.Status == TG_STATUS_CANCELLED) {
			ret = -ERESTARTSYS;
			if (retry-- > 0)
				goto retry;
		} else {
			ret = -TG_ERR(Req.Req.Status);
		}
	}
	kfree(pfd);
	return ret;
}

int host_request_readdir(struct super_block *sb, struct prlfs_file_info *pfi,
			 void *buf, int *buflen)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct prlfs_file_desc *pfd;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;


	pfd = kmalloc(sizeof(struct prlfs_file_desc), GFP_KERNEL);
	if (!pfd)
		return -ENOMEM;
	prlfs_file_info_to_desc(pfd, pfi);
	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_READDIR, 0, 2);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	init_tg_buffer(&sdesc, 0, (void *)pfd, PFD_LEN, 1, 0);
	init_tg_buffer(&sdesc, 1, buf, *buflen, 1, 0);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if (ret == 0) {
		if (Req.Req.Status == TG_STATUS_SUCCESS)
			*buflen = Req.Buffer[1].ByteCount;
		else
			ret = -TG_ERR(Req.Req.Status);
	}
	prlfs_file_desc_to_info(pfi, pfd);
	kfree(pfd);
	return ret;
}

int host_request_rw(struct super_block *sb, struct prlfs_file_info *pfi,
						 struct buffer_descriptor *bd)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct prlfs_file_desc *pfd;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	pfd = kmalloc(sizeof(struct prlfs_file_desc), GFP_KERNEL);
	if (!pfd)
		return -ENOMEM;
	prlfs_file_info_to_desc(pfd, pfi);
	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_RW, 0, 2);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	init_tg_buffer(&sdesc, 0, (void *)pfd, PFD_LEN, 0, 0);
	init_tg_buffer(&sdesc, 1, bd->buf, bd->len, bd->write, bd->user);
	sdesc.flags = bd->flags;
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if (ret == 0) {
		if (Req.Req.Status == TG_STATUS_SUCCESS)
			bd->len = Req.Buffer[1].ByteCount;
		else
			ret = -TG_ERR(Req.Req.Status);
	}
	kfree(pfd);
	return ret;
}

int host_request_remove(struct super_block *sb, void *buf, int buflen)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer;
	} Req;

	memset (&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_REMOVE, 0, 1);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer);
	init_tg_buffer(&sdesc, 0, buf, buflen, 0, 0);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);

	return ret;
}

int host_request_rename(struct super_block *sb, void *buf, size_t buflen,
				void *nbuf, size_t nlen)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_RENAME, 0, 2);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	init_tg_buffer(&sdesc, 0, buf, buflen, 0, 0);
	init_tg_buffer(&sdesc, 1, nbuf, nlen, 0, 0);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);

	return ret;
}

int host_request_statfs(struct super_block *sb, long *bsize, compat_statfs_block *blocks,
                        compat_statfs_block *bfree)
{
	int ret;
	TG_REQ_DESC sdesc;
	typedef struct {
		long long TotalAllocationUnits;
		long long AvailableAllocationUnits;
		u32 SectorsPerAllocationUnit;
		u32 BytesPerSector;
	} fsinfo_t;
	struct {
		TG_REQUEST Req;
		union {
			unsigned sfid;
			fsinfo_t fsinfo;
		} u;
	} Req;

	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_GETSIZEINFO, sizeof(Req.u), 0);
	Req.u.sfid = PRLFS_SB(sb)->sfid;
	init_req_desc(&sdesc, &Req.Req, &Req.u, NULL);
	ret = call_tg_sync(PRLFS_SB(sb)->pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);
	*bsize = Req.u.fsinfo.SectorsPerAllocationUnit * Req.u.fsinfo.BytesPerSector;
	*blocks = Req.u.fsinfo.TotalAllocationUnits;
	*bfree = Req.u.fsinfo.AvailableAllocationUnits;
	return ret;
}

int host_request_readlink(struct super_block *sb, void *src_path, int src_len,
                          void *tgt_path, int tgt_len)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_READLNK, 0, 2);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	init_tg_buffer(&sdesc, 0, src_path, src_len, 0, 0);
	init_tg_buffer(&sdesc, 1, tgt_path, tgt_len, 1, 0);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);
	return ret;
}

int host_request_symlink(struct super_block *sb, const void *src_path, int src_len,
                         const void *tgt_path, int tgt_len)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[3];
	} Req;

	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_CREATELNK, 0, 3);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	init_tg_buffer(&sdesc, 0, &PRLFS_SB(sb)->sfid, sizeof(PRLFS_SB(sb)->sfid), 0, 0);
	init_tg_buffer(&sdesc, 1, (void *)src_path, src_len, 0, 0);
	init_tg_buffer(&sdesc, 2, (void *)tgt_path, tgt_len, 0, 0);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);
	return ret;
}

