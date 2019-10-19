///////////////////////////////////////////////////////////////////////////////
///
/// @file sf_lin.h
///
/// Constants and data structures for the SharedFolders Linux guest and host
/// components interaction
///
/// @author vvs@
///
/// Copyright (c) 1999-2016 Parallels International GmbH.
/// All rights reserved.
/// http://www.parallels.com
///
///////////////////////////////////////////////////////////////////////////////

#ifndef __SF_LIN_H__
#define __SF_LIN_H__

#ifdef _WIN_
#  pragma pack(push, 1)
#endif

#ifndef PACKED
#  ifdef __GNUC__
#    define PACKED __attribute__((packed))
#  else
#    define PACKED
#  endif
#endif

#define SFLIN_CHECK_SIZE(typenam, actualsize, size) \
				struct sflin_check_size_of_##typenam { \
					char sizeof__##typenam##__##size[(actualsize) == (size) ? 1 : -1]; \
				};


struct prlfs_attr {
	unsigned long long size;
	unsigned long long atime;
	unsigned long long mtime;
	unsigned long long ctime;
	unsigned int mode;
	unsigned int uid;
	unsigned int gid;
	unsigned int valid;
} PACKED;
SFLIN_CHECK_SIZE(prlfs_attr, sizeof(struct prlfs_attr), 48)

#define PATTR_STRUCT_SIZE	sizeof(struct prlfs_attr)

/* valid bitmask */
#define _PATTR_SIZE	(1 << 0)
#define _PATTR_ATIME	(1 << 1)
#define _PATTR_MTIME	(1 << 2)
#define _PATTR_CTIME	(1 << 3)
#define _PATTR_MODE	(1 << 4)
#define _PATTR_UID	(1 << 5)
#define _PATTR_GID	(1 << 6)

struct prlfs_dir_entry {
	unsigned char	name_len;
	unsigned char	file_type;
	char	name[1];
} PACKED;
typedef struct prlfs_dir_entry prlfs_dirent;

#define PRLFS_DIR_PAD			8
#define PRLFS_DIR_ROUND			(PRLFS_DIR_PAD - 1)
#define PRLFS_DIR_REC_LEN(name_len)	(((name_len) + sizeof(prlfs_dirent) + PRLFS_DIR_ROUND ) & \
					 ~PRLFS_DIR_ROUND)

enum {
	PRLFS_FILE_TYPE_UNKNOWN = 0,
	PRLFS_FILE_TYPE_REGULAR,
	PRLFS_FILE_TYPE_DIRECTORY,
	PRLFS_FILE_TYPE_SYMLINK,
	PRLFS_FILE_TYPE_MAX,
};

/* ToolGate data structure, OS independed data representation*/
struct prlfs_file_desc {
        unsigned long long      fd;
        unsigned long long      offset;
        unsigned int            flags; /* prl_file_flags */
        unsigned int            sfid;

} PACKED;

#define PFD_LEN sizeof (struct prlfs_file_desc)

/* In memory data structure. By historical reasons some fs related flags are
 * OS depended. Every user must transform this structure to os independ data
 * structure before toolgate transfer.
 */
struct prlfs_file_info {
        unsigned long long      fd;
        unsigned long long      offset;
        unsigned int		flags;
        unsigned int            sfid;
	unsigned int		padding; /* unused */
} PACKED;

#define PFI_LEN         sizeof(struct prlfs_file_info)

enum prlfs_file_flags
{
	PRL_O_RDONLY,
	PRL_O_WRONLY,
	PRL_O_RDWR,
	PRL_O_CREAT,
	PRL_O_EXCL,
	PRL_O_NOCTTY,
	PRL_O_TRUNC,
	PRL_O_APPEND,
	PRL_O_NONBLOCK,
	PRL_O_SYNC,
	PRL_O_FASYNC,
	PRL_O_DIRECT,
	PRL_O_LARGEFILE,
	PRL_O_DIRECTORY,
	PRL_O_NOFOLLOW,
	PRL_O_NOATIME,
	PRL_O_CLOEXEC,
	PRL_O_NDELAY,
	PRL_O_LAST
};

#ifdef O_RDONLY
#define _TO_HOST_RDONLY(fl) \
	((1<<PRL_O_RDONLY) & (fl)) ? O_RDONLY : 0
#define _FROM_HOST_RDONLY(fl) \
	 ((fl)& O_RDONLY) ? (1<<PRL_O_RDONLY) : 0
#else
#define _TO_HOST_RDONLY(fl) 0
#define _FROM_HOST_RDONLY(fl) 0
#endif

#ifdef O_WRONLY
#define _TO_HOST_WRONLY(fl) \
	((1<<PRL_O_WRONLY) & (fl)) ? O_WRONLY : 0
#define _FROM_HOST_WRONLY(fl) \
	 ((fl)& O_WRONLY) ? (1<<PRL_O_WRONLY) : 0
#else
#define _TO_HOST_WRONLY(fl) 0
#define _FROM_HOST_WRONLY(fl) 0
#endif

#ifdef O_RDWR
#define _TO_HOST_RDWR(fl) \
	((1<<PRL_O_RDWR) & (fl)) ? O_RDWR : 0
#define _FROM_HOST_RDWR(fl) \
	 ((fl)& O_RDWR) ? (1<<PRL_O_RDWR) : 0
#else
#define _TO_HOST_RDWR(fl) 0
#define _FROM_HOST_RDWR(fl) 0
#endif

#ifdef O_CREAT
#define _TO_HOST_CREAT(fl) \
	((1<<PRL_O_CREAT) & (fl)) ? O_CREAT : 0
#define _FROM_HOST_CREAT(fl) \
	 ((fl)& O_CREAT) ? (1<<PRL_O_CREAT) : 0
#else
#define _TO_HOST_CREAT(fl) 0
#define _FROM_HOST_CREAT(fl) 0
#endif

#ifdef O_EXCL
#define _TO_HOST_EXCL(fl) \
	((1<<PRL_O_EXCL) & (fl)) ? O_EXCL : 0
#define _FROM_HOST_EXCL(fl) \
	 ((fl)& O_EXCL) ? (1<<PRL_O_EXCL) : 0
#else
#define _TO_HOST_EXCL(fl) 0
#define _FROM_HOST_EXCL(fl) 0
#endif

#ifdef O_NOCTTY
#define _TO_HOST_NOCTTY(fl) \
	((1<<PRL_O_NOCTTY) & (fl)) ? O_NOCTTY : 0
#define _FROM_HOST_NOCTTY(fl) \
	 ((fl)& O_NOCTTY) ? (1<<PRL_O_NOCTTY) : 0
#else
#define _TO_HOST_NOCTTY(fl) 0
#define _FROM_HOST_NOCTTY(fl) 0
#endif

#ifdef O_TRUNC
#define _TO_HOST_TRUNC(fl) \
	((1<<PRL_O_TRUNC) & (fl)) ? O_TRUNC : 0
#define _FROM_HOST_TRUNC(fl) \
	 ((fl)& O_TRUNC) ? (1<<PRL_O_TRUNC) : 0
#else
#define _TO_HOST_TRUNC(fl) 0
#define _FROM_HOST_TRUNC(fl) 0
#endif

#ifdef O_APPEND
#define _TO_HOST_APPEND(fl) \
	((1<<PRL_O_APPEND) & (fl)) ? O_APPEND : 0
#define _FROM_HOST_APPEND(fl) \
	 ((fl)& O_APPEND) ? (1<<PRL_O_APPEND) : 0
#else
#define _TO_HOST_APPEND(fl) 0
#define _FROM_HOST_APPEND(fl) 0
#endif

#ifdef O_NONBLOCK
#define _TO_HOST_NONBLOCK(fl) \
	((1<<PRL_O_NONBLOCK) & (fl)) ? O_NONBLOCK : 0
#define _FROM_HOST_NONBLOCK(fl) \
	 ((fl)& O_NONBLOCK) ? (1<<PRL_O_NONBLOCK) : 0
#else
#define _TO_HOST_NONBLOCK(fl) 0
#define _FROM_HOST_NONBLOCK(fl) 0
#endif

#ifdef O_SYNC
#define _TO_HOST_SYNC(fl) \
	((1<<PRL_O_SYNC) & (fl)) ? O_SYNC : 0
#define _FROM_HOST_SYNC(fl) \
	 ((fl)& O_SYNC) ? (1<<PRL_O_SYNC) : 0
#else
#define _TO_HOST_SYNC(fl) 0
#define _FROM_HOST_SYNC(fl) 0
#endif

#ifdef O_FASYNC
#define _TO_HOST_FASYNC(fl) \
	((1<<PRL_O_FASYNC) & (fl)) ? O_FASYNC : 0
#define _FROM_HOST_FASYNC(fl) \
	 ((fl)& O_FASYNC) ? (1<<PRL_O_FASYNC) : 0
#else
#define _TO_HOST_FASYNC(fl) 0
#define _FROM_HOST_FASYNC(fl) 0
#endif

#ifdef O_DIRECT
#define _TO_HOST_DIRECT(fl) \
	((1<<PRL_O_DIRECT) & (fl)) ? O_DIRECT : 0
#define _FROM_HOST_DIRECT(fl) \
	 ((fl)& O_DIRECT) ? (1<<PRL_O_DIRECT) : 0
#else
#define _TO_HOST_DIRECT(fl) 0
#define _FROM_HOST_DIRECT(fl) 0
#endif

#ifdef O_LARGEFILE
#define _TO_HOST_LARGEFILE(fl) \
	((1<<PRL_O_LARGEFILE) & (fl)) ? O_LARGEFILE : 0
#define _FROM_HOST_LARGEFILE(fl) \
	 ((fl)& O_LARGEFILE) ? (1<<PRL_O_LARGEFILE) : 0
#else
#define _TO_HOST_LARGEFILE(fl) 0
#define _FROM_HOST_LARGEFILE(fl) 0
#endif

#ifdef O_DIRECTORY
#define _TO_HOST_DIRECTORY(fl) \
	((1<<PRL_O_DIRECTORY) & (fl)) ? O_DIRECTORY : 0
#define _FROM_HOST_DIRECTORY(fl) \
	 ((fl)& O_DIRECTORY) ? (1<<PRL_O_DIRECTORY) : 0
#else
#define _TO_HOST_DIRECTORY(fl) 0
#define _FROM_HOST_DIRECTORY(fl) 0
#endif

#ifdef O_NOFOLLOW
#define _TO_HOST_NOFOLLOW(fl) \
	((1<<PRL_O_NOFOLLOW) & (fl)) ? O_NOFOLLOW : 0
#define _FROM_HOST_NOFOLLOW(fl) \
	 ((fl)& O_NOFOLLOW) ? (1<<PRL_O_NOFOLLOW) : 0
#else
#define _TO_HOST_NOFOLLOW(fl) 0
#define _FROM_HOST_NOFOLLOW(fl) 0
#endif

#ifdef O_NOATIME
#define _TO_HOST_NOATIME(fl) \
	((1<<PRL_O_NOATIME) & (fl)) ? O_NOATIME : 0
#define _FROM_HOST_NOATIME(fl) \
	 ((fl)& O_NOATIME) ? (1<<PRL_O_NOATIME) : 0
#else
#define _TO_HOST_NOATIME(fl) 0
#define _FROM_HOST_NOATIME(fl) 0
#endif

#ifdef O_CLOEXEC
#define _TO_HOST_CLOEXEC(fl) \
	((1<<PRL_O_CLOEXEC) & (fl)) ? O_CLOEXEC : 0
#define _FROM_HOST_CLOEXEC(fl) \
	 ((fl)& O_CLOEXEC) ? (1<<PRL_O_CLOEXEC) : 0
#else
#define _TO_HOST_CLOEXEC(fl) 0
#define _FROM_HOST_CLOEXEC(fl) 0
#endif

#ifdef O_NDELAY
#define _TO_HOST_NDELAY(fl) \
	((1<<PRL_O_NDELAY) & (fl)) ? O_NDELAY : 0
#define _FROM_HOST_NDELAY(fl) \
	 ((fl)& O_NDELAY) ? (1<<PRL_O_NDELAY) : 0
#else
#define _TO_HOST_NDELAY(fl) 0
#define _FROM_HOST_NDELAY(fl) 0
#endif

static inline void prlfs_file_desc_to_info(struct prlfs_file_info *dst,
		struct prlfs_file_desc *src)
{
	unsigned int hfl = 0, dfl = src->flags;
	dst->fd = src->fd;
	dst->offset = src->offset;
	/* FIXME: sfid in windows */
	dst->sfid = src->sfid;
	/* Convert OS depended bits.*/
	hfl |= _TO_HOST_RDONLY(dfl);
	hfl |= _TO_HOST_WRONLY(dfl);
	hfl |= _TO_HOST_RDWR(dfl);
	hfl |= _TO_HOST_CREAT(dfl);
	hfl |= _TO_HOST_EXCL(dfl);
	hfl |= _TO_HOST_NOCTTY(dfl);
	hfl |= _TO_HOST_TRUNC(dfl);
	hfl |= _TO_HOST_APPEND(dfl);
	hfl |= _TO_HOST_NONBLOCK(dfl);
	hfl |= _TO_HOST_SYNC(dfl);
	hfl |= _TO_HOST_FASYNC(dfl);
	hfl |= _TO_HOST_DIRECT(dfl);
	hfl |= _TO_HOST_LARGEFILE(dfl);
	hfl |= _TO_HOST_DIRECTORY(dfl);
	hfl |= _TO_HOST_NOFOLLOW(dfl);
	hfl |= _TO_HOST_NOATIME(dfl);
	hfl |= _TO_HOST_CLOEXEC(dfl);
	hfl |= _TO_HOST_NDELAY(dfl);
	dst->flags = hfl;
}

static inline void prlfs_file_info_to_desc(struct prlfs_file_desc *dst,
			struct prlfs_file_info *src)
{
	unsigned int dfl = 0, hfl = src->flags;

	dst->fd = src->fd;
	dst->offset = src->offset;
	/* FIXME: sfid in windows */
	dst->sfid = src->sfid;
	/* Convert OS depended bits.*/
	dfl |= _FROM_HOST_RDONLY(hfl);
	dfl |= _FROM_HOST_WRONLY(hfl);
	dfl |= _FROM_HOST_RDWR(hfl);
	dfl |= _FROM_HOST_CREAT(hfl);
	dfl |= _FROM_HOST_EXCL(hfl);
	dfl |= _FROM_HOST_NOCTTY(hfl);
	dfl |= _FROM_HOST_TRUNC(hfl);
	dfl |= _FROM_HOST_APPEND(hfl);
	dfl |= _FROM_HOST_NONBLOCK(hfl);
	dfl |= _FROM_HOST_SYNC(hfl);
	dfl |= _FROM_HOST_FASYNC(hfl);
	dfl |= _FROM_HOST_DIRECT(hfl);
	dfl |= _FROM_HOST_LARGEFILE(hfl);
	dfl |= _FROM_HOST_DIRECTORY(hfl);
	dfl |= _FROM_HOST_NOFOLLOW(hfl);
	dfl |= _FROM_HOST_NOATIME(hfl);
	dfl |= _FROM_HOST_CLOEXEC(hfl);
	dfl |= _FROM_HOST_NDELAY(hfl);
	dst->flags = dfl;
}

#define LOCALE_NAME_LEN	40
/**
 * http://www.iana.org/assignments/character-sets:
 * "The character set names may be up to 40 characters..."
 */
struct prlfs_sf_parameters {
	unsigned index;
	unsigned id;
	char locale[LOCALE_NAME_LEN];
} PACKED;

#define GET_SF_INFO 0
#define GET_SF_ID_BY_NAME 1

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

struct prlfs_sf_response {
	unsigned char ret;
	char buf[PAGE_SIZE-1];
};

#ifdef _WIN_
#  pragma pack(pop)
#endif

#endif
