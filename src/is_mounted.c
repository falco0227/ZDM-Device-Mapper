/*
 * ismounted.c --- Check to see if the filesystem was mounted
 *
 * Copyright (C) 1995,1996,1997,1998,1999,2000 Theodore Ts'o.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Library
 * General Public License, version 2.
 * %End-Header%
 */

// #define _BSD_SOURCE             /* See feature_test_macros(7) */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fd.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <linux/major.h>
#include <sys/types.h>
#include <mntent.h>
#include <string.h>
#include <sys/stat.h>

#include "is_mounted.h"

/*
 * Check to see if a regular file is mounted.
 * If /etc/mtab/ is a symlink of /proc/mounts, you will need the following check
 * because the name in /proc/mounts is a loopback device not a regular file.
 */
static int check_loop_mounted(const char *mnt_fsname, dev_t mnt_rdev,
				dev_t file_dev, ino_t file_ino)
{
	struct loop_info64 loopinfo;
	int loop_fd, ret;

	if (major(mnt_rdev) == LOOP_MAJOR) {
		loop_fd = open(mnt_fsname, O_RDONLY);
		if (loop_fd < 0)
			return -1;

		ret = ioctl(loop_fd, LOOP_GET_STATUS64, &loopinfo);
		close(loop_fd);
		if (ret < 0)
			return -1;

		if (file_dev == loopinfo.lo_device &&
				file_ino == loopinfo.lo_inode)
			return 1;
	}
	return 0;
}

/*
 * Helper function which checks a file in /etc/mtab format to see if a
 * filesystem is mounted.  Returns an error if the file doesn't exist
 * or can't be opened.
 */
static int check_mntent_file(const char *mtab_file, const char *file,
				   int *mount_flags, char *mtpt, int mtlen)
{
	struct mntent 	*mnt;
	struct stat	st_buf;
	int	retval = 0;
	dev_t		file_dev=0, file_rdev=0;
	ino_t		file_ino=0;
	FILE 		*f;
	int		fd;

	*mount_flags = 0;
	if ((f = setmntent (mtab_file, "r")) == NULL) {
		if (errno == ENOENT) {
			if (getenv("NO_MTAB_OK"))
				return 0;
		}
		return errno;
	}
	if (stat(file, &st_buf) == 0) {
		if (S_ISBLK(st_buf.st_mode)) {
#ifndef __GNU__ /* The GNU hurd is broken with respect to stat devices */
			file_rdev = st_buf.st_rdev;
#endif	/* __GNU__ */
		} else {
			file_dev = st_buf.st_dev;
			file_ino = st_buf.st_ino;
		}
	}
	while ((mnt = getmntent (f)) != NULL) {
		if (mnt->mnt_fsname[0] != '/')
			continue;
		if (strcmp(file, mnt->mnt_fsname) == 0)
			break;
		if (stat(mnt->mnt_fsname, &st_buf) == 0) {
			if (S_ISBLK(st_buf.st_mode)) {
#ifndef __GNU__
				if (file_rdev && (file_rdev == st_buf.st_rdev))
					break;
				if (check_loop_mounted(mnt->mnt_fsname,
						st_buf.st_rdev, file_dev,
						file_ino) == 1)
					break;
#endif	/* __GNU__ */
			} else {
				if (file_dev && ((file_dev == st_buf.st_dev) &&
						 (file_ino == st_buf.st_ino)))
					break;
			}
		}
	}

	if (mnt == 0) {
#ifndef __GNU__ /* The GNU hurd is broken with respect to stat devices */
		/*
		 * Do an extra check to see if this is the root device.  We
		 * can't trust /etc/mtab, and /proc/mounts will only list
		 * /dev/root for the root filesystem.  Argh.  Instead we
		 * check if the given device has the same major/minor number
		 * as the device that the root directory is on.
		 */
		if (file_rdev && stat("/", &st_buf) == 0) {
			if (st_buf.st_dev == file_rdev) {
				*mount_flags = MF_MOUNTED;
				if (mtpt)
					strncpy(mtpt, "/", mtlen);
				goto is_root;
			}
		}
#endif	/* __GNU__ */
		goto errout;
	}
#ifndef __GNU__ /* The GNU hurd is deficient; what else is new? */
	/* Validate the entry in case /etc/mtab is out of date */
	/*
	 * We need to be paranoid, because some broken distributions
	 * (read: Slackware) don't initialize /etc/mtab before checking
	 * all of the non-root filesystems on the disk.
	 */
	if (stat(mnt->mnt_dir, &st_buf) < 0) {
		retval = errno;
		if (retval == ENOENT) {
#ifdef DEBUG
			printf("Bogus entry in %s!  (%s does not exist)\n",
			       mtab_file, mnt->mnt_dir);
#endif /* DEBUG */
			retval = 0;
		}
		goto errout;
	}
	if (file_rdev && (st_buf.st_dev != file_rdev)) {
#ifdef DEBUG
		printf("Bogus entry in %s!  (%s not mounted on %s)\n",
		       mtab_file, file, mnt->mnt_dir);
#endif /* DEBUG */
		goto errout;
	}
#endif /* __GNU__ */
	*mount_flags = MF_MOUNTED;

#ifdef MNTOPT_RO
	/* Check to see if the ro option is set */
	if (hasmntopt(mnt, MNTOPT_RO))
		*mount_flags |= MF_READONLY;
#endif

	if (mtpt)
		strncpy(mtpt, mnt->mnt_dir, mtlen);
	/*
	 * Check to see if we're referring to the root filesystem.
	 * If so, do a manual check to see if we can open /etc/mtab
	 * read/write, since if the root is mounted read/only, the
	 * contents of /etc/mtab may not be accurate.
	 */
	if (!strcmp(mnt->mnt_dir, "/")) {
is_root:
#define TEST_FILE "/.ismount-test-file"
		*mount_flags |= MF_ISROOT;
		fd = open(TEST_FILE, O_RDWR|O_CREAT, 0600);
		if (fd < 0) {
			if (errno == EROFS)
				*mount_flags |= MF_READONLY;
		} else
			close(fd);
		(void) unlink(TEST_FILE);
	}
	retval = 0;
errout:
	endmntent (f);
	return retval;
}

static int check_mntent(const char *file, int *mount_flags,
			      char *mtpt, int mtlen)
{
	int	retval;

#ifdef DEBUG
	retval = check_mntent_file("/tmp/mtab", file, mount_flags,
				   mtpt, mtlen);
	if (retval == 0)
		return 0;
#endif /* DEBUG */
#ifdef __linux__
	retval = check_mntent_file("/proc/mounts", file, mount_flags,
				   mtpt, mtlen);
	if (retval == 0 && (*mount_flags != 0))
		return 0;
#endif /* __linux__ */
#if defined(MOUNTED) || defined(_PATH_MOUNTED)
#ifndef MOUNTED
#define MOUNTED _PATH_MOUNTED
#endif /* MOUNTED */
	retval = check_mntent_file(MOUNTED, file, mount_flags, mtpt, mtlen);
	return retval;
#else
	*mount_flags = 0;
	return 0;
#endif /* defined(MOUNTED) || defined(_PATH_MOUNTED) */
}

/*
 * Check to see if we're dealing with the swap device.
 */
static int is_swap_device(const char *file)
{
	FILE		*f;
	char		buf[1024], *cp;
	dev_t		file_dev;
	struct stat	st_buf;
	int		ret = 0;

	file_dev = 0;
#ifndef __GNU__ /* The GNU hurd is broken with respect to stat devices */
	if ((stat(file, &st_buf) == 0) &&
	    S_ISBLK(st_buf.st_mode))
		file_dev = st_buf.st_rdev;
#endif	/* __GNU__ */

	if (!(f = fopen("/proc/swaps", "r")))
		return 0;
	/* Skip the first line */
	if (!fgets(buf, sizeof(buf), f))
		goto leave;
	if (*buf && strncmp(buf, "Filename\t", 9))
		/* Linux <=2.6.19 contained a bug in the /proc/swaps
		 * code where the header would not be displayed
		 */
		goto valid_first_line;

	while (fgets(buf, sizeof(buf), f)) {
valid_first_line:
		if ((cp = strchr(buf, ' ')) != NULL)
			*cp = 0;
		if ((cp = strchr(buf, '\t')) != NULL)
			*cp = 0;
		if (strcmp(buf, file) == 0) {
			ret++;
			break;
		}
#ifndef __GNU__
		if (file_dev && (stat(buf, &st_buf) == 0) &&
		    S_ISBLK(st_buf.st_mode) &&
		    file_dev == st_buf.st_rdev) {
			ret++;
			break;
		}
#endif 	/* __GNU__ */
	}

leave:
	fclose(f);
	return ret;
}


/*
 * ext2fs_check_mount_point() fills determines if the device is
 * mounted or otherwise busy, and fills in mount_flags with one or
 * more of the following flags: MF_MOUNTED, MF_ISROOT,
 * MF_READONLY, MF_SWAP, and MF_BUSY.  If mtpt is
 * non-NULL, the directory where the device is mounted is copied to
 * where mtpt is pointing, up to mtlen characters.
 */
int is_mounted(const char *device, int *mount_flags, char *mtpt, int mtlen)
{
	int	retval = 0;

	if (is_swap_device(device)) {
		*mount_flags = MF_MOUNTED | MF_SWAP;
		strncpy(mtpt, "<swap>", mtlen);
	} else {
		retval = check_mntent(device, mount_flags, mtpt, mtlen);
		*mount_flags = 0;
	}
	if (retval)
		return retval;

#ifdef __linux__ /* This only works on Linux 2.6+ systems */
	{
		struct stat st_buf;

		if (stat(device, &st_buf) == 0 && S_ISBLK(st_buf.st_mode)) {
			int fd = open(device, O_RDONLY | O_EXCL);

			if (fd >= 0)
				close(fd);
			else if (errno == EBUSY)
				*mount_flags |= MF_BUSY;
		}
	}
#endif

	return 0;
}

int exists(const char *dname)
{
	struct stat sb;
	int found = 1;
	if (stat(dname, &sb) < 0) {
		found = 0;
	}
	return found;
}

int exists(const char *dname);
int is_anypart_mounted(const char *device, int *mount_flags, char *mtpt, int mtlen);

int is_anypart_mounted(const char *device, int *sum_flags, char *mtpt, int mtlen)
{
	char dbuffer[256];
	char mbuf[80];
	int partno;
	int flags;
	int err = 0;

	*sum_flags = 0;

	if (exists(device)) {
		err = is_mounted(device, &flags, mbuf, sizeof(mbuf));
		if (err) {
			printf("Unable to determine if %s is mounted\n", device );
			goto out;
		}
		if (flags) {
			if (mtpt) {
//				printf("%s is mounted at %s [flags %x]\n",
//					device, mbuf, flags );
				snprintf(mtpt, mtlen, "%s", device);
			}
			*sum_flags |= flags;
		}
	}

	for (partno = 0; partno < 256; partno++) {
		snprintf(dbuffer, sizeof(dbuffer), "%s%d", device, partno);
		if (!exists(dbuffer)) {
			goto out;
		}
		err = is_mounted(device, &flags, mbuf, sizeof(mbuf));
		if (flags) {
			if (mtpt) {
//				printf("%s is mounted at %s [flags %x]\n",
//					dbuffer, mbuf, flags );
				snprintf(mtpt, mtlen, "%s", dbuffer);
			}
			*sum_flags |= flags;
		}
	}

out:
	return err;
}

