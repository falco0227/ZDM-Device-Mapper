#ifndef __IS_MOUNTED_H_
#define __IS_MOUNTED_H_

#define MF_MOUNTED   (1 << 1)
#define MF_ISROOT    (1 << 2)
#define MF_READONLY  (1 << 3)
#define MF_SWAP      (1 << 4)
#define MF_BUSY      (1 << 5)

int is_mounted(const char *device, int *mount_flags, char *mtpt, int mtlen);
int is_anypart_mounted(const char *device, int *mount_flags, char *mtpt, int mtlen);
int exists(const char *dname);

/**
 * Ex:
 *
 *  int	 flags = 0;
 *  char mpoint_buf[80];
 *
 *  int err = is_mounted("/dev/sda1", &flags, mpoint_buf, sizeof(mpoint_buf));
 *  if (err) {
 *     goto exit;
 *  }
 *  if (flags) {
 *     how_in_use_by(flags, mpoint_buf);
 *  }
 */

#endif /* __IS_MOUNTED_H_ */
