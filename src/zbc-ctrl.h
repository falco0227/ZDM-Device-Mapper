/*
 * Kernel Device Mapper for abstracting ZAC/ZBC devices as normal
 * block devices for linux file systems.
 *
 * Copyright (C) 2015 Seagate Technology PLC
 *
 * Written by:
 * Shaun Tancheff <shaun.tancheff@seagate.com>
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef _ZBC_CTRL_H_
#define _ZBC_CTRL_H_

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define DEBUG 1

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/**
 * Flags to determine if the connected disk is ZONED:
 *   - Host Aware of Host Managed (or not)
 */
typedef enum zc_type {
	NOT_ZONED    = 0x00,
	HOST_AWARE   = 0x01,
	HOST_MANAGE  = 0x02,
} zc_type_t;

typedef enum zc_vendor_type {
	ZONE_DEV_ATA_SEAGATE = 0x00,
	ZONE_DEV_BLK         = 0x01,
} zc_vendor_type_t;

struct zoned_inquiry {
	u8  evpd;
	u8  pg_op;
	u16 mx_resp_len;
	u8  result[0];
} __packed;
typedef struct zoned_inquiry zoned_inquiry_t;


enum zone_report_option {
	ZOPT_NON_SEQ_AND_RESET   = 0x00,
	ZOPT_ZC1_EMPTY,
	ZOPT_ZC2_OPEN_IMPLICIT,
	ZOPT_ZC3_OPEN_EXPLICIT,
	ZOPT_ZC4_CLOSED,
	ZOPT_ZC5_FULL,
	ZOPT_ZC6_READ_ONLY,
	ZOPT_ZC7_OFFLINE,
	ZOPT_RESET               = 0x10,
	ZOPT_NON_SEQ             = 0x11,
	ZOPT_NON_WP_ZONES        = 0x3f,
};

enum zone_zm_action {
 // Report, close, finish, open, reset wp:
	REPORT_ZONES_EXT   = 0x00,
	CLOSE_ZONE_EXT,
	FINISH_ZONE_EXT,
	OPEN_ZONE_EXT,
	RESET_WP_EXT,
};

struct bdev_zone_report_request_t {
	u64 zone_locator_lba;	  /* starting lba for first zone to be reported. */
	u32 return_page_count;  /* number of bytes allocated for result */
	u8  report_option;	  /* see: zone_report_option enum */
};

enum bdev_zone_type {
	ZTYP_RESERVED            = 0,
	ZTYP_CONVENTIONAL        = 1,
	ZTYP_SEQ_WRITE_REQUIRED  = 2,
	ZTYP_SEQ_WRITE_PREFERRED = 3,
};

enum bdev_zone_condition {
	ZCOND_CONVENTIONAL       = 0, /* no write pointer */
	ZCOND_ZC1_EMPTY          = 1,
	ZCOND_ZC2_OPEN_IMPLICIT  = 2,
	ZCOND_ZC3_OPEN_EXPLICIT  = 3,
	ZCOND_ZC4_CLOSED         = 4,
	/* 5 - 0xC - reserved */
	ZCOND_ZC6_READ_ONLY      = 0xd,
	ZCOND_ZC5_FULL           = 0xe,
	ZCOND_ZC7_OFFLINE        = 0xf,
};

/* NOTE: all LBA's are u64 only use the lower 48 bits */

struct bdev_zone_descriptor_entry_t {
	u8  type;         /* see zone_type enum */
	u8  flags;        /* 0:reset, 1:non-seq, 2-3: resv,
                           * bits 4-7: see zone_condition enum */
	u8  reserved1[6];
	u64 length;       /* length of zone: in sectors */
	u64 lba_start;    /* lba of zone start */
	u64 lba_wptr;     /* lba of write pointer - ready to be written next */
        u8 reserved[32];
} __packed;

enum bdev_zone_same {
	ZS_ALL_DIFFERENT        = 0,
	ZS_ALL_SAME             = 1,
	ZS_LAST_DIFFERS         = 2,
	ZS_SAME_LEN_DIFF_TYPES  = 3,
};

struct bdev_zone_report_result_t {
	u32 descriptor_count;   /* number of zone_descriptor entries that follow */
	u8  same_field;         /* bits 0-3: enum zone_same (MASK: 0x0F) */
	u8  reserved1[3];
	u64 maximum_lba;        /* The MAXIMUM LBA field indicates the LBA of the
	                         * last logical sector on the device, including
	                         * all logical sectors in all zones. */
	u8  reserved2[48];
	struct bdev_zone_descriptor_entry_t descriptors[0];
} __packed;

struct bdev_zone_report_ioctl_t {
	union {
		struct bdev_zone_report_request_t in;
		struct bdev_zone_report_result_t out;
	} data;
} __packed;

/* Used for Zone based SMR devices */
#define SCSI_IOCTL_INQUIRY		0x10000
#define SCSI_IOCTL_CLOSE_ZONE		0x10001
#define SCSI_IOCTL_FINISH_ZONE		0x10002
#define SCSI_IOCTL_OPEN_ZONE		0x10003
#define SCSI_IOCTL_RESET_WP		0x10004
#define SCSI_IOCTL_REPORT_ZONES		0x10005

int zdm_is_ha_device(zoned_inquiry_t * inquire, int verbose);
int zdm_is_big_endian_report(struct bdev_zone_report_result_t * info);

zoned_inquiry_t * zdm_device_inquiry(int fd, int do_ata);
int zdm_zone_reset_wp(int fd, uint64_t lba, int do_ata);
int zdm_report_zones(int fd, struct bdev_zone_report_ioctl_t * zone_info,
		     uint64_t size, uint8_t option, uint64_t lba, int do_ata);

int zdm_zone_open(int fd, uint64_t lba, int do_ata);
int zdm_zone_close(int fd, uint64_t lba, int do_ata);
int zdm_zone_finish(int fd, uint64_t lba, int do_ata);


#endif /* _ZBC_CTRL_H_ */
