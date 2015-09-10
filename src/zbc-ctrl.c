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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "zbc-ctrl.h"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif /* offsetof */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof((x))/sizeof((*x)))
#endif

static const char * type_text[] = {
	"RESERVED",
	"CONVENTIONAL",
	"SEQ_WRITE_REQUIRED",
	"SEQ_WRITE_PREFERRED",
};


static const char * r_opt_text[] = {
        "NON_SEQ_AND_RESET",
        "ZC1_EMPTY",
	"ZC2_OPEN_IMPLICIT",
	"ZC3_OPEN_EXPLICIT",
	"ZC4_CLOSED",
	"ZC5_FULL",
	"ZC6_READ_ONLY",
	"ZC7_OFFLINE",
	"RESET",
	"NON_SEQ",
        "NON_WP_ZONES",
};

static const char * same_text[] = {
	"all zones are different",
	"all zones are same size",
	"last zone differs by size",
	"all zones same size - different types",
};


static unsigned char r_opts[] = {
	ZOPT_NON_SEQ_AND_RESET,
	ZOPT_ZC1_EMPTY,
	ZOPT_ZC2_OPEN_IMPLICIT,
	ZOPT_ZC3_OPEN_EXPLICIT,
	ZOPT_ZC4_CLOSED,
	ZOPT_ZC5_FULL,
	ZOPT_ZC6_READ_ONLY,
	ZOPT_ZC7_OFFLINE,
	ZOPT_RESET,
	ZOPT_NON_SEQ,
	ZOPT_NON_WP_ZONES,
};


#define Z_VPD_INFO_BYTE 8
#define DATA_OFFSET (offsetof(zoned_inquiry_t, result))

int zdm_is_ha_device(zoned_inquiry_t * inquire, int verbose)
{
	int is_smr = 0;
	int is_ha  = 0;

	if (inquire->mx_resp_len > Z_VPD_INFO_BYTE) {
		u8 flags = inquire->result[Z_VPD_INFO_BYTE] >> 4 & 0x03;

		switch (flags) {
			case 1:
				is_ha = 1;
				is_smr = 1;
				break;
			case 2:
				is_smr = 1;
				break;
			default:
				break;
		}
	}
	if (verbose) {
		printf("HostAware:%d, SMR:%d\n", is_ha, is_smr );
	}
	return is_ha;
}


zoned_inquiry_t * zdm_device_inquiry(int fd, int do_ata)
{
	int sz = 64;
	int bytes = sz + DATA_OFFSET;
	zoned_inquiry_t * inquire;

	inquire = malloc(bytes);
	if (inquire) {
		int rc;

		inquire->evpd        = 1;
		inquire->pg_op       = 0xb1;
		inquire->mx_resp_len = sz;

		if (do_ata) {
			inquire->evpd |= 0x80; // force ATA passthrough
		}

		rc = ioctl(fd, SCSI_IOCTL_INQUIRY, inquire);
		if (rc == -1) {
			free(inquire);
			inquire = NULL;
		}
	} else {
		fprintf(stderr, "ERR: malloc %d bytes failed.\n\n", bytes );
	}

	return inquire;
}

int zdm_zone_command(int fd, int command, uint64_t lba, int do_ata)
{
	uint64_t iolba = lba;
	int rc;

	if (do_ata) {
		iolba |= 1;
	} else {
		iolba &= ~1ul;
	}

	rc = ioctl(fd, command, iolba);
	if (rc == -1) {
		fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
	}

	return rc;
}

int zdm_zone_close(int fd, uint64_t lba, int do_ata)
{
	return zdm_zone_command(fd, SCSI_IOCTL_CLOSE_ZONE, lba, do_ata);
}

int zdm_zone_finish(int fd, uint64_t lba, int do_ata)
{
	return zdm_zone_command(fd, SCSI_IOCTL_FINISH_ZONE, lba, do_ata);
}

int zdm_zone_open(int fd, uint64_t lba, int do_ata)
{
	return zdm_zone_command(fd, SCSI_IOCTL_OPEN_ZONE, lba, do_ata);
}

int zdm_zone_reset_wp(int fd, uint64_t lba, int do_ata)
{
	return zdm_zone_command(fd, SCSI_IOCTL_RESET_WP, lba, do_ata);
}


static int fix_endian = 0;

static u64 endian64(u64 in)
{
	return fix_endian ? be64toh(in) : in;
}

static u32 endian32(u32 in)
{
	return fix_endian ? be32toh(in) : in;
}

static void test_endian(struct bdev_zone_report_result_t * info)
{
	fix_endian = zdm_is_big_endian_report(info);
}

void print_zones(struct bdev_zone_report_result_t * info, uint32_t size)
{
	u32 count = endian32(info->descriptor_count);
	u32 max_count;
	int iter;
	int same_code = info->same_field & 0x0f;

	fprintf(stdout, "  count: %u, same %u (%s), max_lba %lu\n",
		count,
		same_code, same_text[same_code],
		endian64(info->maximum_lba & (~0ul >> 16)) );

	max_count = (size - sizeof(struct bdev_zone_report_result_t))
                        / sizeof(struct bdev_zone_descriptor_entry_t);
	if (count > max_count) {
		fprintf(stderr, "Truncating report to %d of %d zones.\n",
			max_count, count );
		count = max_count;
	}

	for (iter = 0; iter < count; iter++ ) {
		struct bdev_zone_descriptor_entry_t * entry =
			&info->descriptors[iter];
		unsigned int type  = entry->type & 0xF;
		unsigned int flags = entry->flags;
		u64 start = endian64(entry->lba_start);
		u64 wp = endian64(entry->lba_wptr);

		fprintf(stdout,
			"  start: %lx, len %lx, wptr %lx\n"
			"   type: %u(%s) reset:%u non-seq:%u, zcond:%u\n",
		start, endian64(entry->length), wp - start,
		type, type_text[type],
		flags & 0x01, (flags & 0x02) >> 1, (flags & 0xF0) >> 4);
	}
}

int zdm_is_big_endian_report(struct bdev_zone_report_result_t * info)
{
	int is_big = 0;
	struct bdev_zone_descriptor_entry_t * entry = &info->descriptors[0];
	u64 be_len;
	be_len = be64toh(entry->length);
	if ( be_len == 0x080000 ||
             be_len == 0x100000 ||
             be_len == 0x200000 ||
             be_len == 0x300000 ||
             be_len == 0x400000 ||
             be_len == 0x800000 ) {
		is_big = 1;
	}
	return is_big;
}

int zdm_report_zones(int fd, struct bdev_zone_report_ioctl_t * zone_info,
		     uint64_t size, uint8_t option, uint64_t lba, int do_ata)
{
	int rc;
	uint32_t cmd = SCSI_IOCTL_REPORT_ZONES;

	zone_info->data.in.report_option     = option;
	zone_info->data.in.return_page_count = size;
	zone_info->data.in.zone_locator_lba  = lba;

	if (do_ata) {
		zone_info->data.in.report_option |= 0x80;
	}

	rc = ioctl(fd, cmd, zone_info);
	if (rc == -1) {
		fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
	}

	return rc;
}

int do_report_zones_ioctl(const char * pathname, uint64_t lba, int do_ata)
{
	int rc = -4;
        int fd = open(pathname, O_RDWR);
        if (fd != -1) {
		struct bdev_zone_report_ioctl_t * zone_info;
                uint64_t size;

		/* NOTE: 128 seems to be about the RELIABLE limit ...     */
                /*       150 worked 180 was iffy (some or all ROs failed) */
                /*       256 all ROs failed..                             */
                size = 128 * 4096;
                zone_info = malloc(size);
                if (zone_info) {
			int opt = 0;
			for (opt = 0; opt < ARRAY_SIZE(r_opts); opt++) {
				memset(zone_info, 0, size);
				rc = zdm_report_zones(fd, zone_info, size, r_opts[opt], lba, do_ata);
				if (rc != -1) {
					test_endian(&zone_info->data.out);

					fprintf(stdout, "%s(%d): found %d zones\n",
						r_opt_text[opt],
						r_opts[opt],
						endian32(zone_info->data.out.descriptor_count) );
					print_zones(&zone_info->data.out, size);
				} else {
					fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
					break;
				}
			}
		}
                close(fd);
        } else {
                fprintf(stderr, "%s\n\n", strerror(errno));
        }

	return rc;
}

