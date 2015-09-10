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
#include <linux/blk-zoned-ctrl.h>

/* Used for Zone based SMR devices */
#define SCSI_IOCTL_INQUIRY		0x10000
#define SCSI_IOCTL_CLOSE_ZONE		0x10001
#define SCSI_IOCTL_FINISH_ZONE		0x10002
#define SCSI_IOCTL_OPEN_ZONE		0x10003
#define SCSI_IOCTL_RESET_WP		0x10004
#define SCSI_IOCTL_REPORT_ZONES		0x10005

const char * same_text[] = {
	"all zones are different",
	"all zones are same size",
	"last zone differs by size",
	"all zones same size - different types",
};

const char * type_text[] = {
	"RESERVED",
	"CONVENTIONAL",
	"SEQ_WRITE_REQUIRED",
	"SEQ_WRITE_PREFERRED",
};

unsigned char r_opts[] = {
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

static char * r_opt_text[] = {
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

#define ARRAY_COUNT(x) (sizeof((x))/sizeof((*x)))

int fix_endian = 0;

static uint64_t endian64(uint64_t in)
{
	return fix_endian ? be64toh(in) : in;
}

static uint32_t endian32(uint32_t in)
{
	return fix_endian ? be32toh(in) : in;
}

// static u16 endian16(u16 in)
// {
// 	return fix_endian ? be16toh(in) : in;
// }

static void test_endian(struct bdev_zone_report * info)
{
	struct bdev_zone_descriptor * entry = &info->descriptors[0];
	uint64_t be_len;
	be_len = be64toh(entry->length);
	if ( be_len == 0x080000 ||
             be_len == 0x100000 ||
             be_len == 0x200000 ||
             be_len == 0x300000 ||
             be_len == 0x400000 ||
             be_len == 0x800000 ) {
		fprintf(stdout, "*** RESULTS are BIG ENDIAN ****\n");
		fix_endian = 1;
	} else {
		fprintf(stdout, "*** RESULTS are LITTLE ENDIAN ****\n");
	}
}

// enum bdev_zone_condition short hand:
const char * condition_str[] = {
	"cv", /* conventional zone */
	"e0", /* empty */
	"Oi", /* open implicit */
	"Oe", /* open explicit */
	"Cl", /* closed */
	"x5", "x6", "x7", "x8", "x9", "xA", "xB", /* xN: reserved */
	"ro", /* read only */
	"fu", /* full */
	"OL"  /* offline */
	};

static const char * zone_condition_str(uint8_t cond)
{
	return condition_str[cond & 0x0f];
}

void print_zones(struct bdev_zone_report * info, uint32_t size)
{
	uint32_t count = endian32(info->descriptor_count);
	uint32_t max_count;
	int iter;
	int same_code = info->same_field & 0x0f;

	fprintf(stdout, "  count: %u, same %u (%s), max_lba %lu\n",
		count,
		same_code, same_text[same_code],
		endian64(info->maximum_lba & (~0ul >> 16)) );

	max_count = (size - sizeof(struct bdev_zone_report))
                        / sizeof(struct bdev_zone_descriptor);
	if (count > max_count) {
		fprintf(stdout, "Truncating report to %d of %d zones.\n",
			max_count, count );
		count = max_count;
	}

	for (iter = 0; iter < count; iter++ ) {
		struct bdev_zone_descriptor * entry = &info->descriptors[iter];
		unsigned int type  = entry->type & 0xF;
		unsigned int flags = entry->flags;
		uint64_t start = endian64(entry->lba_start);
		uint64_t wp = endian64(entry->lba_wptr);
		uint8_t cond = (flags & 0xF0) >> 4;
		uint64_t len = endian64(entry->length);

		if (!len) {
			break;
		}
		fprintf(stdout,
			"  start: %9lx, len %7lx, wptr %8lx"
                        " reset:%u non-seq:%u, zcond:%2u(%s) [type: %u(%s)]\n",
		start, len, wp - start, flags & 0x01, (flags & 0x02) >> 1,
		cond, zone_condition_str(cond), type, type_text[type]);
	}
}

int do_report_zones_ioctl(const char * pathname, uint64_t lba, uint8_t ropt, int do_ata)
{
	int rc = -4;
        int fd = open(pathname, O_RDWR);
        if (fd != -1) {
		struct bdev_zone_report_io * zone_info;
                uint64_t size;

		/* NOTE: 128 seems to be about the RELIABLE limit ...     */
                /*       150 worked 180 was iffy (some or all ROs failed) */
                /*       256 all ROs failed..                             */
                size = 128 * 4096;
                zone_info = malloc(size);
                if (zone_info) {
			uint32_t cmd = SCSI_IOCTL_REPORT_ZONES;
			int opt = 0;
			int optidx;

			for (optidx = 0; optidx < ARRAY_COUNT(r_opts); optidx++) {
				if (ropt == r_opts[optidx]) {
					opt = optidx;
					break;
				}
			}

			memset(zone_info, 0, size);
			zone_info->data.in.report_option     = r_opts[opt];
			zone_info->data.in.return_page_count = size;
			zone_info->data.in.zone_locator_lba  = lba;

			if (do_ata) {
				zone_info->data.in.report_option |= 0x80;
			}

			rc = ioctl(fd, cmd, zone_info);
			if (rc != -1) {
				test_endian(&zone_info->data.out);

				fprintf(stdout, "%s(%d): found %d zones\n",
					r_opt_text[opt],
					r_opts[opt],
					endian32(zone_info->data.out.descriptor_count) );
				print_zones(&zone_info->data.out, size);
			} else {
				fprintf(stderr, "ERR: %d -> %s\n\n", errno, strerror(errno));
			}
		}
                close(fd);
        } else {
                fprintf(stderr, "%s\n\n", strerror(errno));
        }

	return rc;
}

static void usage(void)
{
	printf("Usage:\n");
	printf("  sd_report_zones [-r opt] [ata] [<lba>] <device>\n");
	printf("\nwhere:\n"
	       "    opt is the numeric value from \"enum zone_report_option\".\n"
	       "             0 - non seq. and reset (default)\n"
	       "             1 - empty\n"
	       "             2 - open implicit\n"
	       "             3 - open explicit\n"
	       "             4 - closed\n"
	       "             5 - full\n"
	       "             6 - read only\n"
	       "             7 - offline\n"
	       "          0x10 - reset\n"
	       "          0x11 - non sequential\n"
	       "          0x3f - non write pointer zones\n"
	       "    ata will cause ATA ZAC commands to be used.\n"
               "        default is to use SCSI ZBC commands\n"
	       "\nExamples:\n");
	printf("  sd_report_zones -r 0x11 ata 0x80000 /dev/sdn\n");
	printf("     report zone information using ata commands (ata passthrough)\n"
               "            show zones starting from lba 80000 hex\n"
	       "            that are flagged as non-sequential\n");
	printf("  sd_report_zones 0 /dev/sdn\n");
	printf("     report zone information starting with lba 0, using scsi commands\n");
	printf("\nNOTE: maximum report size is 8091 zones.\n\n");
}

/*
 *
 */
int main(int argc, char *argv[])
{
        uint64_t lba = 0;
        char * fname = NULL;
	int rc;
	int ii;
	int do_ata = 0;
	int opt;
	uint8_t ropt = ZOPT_NON_SEQ_AND_RESET; /* the default report */

	while ((opt = getopt(argc, argv, "r:")) != -1) {
		switch (opt) {
		case 'r':
			ropt = strtol(optarg, NULL, 0);
			break;
		default:
			usage();
			return 1;
			break;
		} /* switch */
	} /* while */

	for (ii = optind; ii < argc; ii++) {
		if (0 == strcmp(argv[ii], "ata") ) {
			do_ata = 1;
		} else {
			char * endptr ;
			uint64_t tmp = strtoull(argv[ii], &endptr, 0);
			if (0 == *endptr) {
				lba = tmp;
			} else if (!fname) {
				fname = argv[ii];
			}
		}
	}
	if (argc == 1 || !fname) {
		usage();
		return 1;
	}

	rc = do_report_zones_ioctl(fname, lba, ropt, do_ata);
	return rc;
}
