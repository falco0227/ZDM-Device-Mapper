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
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>


#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <linux/fs.h>
#include <errno.h>
#include <string.h> // strdup


#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>

#include <locale.h>


#include "utypes.h"
#include "libzdm.h"
#include "libzoned.h"

typedef struct zdm_ioc_status zdm_ioc_status_t;
typedef struct zdm_ioc_request zdm_ioc_request_t;

typedef union zdm_ioc {
	zdm_ioc_request_t request;
	zdm_ioc_status_t  status;
} zdm_ioc_t;


int do_show_megaz(int fd, int megaz, int sram)
{
	int rcode = 0;
	zdm_ioc_t * req_status = malloc(sizeof(zdm_ioc_t));

	req_status->request.result_size = sizeof(*req_status);
	req_status->request.megazone_nr = megaz;

	rcode = ioctl(fd, ZDM_IOC_STATUS, req_status);
	if (rcode < 0) {
		printf("ERROR: %d\n", rcode);
		goto out;
	}
	if (rcode == 0) {
		zdm_ioc_status_t * status = &req_status->status;

		if (sram) {
			int ii;

			printf(" using %'" PRIu64
				" bytes of RAM\n", status->inpool );
			printf("   %'" PRIu64
				" 4k blocks\n", (status->inpool + 4095)/4096 );

			for (ii = 0; ii < 40; ii++) {
				if (status->bins[ii]) {
					printf("  ..  %'d [in %d]\n",
						status->bins[ii], ii );
				}
			}

		}

		printf(" MZ# %d: (in 4k blocks)\n", megaz );
		printf("   b_used       %'" PRIu64 "\n", status->b_used );
		printf("   b_available  %'" PRIu64 "\n", status->b_available );
		printf("   b_discard    %'" PRIu64 "\n", status->b_discard );
		printf("   m_used       %'" PRIu64 "\n", status->m_used );
		printf("   mc_entries   %'" PRIu64 "\n", status->mc_entries );
		printf("   mlut_blocks  %'" PRIu64 "\n", status->mlut_blocks );
		printf("   crc_blocks   %'" PRIu64 "\n", status->crc_blocks );

	}
out:
	return rcode;
}

int do_query_wps(int fd, int megaz)
{
	int rcode = ioctl(fd, ZDM_IOC_MZCOUNT, 0);
	if (rcode < 0) {
		printf("ERROR: %d\n", rcode);
	} else {
		u32 count = rcode;

		printf("Got %u megazones ..", rcode);

		if (-1 == megaz) {
			u32 entry;
			for (entry = 0; entry < count; entry++) {
				rcode = do_show_megaz(fd, entry, entry==0);
			}
		} else if (megaz < rcode) {
			rcode = do_show_megaz(fd, megaz, 1);
		}
	}
	return rcode;
}

int main(int argc, char *argv[])
{
	int opt;
	int index;
	int loglevel;
	int megaz  = -1;
	int exCode = 0;

	setlocale(LC_NUMERIC, "");

	/* Parse command line */
	errno = EINVAL; // Assume invalid Argument if we die
	while ((opt = getopt(argc, argv, "m:l:")) != -1) {
		switch (opt) {
		case 'm':
			megaz = atoi(optarg);
			break;
		case 'l':
			loglevel = atoi(optarg);
			break;
		default:
			printf("USAGE:\n"
			       "    verify -l loglevel files...\n"
			       "Defaults are: -l 0\n");
			break;
		} /* switch */
	} /* while */

	for (index = optind; index < argc; index++) {
		int fd;

		printf("Do something with %s\n", argv[index] );
		fd = open(argv[index], O_RDWR);
		if (fd) {
			do_query_wps(fd, megaz);
		} else {
			perror("Failed to open file");
			fprintf(stderr, "file: %s", argv[index]);
		}
	}

	(void) loglevel;

	return exCode;
}


