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



#include "utypes.h"

struct zdm_ioc_request {
	u32 result_size;
	u32 megazone_nr;
};

// request an info dump from ZDM:
#define ZDM_IOC_MZCOUNT 0x5a4e0001
#define ZDM_IOC_WPS     0x5a4e0002
#define ZDM_IOC_FREE    0x5a4e0003
#define ZDM_IOC_STATUS  0x5a4e0004

int do_show_megaz(int fd, int megaz)
{
	int ncolumns = 5;
	int cc;
	int rcode = 0;
	struct zdm_ioc_request * req_wps;
	struct zdm_ioc_request * req_free;

	req_wps  = malloc(4096);
	req_free = malloc(4096);
	if (req_wps && req_free) {

		req_wps->result_size = 4096;
		req_wps->megazone_nr = megaz;

		rcode = ioctl(fd, ZDM_IOC_WPS, req_wps);
		if (rcode < 0) {
			printf("ERROR: %d\n", rcode);
			goto out;
		}
		req_free->result_size = 4096;
		req_free->megazone_nr = megaz;

		rcode = ioctl(fd, ZDM_IOC_FREE, req_free);
		if (rcode < 0) {
			printf("ERROR: %d\n", rcode);
			return rcode;
		}

		if (rcode == 0) {
			int nn;
			u32 * wps = (u32 *)req_wps;
			u32 * fct = (u32 *)req_free;

			for (cc = 0; cc < ncolumns; cc++) {
				printf("entry fl.  wps .free -");
			}
			printf("\n");

			for (nn = 0; nn < 1024;) {
				for (cc = 0; cc < ncolumns; cc++) {
					u32 flags = wps[nn] >> 24;
					if (wps[nn] == 0xFFFFFFFF) {
						break; // end of data
					}
					printf("%4d: %2x %6x %5u ",
						nn,
						flags,
						wps[nn] & 0xFFFFFF,
						fct[nn] );
					nn++;
				}
				printf("\n");

				if (wps[nn] == 0xFFFFFFFF) {
					break; // end of data
				}
			}
		}
	}
out:
	if (req_wps) {
		free(req_wps);
	}
	if (req_free) {
		free(req_free);
	}
	return rcode;
}

int do_query_wps(int fd, int megaz)
{
	int rcode = ioctl(fd, ZDM_IOC_MZCOUNT, 0);
	if (rcode < 0) {
		printf("ERROR: %d\n", rcode);
	} else {
		u32 count = rcode;

		printf("Got %u megazones\n", rcode);

		if (-1 == megaz) {
			u32 entry;
			for (entry = 0; entry < count; entry++) {
				rcode = do_show_megaz(fd, entry);
			}
		} else if (megaz < rcode) {
			rcode = do_show_megaz(fd, megaz);
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


