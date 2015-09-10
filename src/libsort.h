/*
 * Kernel Device Mapper for abstracting ZAC/ZBC devices as normal
 * block devices for linux file systems.
 *
 * Linux kernel heap sort
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef _LINUX_SORT_H
#define _LINUX_SORT_H


#include "utypes.h"

void sort(void *base, size_t num, size_t size,
	  int (*cmp)(const void *, const void *),
	  void (*swap)(void *, void *, int));

#endif
