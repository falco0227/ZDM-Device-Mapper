/*
 * Kernel Device Mapper for abstracting ZAC/ZBC devices as normal
 * block devices for linux file systems.
 *
 * crc64 implementation from util-linux
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef UTIL_LINUX_CRC64_H
#define UTIL_LINUX_CRC64_H

#include <sys/types.h>
#include <stdint.h>

extern uint64_t crc64(uint64_t seed, const unsigned char *data, size_t len);

#endif
