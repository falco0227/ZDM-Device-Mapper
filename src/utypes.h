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

#ifndef __UTYPES_H__
#define __UTYPES_H__

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t    __u8;
typedef uint8_t      u8;

typedef uint16_t __le16;
typedef uint16_t  __u16;
typedef uint16_t   le16;
typedef uint16_t    u16;

typedef uint32_t __le32;
typedef uint32_t  __u32;
typedef uint32_t   le32;
typedef uint32_t    u32;

typedef uint64_t   le64;
typedef uint64_t    u64;

typedef int16_t     s16;
typedef int32_t     s32;
typedef int64_t     s64;

typedef int bool;

#ifdef __cplusplus
}
#endif

#endif // __UTYPES_H__

/// @}
