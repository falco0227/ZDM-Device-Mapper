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

#ifndef _LIBZDM_COMPAT_H_
#define _LIBZDM_COMPAT_H_

#define EXTRA_DEBUG              0

#define MZ_MEMPOOL_SZ           64
#define JOURNAL_MEMCACHE_BLOCKS  4
#define MEM_PURGE_MSECS       1500

/* Always run the GC when this many blocks can be freed */
#define GC_COMPACT_NORMAL     1024
/* When less than 20 zones are free use aggressive gc in the megazone */
#define GC_COMPACT_AGGRESSIVE   32

// For performance tuning:
//   Q? smaller strips give smoother performance
//      a single drive I/O is 8 (or 32?) blocks?
//   A? Does not seem to ...
#define GC_MAX_STRIPE          256
#define REPORT_BUFFER           65 /* pages for (at least) 4096 zone info */
#define SYNC_CACHE_ORDER         4
#define SYNC_CACHE_PAGES        (1 << SYNC_CACHE_ORDER)
#define SYNC_IO_ORDER            2
#define SYNC_IO_SZ             ((1 << SYNC_IO_ORDER) * PAGE_SIZE)

#define MZTEV_UNUSED    0xFFFFFFFFu
#define MZTEV_NF        0x80000000u
#define MZTEV_MAX       0x03ffFFFFu

#define REF( v )   atomic_inc( &(v) )
#define DEREF( v ) atomic_dec( &(v) )

#define Z_TABLE_MAGIC  0x123456787654321Eul
#define Z_KEY_SIG      0xFEDCBA987654321Ful

#define Z_CRC_4K	    4096
#define Z_BLKSZ          0x10000
#define MAX_ZONES_PER_MZ    1024
#define Z_SMR_SZ_BYTES   (Z_BLKSZ*Z_C4K)

#define GC_READ          (1ul << 15)

/*
 *  generic-ish n-way alloc/free
 *  Use kmalloc for small (< 4k) allocations.
 *  Use vmalloc for multi-page alloctions
 *  Except:
 *  Use multipage allocations for dm_io'd pages that a frequently hit.
 *
 *  NOTE: ALL allocations are zero'd before returning.
 *        alloc/free count is tracked for dynamic analysis.
 */

#define GET_PG_SYNC   0x010000
#define GET_PG_CACHE  0x020000
#define GET_ZPG       0x040000
#define GET_KM        0x080000
#define GET_VM        0x100000

#define MP_SIO   (GET_PG_SYNC | 23 )
#define MP_CACHE (GET_PG_CACHE | 24 )

#define PG_01    (GET_ZPG |  1 )
#define PG_02    (GET_ZPG |  2 )
#define PG_05    (GET_ZPG |  5 )
#define PG_06    (GET_ZPG |  6 )
#define PG_08    (GET_ZPG |  8 )
#define PG_09    (GET_ZPG |  9 )
#define PG_10    (GET_ZPG | 10 )
#define PG_11    (GET_ZPG | 11 )
#define PG_13    (GET_ZPG | 13 )
#define PG_17    (GET_ZPG | 17 )
#define PG_27    (GET_ZPG | 27 )

#define KM_00    (GET_KM  |  0 )
#define KM_07    (GET_KM  |  7 )
#define KM_12    (GET_KM  | 12 )
#define KM_14    (GET_KM  | 14 )
#define KM_15    (GET_KM  | 15 )
#define KM_16    (GET_KM  | 16 )
#define KM_18    (GET_KM  | 18 )
#define KM_20    (GET_KM  | 20 )
#define KM_25    (GET_KM  | 25 )
#define KM_26    (GET_KM  | 26 )
#define KM_28    (GET_KM  | 28 )
#define KM_29    (GET_KM  | 29 )
#define KM_30    (GET_KM  | 30 )

#define VM_03    (GET_VM  |  3 )
#define VM_04    (GET_VM  |  4 )
#define VM_21    (GET_VM  | 21 )
#define VM_22    (GET_VM  | 22 )

#define ZDM_FREE(z, _p, sz, id)    _zdm_free( (z), (_p), (sz), (id) ), (_p) = 0
#define ZDM_ALLOC(z, sz, id)       _zdm_alloc((z), (sz), (id) )
#define ZDM_CALLOC(z, n, sz, id)   _zdm_calloc((z), (n), (sz), (id) )

void _zdm_free(struct zoned * znd, void *p, size_t sz, u32 code);
void * _zdm_alloc(struct zoned * znd, size_t sz, int code);
void * _zdm_calloc(struct zoned * znd, size_t n, size_t sz, int code);

#define sb_check(a) \
	zdm_superblock_check( (a) )
#define map_addr_calc(a, b) \
	zdm_map_addr(a, b)
#define do_sync_tables(a, b) \
	zdm_sync_tables(a, b)
#define sync_crc_pages(megaz) \
	zdm_sync_crc_pages(megaz)
#define unused_phy(a, b) \
	zdm_unused_phy(a, b)
#define unused_addr(megaz, dm_s) \
	zdm_unused_addr(megaz, dm_s)
#define z_lookup(megaz, maddr) \
	zdm_lookup(megaz, maddr)
#define z_mapped_addmany(megaz, dm_s, lba, count) \
	zdm_mapped_addmany(megaz, dm_s, lba, count)
#define z_mapped_discard(megaz, dm_s, lba) \
	zdm_mapped_discard(megaz, dm_s, lba)
#define z_mapped_to_list(megaz, dm_s, lba, purge) \
	zdm_mapped_to_list(megaz, dm_s, lba, purge)
#define z_mapped_sync(megaz) \
	zdm_mapped_sync(megaz)
#define z_mapped_init(megaz) \
	zdm_mapped_init(megaz)
#define write_if_dirty(megaz, oldest, use_wq) \
	zdm_write_if_dirty(megaz, oldest, use_wq)
#define release_table_pages(megaz) \
	zdm_release_table_pages(megaz)
#define sb_crc32(sblock) \
	zdm_sb_crc32(sblock)
#define z_acquire(megaz, maddr, bMeta, count, avail) \
	zdm_reserve_blocks(megaz, maddr, bMeta, count, avail)
#define move_to_map_tables(megaz, jrnl) \
	zdm_move_to_map_tables(megaz, jrnl)
#define get_map_entry(megaz, maddr, dir) \
	zdm_get_map_entry(megaz, maddr, dir)
#define sector_map_entry(megaz, maddr) \
	zdm_smap_entry(megaz, maddr)
#define reverse_map_entry(megaz, maddr) \
	zdm_rmap_entry(megaz, maddr)
#define get_map_table_entry(megaz, maddr, is_map_to) \
	zdm_map_table_entry(megaz, maddr, is_map_to)
#define update_map_entry(megaz, map, maddr, lba, is_fwd) \
	zdm_update_map_entry(megaz, map, maddr, lba, is_fwd)
#define get_meta_pg_crc(megaz, maddr, is_map_to, X) \
	zdm_get_meta_pg_crc(megaz, maddr, is_map_to), (void)X
#define fpages(megaz, allowed_pages) \
	zdm_free_unused(megaz, allowed_pages)
#define meta_integrity_test(megaz) \
	zdm_mz_integrity_check(megaz)
#define mcache_greatest_gen(mz, at, _a, _b) \
	zdm_mcache_greatest_gen(mz, at, _a, _b)

static inline struct zoned *get_znd(struct dm_target *ti)
{
	struct zoned *znd = ti->private;
	return znd;
}

#define read_block(ti, X, data, lba, count, Y) \
	zdm_read(get_znd(ti), data, lba, count), (void)X, (void)Y
#define write_block(ti, X, data, lba, count, Y) \
	zdm_write(get_znd(ti), data, lba, count), (void)X, (void)Y
#define crc_md_le16(data, len) \
	zdm_crc16_le16(data, len)
#define map_value(megaz, delta) \
	zdm_map_value(megaz, delta)
#define map_encode(megaz, to_addr, value) \
	zdm_map_encode(megaz, to_addr, value)
#define is_reverse_table_zone(megaz, maddr) \
	zdm_is_reverse_table_zone(megaz, maddr)
#define z_lookup_cache(megaz, maddr) \
	zdm_lookup_cache(megaz, maddr)
#define locate_sector(megaz, maddr) \
	zdm_locate_sector(megaz, maddr)
#define load_page(megaz, mapped, lba, is_to) \
	zdm_load_page(megaz, mapped, lba, is_to)

#endif /* _LIBZDM_COMPAT_H_ */

