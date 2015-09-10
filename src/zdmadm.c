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

#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <linux/fs.h>
#include <linux/hdreg.h>

#include <errno.h>
#include <string.h> // strdup

#include "libzdm.h"
#include "libzdm-compat.h"
#include "zbc-ctrl.h"
#include "crc64.h"
#include "is_mounted.h"

#define ZDMADM_CREATE 1
#define ZDMADM_RESTORE 2
#define ZDMADM_CHECK 3
#define ZDMADM_PROBE 4
#define ZDMADM_UNLOAD 5
#define ZDMADM_WIPE 6


#define ZDM_SBLK_VER_MAJOR 1
#define ZDM_SBLK_VER_MINOR 0
#define ZDM_SBLK_VER_POINT 0

#define ZDM_SBLK_VER   (ZDM_SBLK_VER_MAJOR << 16) | \
                       (ZDM_SBLK_VER_MINOR << 8) | \
                        ZDM_SBLK_VER_POINT

#define MEDIA_ZBC 0x01
#define MEDIA_ZAC 0x02

#define MEDIA_HOST_AWARE    (0x01 << 16)
#define MEDIA_HOST_MANAGED  (0x01 << 17)

#define ZONE_SZ_IN_SECT 0x80000 /* 1 << 19 */

/**
 * A large randomish number to identify a ZDM partition
 */
static const char zdm_magic[] = {
	0x7a, 0x6f, 0x6e, 0x65, 0x63, 0x44, 0x45, 0x56,
	0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81
};

/**
 * A superblock stored at the 0-th block of a deivce used to
 * re-create identify and manipulate a ZDM instance.
 * Contains enough information to repeat the dmsetup magic create/restore
 * an instance.
 */
struct zdm_super_block {
	u64 crc64;
	u8  magic[ARRAY_SIZE(zdm_magic)];
	uuid_t  uuid;
	u32 version;     /* 0xMMMMmmpt */
	u64 sect_start;
	u64 sect_size;
	u32 mz_metadata_zones;     /* 3 (default) */
	u32 mz_over_provision;     /* 5 (minimum) */
	u64 zdm_blocks;  /* 0 -> <zdm_blocks> for dmsetup table entry */
	u32 discard;     /* if discard support is enabled */
	u32 disk_type;   /* HA | HM */
	u32 zac_zbc;     /* if ZAC / ZBC is supported on backing device */
	char label[64];
};
typedef struct zdm_super_block zdm_super_block_t;

/**
 * A 64bit CRC. Overkill but it looked nice,
 *   inspired by btrfs-tools via util-linux
 */
static uint64_t zdm_crc64(zdm_super_block_t *sblk)
{
	u64 icrc = sblk->crc64;
	unsigned char *data = (unsigned char *) sblk;
	size_t sz = sizeof(*sblk);
	u64 calc;

	sblk->crc64 = 0ul;
	calc = crc64(0xFFFFFFFFFFFFFFFFULL, data, sz) ^ 0xFFFFFFFFFFFFFFFFULL;
	sblk->crc64 = icrc;

	return calc;
}

/**
 * Decode the ZDM superblock to a more user-friendly representation.
 */
static void zdmadm_show(const char * dname, zdm_super_block_t *sblk)
{
	char uuid_str[40];

	uuid_unparse(sblk->uuid, uuid_str);

	printf("Device %s is configured for ZDM:\n", dname );
	printf("crc     - %" PRIx64 "\n", sblk->crc64 );
	printf("magic   - %02x%02x%02x%02x%02x%02x%02x%02x "
			 "%02x%02x%02x%02x%02x%02x%02x%02x\n",
			sblk->magic[0],
			sblk->magic[1],
			sblk->magic[2],
			sblk->magic[3],
			sblk->magic[4],
			sblk->magic[5],
			sblk->magic[6],
			sblk->magic[7],
			sblk->magic[8],
			sblk->magic[9],
			sblk->magic[10],
			sblk->magic[11],
			sblk->magic[12],
			sblk->magic[13],
			sblk->magic[14],
			sblk->magic[15]);
	printf("uuid    - %s\n", uuid_str );
	printf("version - %d.%d.%d\n",
	                (sblk->version >> 16) & 0xFFFF,
			(sblk->version >>  8) & 0xFF,
			(sblk->version >>  0) & 0xFF );

	if (strlen(sblk->label) > 0) {
		printf("label   - %s\n", sblk->label );
	}
	printf("start   - %"PRIu64"\n", sblk->sect_start);
	printf("size    - %"PRIu64"\n", sblk->sect_size);
	printf("zdm sz  - %"PRIu64"\n", sblk->zdm_blocks);
	printf("resv    - %u [%u: metadata + %u: over provision]\n",
			sblk->mz_metadata_zones +  sblk->mz_over_provision,
			sblk->mz_metadata_zones,
			sblk->mz_over_provision);
	printf("trim    - %s\n", sblk->discard ? "ON" : "OFF");
	printf("ha/hm   - HostAware %s / HostManaged %s\n",
		sblk->disk_type & MEDIA_HOST_AWARE   ? "Yes" : "No",
		sblk->disk_type & MEDIA_HOST_MANAGED ? "Yes" : "No");

	printf("zac/zbc - ZAC: %s / ZBC: %s\n",
		sblk->zac_zbc & MEDIA_ZAC ? "Yes" : "No",
		sblk->zac_zbc & MEDIA_ZBC ? "Yes" : "No" );
}

/**
 * An initial 'check' and 'repair' ZDM metadata ...
 */
int my_debug_test(struct zoned * znd)
{
	int rc = 0;
	u64 mz = 1;
	u32 *data = ZDM_ALLOC(znd, Z_C4K, PG_09);
	if (!data)
		return -ENOMEM;

	printf("Loading MZ #");
	fflush(stdout);

	if (mz < znd->mega_zones_count)	{
		int err;
		struct megazone * megaz = &znd->z_mega[mz];

		printf(". %" PRIu64, mz);
		fflush(stdout);

		err = zdm_mapped_init(megaz);
                if (!err) {
			struct map_addr maddr;
			struct crc_pg *crc_pg_blk;
			u64 my_sector = 0x4020040ul; /* Is Rlut */
			int crc_okay = 0;
			int is_to = 0;
			int use_wq = 0;
			int crce;

			map_addr_calc(my_sector, &maddr);
			is_to = !is_reverse_table_zone(megaz, &maddr);
			crce = (maddr.mz_off & 0xFFFF) % 2048;
			crc_pg_blk = get_meta_pg_crc(megaz, &maddr, is_to, use_wq);
			if (!crc_pg_blk) {
				Z_ERR(megaz->znd, "%s: Out of space for metadata?", __func__);
				return -ENOSPC;
			}

			REF(crc_pg_blk->refcount);
			if (crc_pg_blk->crc_pg[crce]) {
				u64 lba = z_lookup(megaz, &maddr);

                                if (!lba) {
					lba = z_lookup_cache(megaz, &maddr);
				}
                                if (!lba) {
					lba = locate_sector(megaz, &maddr);
				}

	if (!lba) {
		struct map_pg *mapped;

		mapped = sector_map_entry(megaz, &maddr);
		if (mapped) {
			if (mapped->mdata) {
				u32 delta = mapped->mdata[maddr.offentry];
				u64 phy = map_value(megaz, delta);

				Z_ERR(megaz->znd, "%s: Delta %x", __func__, delta);
				Z_ERR(megaz->znd, "%s: Phy %" PRIx64, __func__, phy);
			} else {
				Z_ERR(megaz->znd, "%s: No BLOCK", __func__);
			}
		} else {
			Z_ERR(megaz->znd, "%s: No SME", __func__);
		}
	}


				if (lba) {
					int count = 1;
					int rd;

					Z_ERR(znd, "MZ# %u Mapping found for: "
					      "%"  PRIx64 " -> %" PRIx64 " [is_to %d]",
					      megaz->mega_nr, my_sector,  lba, is_to );


					rd = read_block(megaz->znd->ti,
							DM_IO_KMEM, data, lba,
							count, use_wq);
					if (rd) {
						rc = rd;
						Z_ERR(znd, "Integrity ERR: "
						      "%" PRIx64 " on disk %" PRIx64
						      " read err %d", my_sector,
						      lba, rd);
					} else {
						u16 crc = crc_md_le16(data, Z_CRC_4K);
						if (crc == crc_pg_blk->crc_pg[crce]) {
							crc_okay = 1;
						} else {
							Z_ERR(znd, "Integrity ERR: "
							      "%04x != %04x "
							      "at lba %" PRIx64 " "
							      "lmap %" PRIx64,
							      crc,
							      crc_pg_blk->crc_pg[crce],
							      lba, maddr.dm_s);
							rc = -EIO;
						}

					}
				} else {
					Z_ERR(znd, "MZ# %u PhyLBA Not found for: "
					      "0x%"  PRIx64 " is_to %d",
					      megaz->mega_nr, my_sector,  is_to );
				}
			}
			DEREF(crc_pg_blk->refcount);
			(void)crc_okay;
		}
	}

	ZDM_FREE(znd, data, Z_C4K, PG_09);

	return rc;
}


/**
 * An initial 'check' and 'repair' ZDM metadata ...
 */
int my_meta_integrity_test(struct megazone * megaz)
{
	int rc = 0;
	u32 z_used = Z_BLKSZ;
	u64 entry;
	u64 s_base = 0x20000 + (megaz->mega_nr * Z_BLKSZ * 1024);

	u32 *data = ZDM_ALLOC(megaz->znd, Z_C4K, PG_09);
	if (!data)
		return -ENOMEM;

#if EXTRA_DEBUG
	Z_ERR(megaz->znd, "MZ# %u integrity check in progress ..", megaz->mega_nr);
#endif // EXTRA_DEBUG

	for (entry = 0; entry < 0x20000; entry++) {
		int crc_okay = 0;
		int z_id = entry / 64;
		int use_wq = 0;
		int is_to;
		int crce;
		struct map_addr maddr;
		struct crc_pg *crc_pg_blk;

		map_addr_calc(s_base + entry, &maddr);
		crce = (maddr.mz_off & 0xFFFF) % 2048;
		is_to = !is_reverse_table_zone(megaz, &maddr);
		crc_pg_blk = get_meta_pg_crc(megaz, &maddr, is_to, use_wq);
		if (!crc_pg_blk) {
			Z_ERR(megaz->znd, "%s: Out of space for metadata?", __func__);
			return -ENOSPC;
		}

		if (!is_to) {
			if (0 == (entry % 64)) {
				z_used = Z_BLKSZ;
			}
		}

		REF(crc_pg_blk->refcount);
		if (crc_pg_blk->crc_pg[crce]) {
			u64 lba = z_lookup(megaz, &maddr);
			if (lba) {
				int count = 1;
				int rd;

				rd = read_block(megaz->znd->ti,
						DM_IO_KMEM, data, lba,
						count, use_wq);
				if (rd) {
					rc = rd;
					Z_ERR(megaz->znd, "Integrity ERR: "
					      "%" PRIx64 " on disk %" PRIx64
					      " read err %d", s_base + entry,
					      lba, rd);
				} else {
					u16 crc = crc_md_le16(data, Z_CRC_4K);
					if (crc == crc_pg_blk->crc_pg[crce]) {
						crc_okay = 1;
					} else {
						Z_ERR(megaz->znd, "Integrity ERR: "
						      "%04x != %04x "
						      "at lba %" PRIx64 " "
						      "lmap %" PRIx64,
						      crc,
						      crc_pg_blk->crc_pg[crce],
						      lba, maddr.dm_s);
						rc = -EIO;
					}

				}
			} else {
				Z_ERR(megaz->znd, "MZ# %u LBA Not found for: "
				      "0x%" PRIx64 "+entry:%" PRIx64 " [%"
				      PRIx64 "] is_to %d",
				      megaz->mega_nr,
				      s_base, entry, s_base + entry,
				      is_to );
			}

			if (crc_okay && (!is_to)) {
				int off;

				if (0 == (entry % 64)) {
					z_used = Z_BLKSZ;
				}

				for (off = 0; off < 1024; off++) {
					u64 ORlba =
					    (megaz->mega_nr * Z_BLKSZ * 1024)
					    + (z_id * Z_BLKSZ)
					    + ((entry % 64) * 1024)
					    + off;

					u32 enc = data[off];
					if (enc == MZTEV_UNUSED) {
						z_used--;
					} else {
						u64 dm_s =
						    map_value(megaz, enc);
						if (dm_s <
						    megaz->znd->nr_blocks) {
							struct map_pg *Smap;
							struct map_addr Saddr;
							map_addr_calc(dm_s,
								      &Saddr);
							Smap =
							    sector_map_entry
							    (megaz, &Saddr);
							if (Smap && Smap->mdata) {
								Z_DBG(megaz->znd, "lba: %"
								     PRIx64
								     " okay",
								     ORlba);
							} else {
								Z_ERR(megaz->znd, "lba: %"
								      PRIx64
								      " ERROR",
								      ORlba);
							}
						} else {
							Z_ERR(megaz->znd,
							      "Invalid rmap entry: %x.",
							      enc);
						}
						BUG_ON(dm_s >=
						       megaz->znd->nr_blocks);
					}
				}
			}
		}
		DEREF(crc_pg_blk->refcount);

		if (!is_to) {
			if (63 == (entry % 64)) {
				// update zone unused count
				if (0 ==
				    (megaz->z_ptrs[z_id] & Z_WP_FLAGS_MASK)) {
					megaz->zfree_count[z_id] =
					    Z_BLKSZ - z_used;
				}
			}
		}
	}

	ZDM_FREE(megaz->znd, data, Z_C4K, PG_09);
	return rc;
}




/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int zdm_mentry_page(struct megazone * megaz, struct map_pg *mapped, u64 lba, int mt)
{
	int rc = -ENOMEM;

	REF(mapped->refcount);
	mutex_lock(&mapped->md_lock);
	mapped->mdata = ZDM_ALLOC(megaz->znd, Z_C4K, PG_27);
	if (mapped->mdata) {
		memset(mapped->mdata, 0xFF, Z_C4K);
	}
	mutex_unlock(&mapped->md_lock);

	if (!mapped->mdata) {
		Z_ERR(megaz->znd, "%s: Out of memory.", __func__);
		goto out;
	}

	rc = load_page(megaz, mapped, lba, mt);
	if (rc < 0) {
		Z_ERR(megaz->znd, "%s: load_page from %" PRIx64
		      " [to? %d] error: %d", __func__, lba,
		      mt, rc);
		goto out;
	}
	mapped->age = jiffies_64;
out:
	DEREF(mapped->refcount);
	return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct map_pg *zdm_get_mentry(struct megazone * megaz, struct map_addr * maddr, int is_map_to)
{
	u64 lba = is_map_to ? maddr->lut_s : maddr->lut_r;
	struct map_pg *mapped = get_map_table_entry(megaz, lba, is_map_to);
	if (mapped) {
		if (!mapped->mdata) {
			int rc = zdm_mentry_page(megaz, mapped, lba, is_map_to);
			if (rc < 0) {
				megaz->meta_result = rc;
			}
		}
	} else {
		Z_ERR(megaz->znd, "%s: No table for %" PRIx64 " page# %" PRIx64 ".",
		      __func__, maddr->dm_s, lba);
	}
	return mapped;
}


/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static struct map_pg *load_map_entry(struct megazone * megaz, u64 lba, int is_map_to)
{
	struct map_pg *mapped = get_map_table_entry(megaz, lba, is_map_to);
	if (mapped) {
		if (!mapped->mdata) {
			int rc = zdm_mentry_page(megaz, mapped, lba, is_map_to);
			if (rc < 0) {
				megaz->meta_result = rc;
			}
		}
	} else {
		Z_ERR(megaz->znd, "%s: No table for page# %" PRIx64 ".",
		      __func__, lba);
	}
	return mapped;
}

#define E_NF MZTEV_NF

static void _all_nf(struct map_pg *mapped)
{
	int entry;
	for (entry = 0; entry < 1024; entry++) {
		mapped->mdata[entry] = E_NF;
	}
}

static int _test_nf(struct map_pg *mapped, int dont_fix)
{
	int entry;
	for (entry = 0; entry < 1024; entry++) {
		if (E_NF == mapped->mdata[entry]) {
			if (dont_fix) {
				printf("Bad entry %d [%x]\n", entry, mapped->mdata[entry] );
				return -1; /* E: Corrupt */
			}
			mapped->mdata[entry] = MZTEV_UNUSED;
		}
	}
	return 0;
}


/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

int __btf(struct megazone * megaz, struct map_pg *mapped, u64 b_lba, int is_to)
{
	int rcode = 0;
	u32 enc = 0;
	int entry;
	struct map_pg * lba_map;
	struct map_addr maddr;
	u64 lba_addr;
	u64 addr = (b_lba & 0xFFFF) * 1024;

	for (entry = 0; entry < 1024; entry++) {
		u64 dm_s = addr + entry
			 + (megaz->mega_nr * Z_BLKSZ * 1024ul);

		enc = mapped->mdata[entry];
		if ( enc > 0x03ffFFFFu ) {
			if ( MZTEV_UNUSED != enc ) {
//				printf("*** Invalid entry: %s %"PRIx64" %d %x\n",
//				       is_to ? "dms" : "lba", dm_s, entry, enc);
//
				mapped->mdata[entry] = E_NF;
				rcode = 1;
			}
		} else {
			int err;
			u32 value;
			u32 lba_enc = 0;
			u64 r_sect = 0;
			u64 lba = map_value(megaz, enc); // phy of dm_s

			if (!lba) {
				printf("Un-possible!! %d\n", __LINE__);
				mapped->mdata[entry] = E_NF;
				rcode = 1;
				continue;
			}

			map_addr_calc(lba, &maddr);
			lba_addr = !is_to ? maddr.lut_s : maddr.lut_r;
			lba_map = get_map_table_entry(megaz, lba_addr, !is_to);
			if (lba_map && lba_map->mdata) {
				lba_enc = lba_map->mdata[maddr.offentry];
				r_sect = map_value(megaz, lba_enc);
			}

			/* if lba_enc == MZTEV_NF (or othersise invalid) */
			/* correct the broken reverse map value */
			if (r_sect != dm_s) {
				printf("b2f: %s %" PRIx64 " --> %" PRIx64
				       " (%s) [dms_enc: %x]...",
					is_to ? "dms" : "lba",
					dm_s, lba, is_to ? "lba" : "dms", enc);

				err = map_encode(megaz, dm_s, &value);
				if (!err) {
					printf("Fix %" PRIx64 " %x <-- "
					       "[value: %x] %" PRIx64, lba,
					       lba_map->mdata[maddr.offentry],
					       value, r_sect );
					lba_map->mdata[maddr.offentry] = value;
					set_bit(IS_DIRTY, &lba_map->flags);
				}
				printf("\n");
			}
		}
	}
	return rcode;
}

/**
 * An initial check and repair the lookup tables.
 */
int zmz_car_rlut(struct megazone * megaz)
{
	struct mzlam * lam = &megaz->logical_map;
	u64 lba;
	u64 dm_s;
	int is_to = 0;
	int need_repair = 1;
	int fwd_corrupt = 0;
	int rev_corrupt = 0;

	/*
	 * Check and repair:
	 *   - load reverse map entries.
	 *   - load foward map entries.
	 */


	printf("e");
	fflush(stdout);

//	printf("REPAIR: MZ #%u, r_base %" PRIx64 " s_base %" PRIx64 "\n",
//		megaz->mega_nr, lam->r_base, lam->s_base );

//	printf("Loading Reverse mapping table\n");
	for (lba = lam->r_base; lba < (lam->r_base + Z_BLKSZ); lba++) {
		struct map_pg *mapped = get_map_table_entry(megaz, lba, is_to);
		if (mapped) {
			if (!mapped->mdata) {
				int err;
				err = zdm_mentry_page(megaz, mapped, lba, is_to);
				if (-ENOSPC == err) {
					printf("Out of memory!! %d\n", __LINE__);
					rev_corrupt = 1;
				} else if (err < 0) {
					printf("Loaded %" PRIx64 " Corrupt page.\n", lba );
					_all_nf(mapped);
					rev_corrupt = 1;
				} else {
					if (_test_nf(mapped, 1)) {
						printf("Repair failed: Bad entries in %"
							PRIx64 ".\n", lba);
					}
				}
			}
		} else {
			printf("Out of memory!! %d\n", __LINE__ );
		}
	}

// printf("Loading Forward mapping table / Fix reverse map\n");

	printf("p");
	fflush(stdout);

	is_to = 1;
	for (dm_s = lam->s_base; dm_s < (lam->s_base + Z_BLKSZ); dm_s++) {
		struct map_pg *mapped = get_map_table_entry(megaz, dm_s, is_to);
		if (mapped) {
			if (!mapped->mdata) {
				int err;
				err = zdm_mentry_page(megaz, mapped, dm_s, is_to);
				if (-ENOSPC == err) {
					printf("%" PRIx64 " -- Out of memory!!"
					        " %d\n", dm_s, __LINE__);
					fwd_corrupt = 1;
				} else if (err < 0) {
					printf("%" PRIx64 " -- Corrupt Entry!!"
					        " %d\n", dm_s, __LINE__);
					_all_nf(mapped);
					fwd_corrupt = 1;
				} else {
					if (_test_nf(mapped, 1)) {
						printf("Repair failed: Bad entries in %"
							PRIx64 ".\n", lba);
					}
				}
			}
			__btf(megaz, mapped, dm_s, is_to);
		} else {
			printf("Out of memory!! %d\n", __LINE__ );
		}
	}

//printf("Fixing Forward mapping table\n");
	printf("a");
	fflush(stdout);

	is_to = 0;
	for (lba = lam->r_base; lba < (lam->r_base + Z_BLKSZ); lba++) {
		struct map_pg *mapped = get_map_table_entry(megaz, lba, is_to);
		if (mapped) {
			if (!mapped->mdata) {
				int err;

printf("Loading %"PRIx64 " ?? \n", lba );
				err = zdm_mentry_page(megaz, mapped, lba, 0);
				if (-ENOSPC == err) {
					printf("%" PRIx64 " -- Out of memory!!"
					        " %d\n", lba, __LINE__);
				} else if (err < 0) {
					printf("%" PRIx64 " -- Corrupt Entry!!"
					        " %d\n", lba, __LINE__);
//					_all_nf(mapped);
				}
				rev_corrupt = 1;
			}
			__btf(megaz, mapped, lba, is_to);
		} else {
			printf("Out of memory!! %d\n", __LINE__ );
		}
	}

// printf("Verify Forward mapping table entries\n");
	printf("i");
	fflush(stdout);

	is_to = 1;
	for (dm_s = lam->s_base; dm_s < (lam->s_base + Z_BLKSZ); dm_s++) {
		struct map_pg *mapped = get_map_table_entry(megaz, dm_s, is_to);
		if (mapped) {
			if (!mapped->mdata) {
				int err;
				err = zdm_mentry_page(megaz, mapped, dm_s, is_to);
                                if (err < 0) {
					printf("Repair failed dm_s %" PRIx64
						" Err %d.\n", dm_s, err );
					goto out;
				}
			}
			if (!mapped->mdata) {
				printf("Repair failed: No page for %"
					PRIx64 ".\n", dm_s);
				goto out;
			}
			if (_test_nf(mapped, rev_corrupt)) {
				printf("Repair failed: Bad entries in %"
					PRIx64 ".\n", dm_s);
				goto out;
			}
		} else {
			printf("Out of memory!! %d\n", __LINE__ );
		}
	}

// printf("Verify Reverse mapping table entries\n");
	printf("r");
	fflush(stdout);

	is_to = 0;
	for (lba = lam->r_base; lba < (lam->r_base + Z_BLKSZ); lba++) {
		struct map_pg *mapped = get_map_table_entry(megaz, lba, is_to);
		if (mapped) {
			if (!mapped->mdata) {
				int err;
				err = zdm_mentry_page(megaz, mapped, lba, 0);
                                if (err < 0) {
					printf("Repair failed lba %" PRIx64
						" Err %d.\n", lba, err );
					goto out;
				}
			}
			if (!mapped->mdata) {
				printf("Repair failed: No page for %"
					PRIx64 ".\n", lba);
				goto out;
			}
			if (_test_nf(mapped, fwd_corrupt)) {
				printf("Repair failed: Bad entries in %"
					PRIx64 ".\n", lba);
				goto out;
			}
		} else {
			printf("Out of memory!! %d\n", __LINE__ );
		}
	}
	need_repair = 0;

	printf(".");
	fflush(stdout);

out:
	return need_repair;
}

/**
 * An initial 'check' and 'repair' ZDM metadata on a Megazone
 */
int zdm_mz_check_and_repair(struct megazone * megaz)
{
	int err;
	int entry;

	printf("R");
	fflush(stdout);

	err = zmz_car_rlut(megaz);
	if (err) {
		/* repair is still needed */
		goto out;
	}

	/* on clean: */
	for (entry = 0; entry < Z_BLKSZ; entry++) {
		if (megaz->sectortm[entry]) {
			write_if_dirty(megaz, megaz->sectortm[entry], 1);
		}
		if (megaz->reversetm[entry]) {
			write_if_dirty(megaz, megaz->reversetm[entry], 1);
		}
	}

out:
	release_table_pages(megaz);

	return err;
}

/**
 * An initial 'check' and 'repair' ZDM metadata ...
 */
int zdm_check_and_repair(struct zoned * znd)
{
	int err = 0;
	u64 mz = 0;
	int all_good = 1;

	printf("Loading MZ ");
	fflush(stdout);
	for (mz = 0; mz < znd->mega_zones_count; mz++) {
		printf("%"PRIu64".", mz);
		fflush(stdout);

		err = zdm_mapped_init(&znd->z_mega[mz]);
		if (err) {
			printf("MZ #%"PRIu64" Init failed -> %d\n", mz, err);
			goto out;
		}
	}

	printf("done.\nZDM Check ");
	fflush(stdout);

	for (mz = 0; mz < znd->mega_zones_count; mz++) {
		printf("%"PRIu64".", mz);
		fflush(stdout);

		err = zdm_mz_check_and_repair(&znd->z_mega[mz]);
		if (err) {
			printf("MZ #%"PRIu64" Check failed -> %d\n", mz, err);
			goto out;
		}
	}

	if (all_good) {
		int do_tables = 1;

		printf("Write clean SB\n");
		if (znd->z_superblock) {
			struct mz_superkey *key_blk = znd->z_superblock;
			struct zdm_superblock *sblock = &key_blk->sblock;

			sblock->flags = cpu_to_le32(0);
			sblock->csum = sb_crc32(sblock);
		}
		printf("Sync ... SB\n");

		for (mz = 0; mz < znd->mega_zones_count; mz++) {
			zdm_sync(&znd->z_mega[mz], do_tables);
		}
	}

out:
	return 0;
}

/**
 * An initial 'check' and 'repair' ZDM metadata ...
 */
int my_alt_test(struct zoned * znd, int verbose)
{
	u64 dm_s;
	u64 lba;
	struct megazone * megaz = &znd->z_mega[0];

	for (dm_s = 0x20000; dm_s < 0x60000; dm_s++) {
		struct map_addr maddr;

		zdm_map_addr(dm_s, &maddr);
		lba = zdm_lookup(megaz, &maddr);
		if (lba && verbose) {
			fprintf(stderr, "%"PRIx64" -> %"PRIx64"\n", dm_s, lba);
		}
	}
	return 0;
}

/**
 * Find and verify the actual ZDM superblock(s) and key metadata.
 *
 * Return 1 if superblock is flagged as dirty.
 */
int zdm_metadata_check(struct zoned * znd)
{
	int rcode = 0;
	struct zdm_superblock * sblock = znd->super_block;
	char uuid_str[40];

	uuid_unparse(sblock->uuid, uuid_str);

	rcode = zdm_superblock_check(sblock);
	printf("sb check -> %d %s\n", rcode, rcode ? "error" : "okay");
	if (rcode) {
		return rcode;
	}

	rcode = zdm_sb_test_flag(sblock, SB_DIRTY) ? 1 : 0;

	// do whatever
	printf("UUID    : %s\n",   uuid_str);
	printf("Magic   : %"PRIx64"\n",   le64_to_cpu(sblock->magic) );
	printf("Version : %08x\n", le32_to_cpu(sblock->version) );
	printf("N# Zones: %d\n",   le32_to_cpu(sblock->nr_zones) );
	printf("First Zn: %"PRIx64"\n",   le64_to_cpu(sblock->first_zone) );
	printf("Flags   : %08x\n", le32_to_cpu(sblock->flags) );
	printf("          %s %s\n",
			zdm_sb_test_flag(sblock, SB_DIRTY) ? "dirty" : "clean",
			zdm_sb_test_flag(sblock, SB_Z0_RESERVED) ? "no Z0" : "open"
			 );

	znd->first_zone  = le64_to_cpu(sblock->first_zone);
	if (zdm_sb_test_flag(sblock, SB_Z0_RESERVED) && ! znd->preserve_z0) {
		znd->preserve_z0 = zdm_sb_test_flag(sblock, SB_Z0_RESERVED);
		printf("TODO: Must re-read sb checking for "
		             "highest gen between Z1/Z2.\n");
	}
	return rcode;

}


/**
 * Get the starting block of the partition.
 * Currently using HDIO_GETGEO and start is a long ...
 * Q: Is there better way to get this? Preferably an API
 *    returning the a full u64. Other option is to poke
 *    around in sysfs (/sys/block/sdX/sdXn/start)
 *
 * FUTURE: Do this better ...
 */
int blkdev_get_start(int fd, unsigned long *start)
{
	struct hd_geometry geometry;

	if (ioctl(fd, HDIO_GETGEO, &geometry) == 0) {
		*start = geometry.start;
		return 0;
	}
	return -1;
}


/**
 * Get the full size of a partition/block device.
 */
int blkdev_get_size(int fd, u64 *sz)
{
	if (ioctl(fd, BLKGETSIZE64, sz) >= 0) {
		return 0;
	}
	return -1;
}


/**
 * User requested the ZDM be checked ...
 * TODO: Add fix support, switch to RW, etc.
 */
int zdmadm_check(const char *dname, int fd, zdm_super_block_t * sblock, int do_fix)
{
	struct zoned * znd;
	char * zname;
	int rcode;

	if (strlen(sblock->label) > 0) {
		zname = sblock->label;
	} else {
		zname = strrchr(dname, '/');
		if (zname) {
			if (*zname == '/') {
				zname++;
			}
		} else {
			rcode = -1;
			printf("Invalid argument. Need valid dname or zname\n");
			goto out;
		}
	}

	znd = zoned_alloc(fd, zname);
	rcode = zdm_superblock(znd);
	if (0 == rcode) {
		int is_dirty = zdm_metadata_check(znd);
		if (is_dirty ||	do_fix) {
			int err = zdm_check_and_repair(znd);
			if (err) {
				printf("ERROR: check/repair failed!\n");
				rcode = err;
			}
		}

	} else {
		printf("Unable to find/load superblock\n");
	}

out:
	return rcode;
}

int zaczbc_probe_media(int fd, zdm_super_block_t * sblk, int verbose)
{
	int do_ata = 0;
	int rcode = -1;

	zoned_inquiry_t * inq = zdm_device_inquiry(fd, do_ata);
	if (inq) {
		if (zdm_is_ha_device(inq, 0)) {
			sblk->zac_zbc |= MEDIA_ZBC;
			sblk->disk_type |= MEDIA_HOST_AWARE;
			if (verbose > 0) {
				printf(" ... HA device supports ZBC access.\n");
			}
			rcode = 0;
		}
		free(inq);
	}

	do_ata = 1;
	inq = zdm_device_inquiry(fd, do_ata);
	if (inq) {
		if (zdm_is_ha_device(inq, 0)) {
			sblk->disk_type |= MEDIA_HOST_AWARE;
			sblk->zac_zbc   |= MEDIA_ZAC;
			if (verbose > 0) {
				printf(" ... HA device supports ZAC access.\n");
			}
			rcode = 0;
		}
		free(inq);
	}

	if (0 == sblk->disk_type && 0 == sblk->zac_zbc) {
		if (verbose > 0) {
			printf(" ... No ZAC/ZAC support detected.\n");
		}
		rcode = 0;
	}

	return rcode;
}

static inline int is_conv_or_relaxed(unsigned int type)
{
	return (type == 1 || type == 3) ? 1 : 0;
}

int zdmadm_probe_zones(int fd, zdm_super_block_t * sblk)
{
	int rcode = 0;
	size_t size = 128 * 4096;
	struct bdev_zone_report_ioctl_t * report = malloc(size);
	if (report) {
		int opt = ZOPT_NON_SEQ_AND_RESET;
		u64 lba = sblk->sect_start;
		int do_ata = (sblk->zac_zbc & MEDIA_ZAC) ? 1 : 0;

		memset(report, 0, size);
		rcode = zdm_report_zones(fd, report, size, opt, lba, do_ata);
		if (rcode < 0) {
			printf("report zones failure: %d\n", rcode);
		} else  {
			struct bdev_zone_report_result_t * info = &report->data.out;
			struct bdev_zone_descriptor_entry_t * entry = &info->descriptors[0];

			int is_be = zdm_is_big_endian_report(info);
			u64 fz_at = is_be ? be64toh(entry->lba_start) : entry->lba_start;
			unsigned int type = entry->type & 0xF;
			int same = info->same_field & 0x0f;

			if (0 == same) {
				printf("Same code: %d is not supported.\n", same );
				rcode = -1;
			}

			if (lba != fz_at) {
				printf("Partition is not on zone boundary .. unsupported.\n");
				printf("Next zone lba is at sector: 0x%" PRIx64 ".\n",
					fz_at );
				rcode = -1;
			}

			if ( !is_conv_or_relaxed(type) ) {
				printf("Unsupported device: ZDM first zone must be conventional"
				       " or sequential-write preferred\n");
				rcode = -1;
			}
		}
		free(report);
	}
	return rcode;
}

int zdmadm_create(const char *dname, char *zname_opt,
		  int fd, zdm_super_block_t * sblock, int use_force, int verbose)
{
	int rc = 0;
	off_t lba = 0ul;
	zdm_super_block_t * data = malloc(Z_C4K);
	char cmd[1024];
	char * zname;

	if (zname_opt) {
		snprintf(sblock->label, sizeof(sblock->label), "%s", zname_opt);
		sblock->crc64 = zdm_crc64(sblock);
		zname = zname_opt;
	} else {
		zname = strrchr(dname, '/');
		if (zname) {
			if (*zname == '/') {
				zname++;
			}
		} else {
			rc = -1;
			printf("Invalid argument. Need valid dname or zname\n");
			goto out;
		}
	}

	if (!data) {
		fprintf(stderr, "Failed to allocate 4k\n");
		rc = -2;
		goto out;
	}
	memset(data, 0, Z_C4K);
	memcpy(data, sblock, sizeof(*sblock));

	rc = pwrite64(fd, data, Z_C4K, lba);
	if (rc != Z_C4K) {
		fprintf(stderr, "write error: %d writing %"
			PRIx64 "\n", rc, lba);
		rc = -1;
		goto out;
	}

	snprintf(cmd, sizeof(cmd),
		"dmsetup create \"zdm_%s\" "
			"--table \"0 %" PRIu64 " zoned %s %"PRIu64
			        " create %s %s %s %s reserve=%d\"",
		zname,
		sblock->zdm_blocks,
		dname,
		sblock->sect_start >> 19,
		use_force ? "force" : "",
		sblock->discard ? "discard" : "nodiscard",
		sblock->zac_zbc & MEDIA_ZAC ? "zac" : "nozac",
		sblock->zac_zbc & MEDIA_ZBC ? "zbc" : "nozbc",
		sblock->mz_metadata_zones + sblock->mz_over_provision);
	if (verbose) {
		printf("%s\n", cmd);
	}
	rc = system(cmd);
	if (rc != 0) {
		printf("** ERROR: Create ZDM instance failed: %d\n", rc);
	}
	zdmadm_show(dname, sblock);

out:
	if (data) {
		free(data);
	}
	return rc;
}

int zdmadm_restore(const char *dname, int fd, zdm_super_block_t * sblock)
{
	int rc = 0;
	char cmd[1024];
	char * zname;

	if (strlen(sblock->label) > 0) {
		zname = sblock->label;
	} else {
		zname = strrchr(dname, '/');
		if (zname) {
			if (*zname == '/') {
				zname++;
			}
		} else {
			rc = -1;
			printf("Invalid argument. Need valid dname or zname\n");
			goto out;
		}
	}


	snprintf(cmd, sizeof(cmd),
		"dmsetup create \"zdm_%s\" --table "
			"\"0 %" PRIu64 " zoned %s %"
		                PRIu64 " load %s %s %s reserve=%d\"",
		zname,
		sblock->zdm_blocks,
		dname,
		sblock->sect_start >> 19,
		sblock->discard ? "discard" : "nodiscard",
		sblock->zac_zbc & MEDIA_ZAC ? "zac" : "nozac",
		sblock->zac_zbc & MEDIA_ZBC ? "zbc" : "nozbc",
		sblock->mz_metadata_zones + sblock->mz_over_provision );

	printf("%s\n", cmd);
	rc = system(cmd);
	if (rc != 0) {
		printf("Restore ZDM instance failed: %d\n", rc);
	}

out:
	return rc;
}


int zdmadm_wipe(int fd, zdm_super_block_t * sblock)
{
	int rc = 0;
	off_t lba = 0ul;
	zdm_super_block_t * data = malloc(Z_C4K);

	memset(data, 0, Z_C4K);

	do {
		rc = pwrite64(fd, data, Z_C4K, lba);
		if (rc != Z_C4K) {
			fprintf(stderr, "write error: %d writing %"
				PRIx64 "\n", rc, lba);
			rc = -1;
			goto out;
		}
	} while (lba++ < 2048);

out:
	if (data) {
		free(data);
	}
	return rc;
}

int zdmadm_unload(const char *dname, int fd, zdm_super_block_t * sblock)
{
	int rc = 0;
	char cmd[1024];
	char * zname;

	if (strlen(sblock->label) > 0) {
		zname = sblock->label;
	} else {
		zname = strrchr(dname, '/');
		if (zname) {
			if (*zname == '/') {
				zname++;
			}
		} else {
			rc = -1;
			printf("Invalid argument. Need valid dname or zname\n");
			goto out;
		}
	}

	snprintf(cmd, sizeof(cmd), "dmsetup remove \"zdm_%s\"", zname );

	printf("%s\n", cmd);
	rc = system(cmd);
	if (rc != 0) {
		printf("ZDM Unload failed: %d\n", rc);
	}

out:
	return rc;
}


int zdmadm_probe_existing(int fd, zdm_super_block_t * sblock, int verbose)
{
	int rc = 0;
	off_t lba = 0ul;
	zdm_super_block_t * data = malloc(Z_C4K);
	u64 crc;

	if (!data) {
		fprintf(stderr, "Failed to allocate 4k\n");
		rc = -2;
		goto out;
	}

	rc = pread64(fd, data, Z_C4K, lba);
	if (rc != Z_C4K) {
		fprintf(stderr, "read error: %d reading %" PRIx64 "\n", rc, lba);
		rc = -1;
		goto out;
	}

	crc = zdm_crc64(data);
	if (crc != data->crc64) {
		if (verbose > 0) {
			fprintf(stderr, "ZDM CRC: %" PRIx64 " != %" PRIx64
				" on device.\n", crc, data->crc64 );
		}
		rc = -1;
		goto out;
	}

	if (0 != memcmp(data->magic, zdm_magic, ARRAY_SIZE(zdm_magic)) ) {
		if (verbose > 0) {
			fprintf(stderr, "ZDM Magic not found on device.\n");
		}
		rc = -1;
		goto out;
	}

	memcpy(sblock, data, sizeof(*sblock));

out:
	if (data) {
		free(data);
	}
	return rc;
}


static void calculate_zdm_blocks(zdm_super_block_t * sblk)
{
	u64 mz_resv      = sblk->mz_metadata_zones + sblk->mz_over_provision;
	u64 zone_count   = sblk->sect_size >> 19;
	u64 megaz_count  = (zone_count + 1023) >> 10;
	u64 zdm_reserved = mz_resv * megaz_count;
	sblk->zdm_blocks = (zone_count << 19) - (zdm_reserved << 19);
}

int zdmadm_probe_default(const char * dname, int fd, zdm_super_block_t * sblk,
			 u32 resv, u32 oprov, u32 trim, int verbose)
{
	unsigned long start; /* in 512 byte sectors */
	u64 sz;
	int exCode = 0;

	sblk->version = ZDM_SBLK_VER;
	sblk->discard = 1;
	memcpy(sblk->magic, zdm_magic, sizeof(sblk->magic));
	uuid_generate(sblk->uuid);
	sblk->mz_metadata_zones = resv;
	sblk->mz_over_provision = oprov;
	sblk->discard = trim;

	if (verbose > 0) {
		printf("Scanning device %s\n", dname );
	}

	if (blkdev_get_start(fd, &start) < 0) {
		printf("Failed to determine partition starting sector!!\n");
		exCode = 1;
		goto out;
	}
	sblk->sect_start = start;

	if (blkdev_get_size(fd, &sz) < 0) {
		printf("Failed to determine partition size!!\n");
		exCode = 2;
		goto out;
	}
	sblk->sect_size = sz >> 9;

	if (zaczbc_probe_media(fd, sblk, verbose) < 0) {
		exCode = 3;
		goto out;
	}
	if (verbose > 0) {
		printf(" ... partition %lx, len %"PRIu64" (512 byte sectors)\n",
			sblk->sect_start, sblk->sect_size);
	}

	calculate_zdm_blocks(sblk);

	if (sblk->zac_zbc) {
		/* test 'size' for sanity */
		if (zdmadm_probe_zones(fd, sblk) < 0) {
			exCode = 4;
			goto out;
		}
	} else {
		/* pass through conventional ... no checks */
	}

	sblk->crc64 = zdm_crc64(sblk);

out:
	return exCode;
}

void usage(void)
{
	printf("USAGE:\n"
	       "    zdmadm [options] device\n"
	       "Options:\n"
	       "    -c create zdm on device\n"
	       "    -F force used with create or wipe \n"
	       "    -k check zdm instance\n"
	       "    -l specify zdm 'label' (default is zdm_sdXn)\n"
	       "    -p probe device for superblock. (default)\n"
	       "    -r restore zdm instance11\n"
	       "    -R <N> over-provision <N> zones per Megazone (minimum=8)\n"
	       "    -t <0|1> trim on/off, default is on.\n"
	       "    -u unload zdm instance\n"
	       "    -v verbosity. More v's more verbose.\n"
	       "    -w wipe an existing zdm instance. Requires -F\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int index;
	char * label = NULL;
	int exCode = 0;

	u32 reserved_zones  = 3;
	u32 over_provision  = 5;
	u32 discard_default = 1;
	u32 resv;
	int command = ZDMADM_PROBE;
	int use_force = 0;
	int verbose = 0;

	/* Parse command line */
	errno = EINVAL; // Assume invalid Argument if we die
	while ((opt = getopt(argc, argv, "t:R:l:Fpcrkuwv")) != -1) {
		switch (opt) {
		case 'p':
			command = ZDMADM_PROBE;
			break;
		case 'c':
			command = ZDMADM_CREATE;
			break;
		case 'R':
			resv = strtoul(optarg, NULL, 0);
			if (8 < resv && resv < 1024) {
				over_provision = resv - reserved_zones;
			}
			break;
		case 'r':
			command = ZDMADM_RESTORE;
			break;
		case 'k':
			command = ZDMADM_CHECK;
			break;
		case 'w':
			command = ZDMADM_WIPE;
			break;
		case 'u':
			command = ZDMADM_UNLOAD;
			break;
		case 'F':
			use_force = 1;
			break;
		case 'l':
			if (strlen(optarg) < 64) {
				label = optarg;
			} else {
				printf("Label: '%s' is too long. Max is 63\n",
					optarg);
			}
			break;
		case 't':
			discard_default = atoi(optarg) ? 1 : 0;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
			break;
		} /* switch */
	} /* while */

	if (verbose > 0) {
		set_debug(verbose);
	}

	for (index = optind; index < argc; ) {
		int fd;
		char *dname = argv[index];
		int is_busy;
		char buf[80];
		int flags;
		int need_rw = 0;
		int o_flags = O_RDONLY;

		is_busy = is_anypart_mounted(dname, &flags, buf, sizeof(buf));
		if (is_busy || flags) {
			if (ZDMADM_CREATE == command ||ZDMADM_WIPE == command ) {
				need_rw = 1;
			}
			if (use_force && ZDMADM_CHECK == command) {
				need_rw = 1;
			}

			if (need_rw) {
				printf("%s is busy/mounted: %d:%x\n",
					dname, is_busy, flags );
				printf("refusing to proceed\n");
				exCode = 1;
				goto out;
			}
		}

		if (need_rw) {
			o_flags = O_RDWR;
		}

		fd = open(dname, o_flags);
		if (fd) {
			int zdm_exists = 1;
			zdm_super_block_t sblk_def;
			zdm_super_block_t sblk;

			memset(&sblk_def, 0, sizeof(sblk_def));

			exCode = zdmadm_probe_default(dname, fd, &sblk_def,
						      reserved_zones,
						      over_provision,
						      discard_default,
						      verbose );
			if (exCode) {
				goto out;
			}

			exCode = zdmadm_probe_existing(fd, &sblk, verbose);
			if (exCode < 0) {
				zdm_exists = 0;
			}

			switch(command) {
			case ZDMADM_CREATE:
				if (zdm_exists && ! use_force) {
					printf("ZDM Already on disk. Use -F to force\n");
					exCode = 1;
					goto out;
				}
				close(fd);
				fd = open(dname, O_RDWR);
				if (fd < 0) {
					perror("Failed to open device for RW");
					printf("ZDM disk re-open RDWR failed: %s\n", dname);
					exCode = 1;
					goto out;
				}
				exCode = zdmadm_create(dname, label, fd, &sblk_def,
							use_force, verbose);
				if (exCode < 0) {
					printf("ZDM Create failed.\n");
					exCode = 1;
					goto out;
				}
			break;
			case ZDMADM_RESTORE:
				if (! zdm_exists) {
					printf("ZDM No found. Nothing to restore.\n");
					goto next;
				}
				exCode = zdmadm_restore(dname, fd, &sblk);
				if (exCode < 0) {
					printf("ZDM Restore failed.\n");
					exCode = 1;
					goto next;
				}
			break;
			case ZDMADM_UNLOAD:
				if (! zdm_exists) {
					printf("ZDM No found. Nothing to unload.\n");
					goto next;
				}
				exCode = zdmadm_unload(dname, fd, &sblk);
				if (exCode < 0) {
					printf("ZDM Restore failed.\n");
					exCode = 1;
					goto next;
				}
			break;
			case ZDMADM_WIPE:
				if (! zdm_exists) {
					printf("ZDM No found. Nothing to wipe.\n");
					exCode = 1;
					goto out;
				}
				if (! use_force) {
					printf("Wipe must use -F to force\n");
					exCode = 1;
					goto out;
				}
				close(fd);
				fd = open(dname, O_RDWR);
				if (fd < 0) {
					perror("Failed to open device for RW");
					printf("ZDM disk re-open RDWR failed: %s\n", dname);
					exCode = 1;
					goto out;
				}
				exCode = zdmadm_wipe(fd, &sblk);
				if (exCode < 0) {
					printf("ZDM Wipe failed.\n");
					exCode = 1;
					goto out;
				}
			break;
			case ZDMADM_CHECK:
				if (! zdm_exists) {
					printf("No ZDM found on %s device.\n",
						dname);
					goto next;
				}

				if (use_force) {
					close(fd);
					fd = open(dname, O_RDWR);
				}

				exCode = zdmadm_check(dname, fd, &sblk, use_force);
				if (exCode < 0) {
					printf("ZDM check failed.\n");
					exCode = 1;
					goto next;
				}
			break;
			case ZDMADM_PROBE:
				if (! zdm_exists) {
					if (verbose > 0) {
						printf("No ZDM found on %s device.\n",
							dname);
					}
					goto next;
				}
				zdmadm_show(dname, &sblk);
				goto next;
			break;
			default:
				printf("Unknown command\n");
				exCode = 1;
				goto out;
			break;
			}
		} else {
			perror("Failed to open device");
			fprintf(stderr, "device: %s", dname);
		}
next:
		index++;

	} /* end: for each device on cli */

	if (optind >= argc) {
		usage();
	}

out:
	return exCode;
}


