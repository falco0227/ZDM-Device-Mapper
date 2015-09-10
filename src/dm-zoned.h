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

#ifndef _DM_ZONED_H
#define _DM_ZONED_H

#define ZDM_IOC_MZCOUNT 0x5a4e0001
#define ZDM_IOC_WPS     0x5a4e0002
#define ZDM_IOC_FREE    0x5a4e0003
#define ZDM_IOC_STATUS  0x5a4e0004

#define DM_MSG_PREFIX "zoned"

#define ZDM_RESERVED_ZNR         0
#define ZDM_CRC_STASH_ZNR        1 /* first 64 blocks */
#define ZDM_REVERSE_MAP_ZNR      2
#define ZDM_SECTOR_MAP_ZNR       3
#define ZDM_DATA_START_ZNR       4

#define Z_WP_GC_FULL            (1u << 31)
#define Z_WP_GC_ACTIVE          (1u << 30)
#define Z_WP_GC_READY           (1u << 29)
#define Z_WP_NON_SEQ            (1u << 28)

#define Z_WP_GC_PENDING         (Z_WP_GC_FULL|Z_WP_GC_ACTIVE)

/*
 * #define Z_WP_TYPE_CONV          (1 << 27)
 * #define Z_WP_TYPE_CONV          (1 << 26)
 * #define Z_WP_TYPE_CONV          (1 << 25)
 * #define Z_WP_TYPE_CONV          (1 << 24)
 */

#define Z_WP_VALUE_MASK         (~0u >> 8)
#define Z_WP_FLAGS_MASK         (~0u << 24)

#define Z_AQ_GC                 (1 << 31)
#define Z_AQ_META               (1 << 30)
#define Z_AQ_NORMAL             (0)

#define Z_C4K                   (4096ul)
#define Z_UNSORTED              (Z_C4K / sizeof(struct map_sect_to_lba))
#define Z_BLOCKS_PER_DM_SECTOR  (Z_C4K/512)
#define MZ_METADATA_ZONES       (8ul)

#define SUPERBLOCK_LOCATION     0
#define SUPERBLOCK_MAGIC        0x5a6f4e65	/* ZoNe */
#define SUPERBLOCK_CSUM_XOR     146538381
#define MIN_ZONED_VERSION       1
#define Z_VERSION               1
#define MAX_ZONED_VERSION       1
#define INVALID_WRITESET_ROOT   SUPERBLOCK_LOCATION

#define UUID_LEN		16

#define Z_TYPE_SMR		2
#define Z_TYPE_SMR_HA		1
#define Z_VPD_INFO_BYTE		8

enum superblock_flags_t {
	SB_DIRTY = 1,
	SB_Z0_RESERVED,
};

struct z_io_req_t {
	struct dm_io_region *where;
	struct dm_io_request *io_req;
	struct work_struct work;
	int result;
};

#define Z_LOWER48 (~0ul >> 16)
#define Z_UPPER16 (~Z_LOWER48)

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

enum mapped_flags_enum {
	IS_DIRTY,
	IS_GC,
};

enum work_flags_enum {
	DO_JOURNAL_MOVE,
	DO_MEMPOOL,
	DO_SYNC,
	DO_JOURNAL_LOAD,
	DO_META_CHECK,
	DO_GC_NO_PURGE,
	DO_METAWORK_QD,
};

enum gc_flags_enum {
	DO_GC_NEW,
	DO_GC_PREPARE,		/* -> READ or COMPLETE state */
	DO_GC_WRITE,
	DO_GC_META,		/* -> PREPARE state */
	DO_GC_COMPLETE,
};

enum znd_flags_enum {
	ZF_PRESERVE_ZONE0,
	ZF_PACKED_META,
	ZF_IS_ZONED_TYPE,
	ZF_USE_ATA_MODE,
	ZF_FREEZE,
};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct zoned;

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct gc_state {
	struct megazone *megaz;
	unsigned long gc_flags;

	u32 r_ptr;
	u32 w_ptr;

	u32 nblks;		/* 1-65536 */
	int result;

	u16 z_gc;
	u16 tag;

};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct map_sect_to_lba {
	__le64 logical;		/* record type [16 bits] + logical sector # */
	__le64 physical;	/* csum 16 [16 bits] + 'physical' block lba */
} __packed;

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct map_pg {
	struct list_head inpool;

	u64 age;		/* most recent access in jiffies */
	u64 lba;		/* Z_LOWER48 contains the BLOCK where this
				 * data originates from .. */
	unsigned long flags;
	struct mutex md_lock;	/* lock mdata i/o */
	u32 *mdata;		/* 4k page of table entries */
	atomic_t refcount;

	u64 last_write;		/* last known position on disk */
	struct map_addr *maddr; /* nomially null [FIXME: remove this]*/
};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct map_addr {
	u64 dm_s;		/* full map on dm layer         */
	u64 z_id;		/* z_id match zone_list_t.z_id  */
	u64 mz_off;		/* megazone offset              */
	u64 mz_id;		/* mega zone #                  */
	u64 offentry;		/* entry in lut (0-1023)        */
	u64 lut_s;		/* sector table lba  */
	u64 lut_r;		/* reverse table lba */
};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct mzlam {
	u64 mz_base;
	u64 r_base;
	u64 s_base;
	u64 sk_low;
	u64 sk_high;
	u64 crc_low;
	u64 crc_hi;
};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct map_cache {
	struct list_head jlist;
	struct map_sect_to_lba *jdata;	/* 4k page of data */
	atomic_t refcount;
	struct mutex cached_lock;
	unsigned long no_sort_flag;
	u32 jcount;
	u32 jsorted;
	u32 jsize;
};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct crc_pg {
	u64 age;		/* most recent access in jiffies */
	u64 lba;		/* logical home */
	unsigned long flags;	/* IS_DIRTY flag */
	atomic_t refcount;	/* REF count (move to flags?) */
	u64 last_write;
	struct mutex lock_pg;
	u16 *crc_pg;		/* attached 4K page: [2048] entries */
};

#define MZKY_NBLKS  64
#define MZKY_NCRC   32

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct zdm_superblock {
	u8 uuid[UUID_LEN];	/* 16 */
	__le64 nr_zones;	/*  8 */
	__le64 magic;		/*  8 */
	__le64 first_zone;	/*  8 */
	__le32 version;		/*  4 */
	__le32 packed_meta;	/*  4 */
	__le32 flags;		/*  4 */
	__le32 csum;		/*  4 */
} __packed;			/* 56 */

#define MAX_CACHE_SYNC 400

/* stm_keys    -  512 - LBA64 for each key page of the Sector Table */
/* stm_crc_lba -  256 - LBA64 for each CRC page */
/* stm_crc_pg  -   64 - CRC16 for each CRC page */
/* rtm_crc_lba -  256 - LBA64 for each CRC page */
/* rtm_crc_pg  -   64 - CRC16 for each CRC page */
/* crcs        -  816 - Testing worst case so far - 142 entries. */
/* reserved    - 2048 */
/* n_crcs;     -    2 */
/* zp_crc;     -    2 */
/* free_crc    -    2 */
/* sblock;     -   56 */
/* generation  -    8 */
/* key_crc     -    2 */
/* magic       -    8 */

struct mz_superkey {
	u64 sig[2];
	u64 stm_keys[MZKY_NBLKS];
	u64 stm_crc_lba[MZKY_NCRC];
	u16 stm_crc_pg[MZKY_NCRC];
	u64 rtm_crc_lba[MZKY_NCRC];
	u16 rtm_crc_pg[MZKY_NCRC];
	u16 crcs[MAX_CACHE_SYNC];
	u16 reserved[1020];
	u32 gc_resv;
	u32 meta_resv;
	u16 n_crcs;
	u16 zp_crc;
	u16 free_crc;
	struct zdm_superblock sblock;
	u64 generation;
	u16 key_crc;
	u64 magic;
} __packed;

struct mz_state {
	struct mz_superkey  bmkeys;
	u32        z_ptrs[1024];
	u32             zfree[1024];
} __packed;

struct io_4k_block {
	u8 data[Z_C4K];
};

struct io_dm_block {
	u8 data[512];
};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct megazone {
	unsigned long flags;
	struct zoned *znd;
	struct list_head jlist;		/* journal */
	struct list_head smtpool;	/* in-use sm table  entries */
	struct map_pg **sectortm;
	struct map_pg **reversetm;
	struct mz_state *sync_io;
	struct io_4k_block *sync_cache;
	u32 *z_ptrs;
	u32 *zfree_count;
	u32  z_commit[1024];
	struct mz_superkey *bmkeys;
	struct mzlam       logical_map;
	struct crc_pg stm_crc[MZKY_NCRC];
	struct crc_pg rtm_crc[MZKY_NCRC];
	struct work_struct meta_work;
	sector_t last_w;
	u8 *cow_block;
	u64 cow_addr;
	struct mutex mz_io_mutex;	/* for normal i/o */
	struct mutex zp_lock;		/* general lock (block acquire)  */
	spinlock_t jlock;		/* journal lock */
	spinlock_t map_pool_lock;	/* smtpool: memory pool lock */
	struct mutex discard_lock;
	u64 age;		/* most recent access in jiffies */
	u32 mega_nr;
	u32 z_count;		/* megazone data span: 4-1024 */
	u32 z_gc_free;		/* current empty zone count */
	u32 z_data;		/* Range: 2->1023 */
	u32 z_current;		/* Range: 2->1023 */
	u32 z_gc_resv;
	u32 z_meta_resv;
	s32 incore_count;
	int mc_entries;
	int meta_result;
	u8 aggressive_gc;
};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

struct zoned {
	struct dm_target *ti;
	struct dm_target_callbacks callbacks;
	struct dm_dev *dev;
	u64 first_zone;	/* delta from lba 0 .. TBD use report_zones IOCTL */
	unsigned long flags;
	int preserve_z0;
	int packed_meta;

	/* background activity: */
	struct work_struct bg_work;
	struct workqueue_struct *bg_wq;
	spinlock_t stats_lock;

	/* zoned gc: */
	struct gc_state *gc_active;
	spinlock_t gc_lock;
	struct work_struct gc_work;
	struct workqueue_struct *gc_wq;
	int gc_backlog;
	void *gc_io_buf;

	/* superblock: */
	void *z_superblock;
	struct zdm_superblock *super_block;

	/* array of mega-zones: */
	struct megazone *z_mega;
	struct workqueue_struct *meta_wq;

	u64 device_zone_count;	/* zones on device */
	u64 mega_zones_count;	/* # of 256G mega-zones */
	u64 nr_blocks;		/* 4k blocks on backing device */

	struct map_cache gc_postmap;

	struct dm_io_client *io_client;
	struct workqueue_struct *io_wq;
	struct timer_list timer;

	u32 bins[40];
	char bdev_name[BDEVNAME_SIZE];

	size_t memstat;
	atomic_t suspended;
	u16 gc_mz_pref;
	u16 mz_provision;
	u8 zinqtype;
	u8 ata_passthrough;
};

struct zdm_ioc_request {
	u32 result_size;
	u32 megazone_nr;
};

struct zdm_ioc_status {
	u64 b_used;
	u64 b_available;
	u64 b_discard;
	u64 m_used;
	u64 mc_entries;
	u64 mlut_blocks;
	u64 crc_blocks;
	u64 inpool;
	u32 bins[40];
};

#endif /* _DM_ZONED_H */
