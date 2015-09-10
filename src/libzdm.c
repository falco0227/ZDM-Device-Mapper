/*
 * Kernel Device Mapper for abstracting ZAC/ZBC devices as normal
 * block devices for linux file systems.
 *
 * Copyright (C) 2015 Seagate Technology PLC
 *
 * Written by:
 * Shaun Tancheff <shaun.tancheff@seagate.com>
 *
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

#include "libzdm.h"
#include "zbc-ctrl.h"

static int __debug_state = 0;

int _debug(void)
{
	return __debug_state;
}

void set_debug(int state)
{
	__debug_state = state;
}

static inline int megazone_wp_sync(struct zoned *znd, int reset_non_empty)
{
	(void)znd;
	(void)reset_non_empty;
	return 0;
}

static inline struct inode * get_bdev_bd_inode(struct zoned *znd)
{
	(void)znd;
	return NULL;
}

static inline void dump_stack(void) {}

static int read_block(struct dm_target *ti, enum dm_io_mem_type dtype,
                      void *data, u64 lba,
                      unsigned int count, int queue);
static int write_block(struct dm_target *ti, enum dm_io_mem_type dtype,
                       void *data, u64 lba,
                       unsigned int count, int queue);

static int is_zoned_inquiry(struct zoned *znd)
{
	return zdm_zoned_inq(znd);
}

static int dmz_reset_wp(struct megazone * megaz, u64 z_id)
{
	return zdm_reset_wp(megaz, z_id);
}

static int dmz_open_zone(struct megazone * megaz, u64 z_id)
{
	return zdm_open(megaz, z_id);
}

static int dmz_close_zone(struct megazone * megaz, u64 z_id)
{
	return zdm_close(megaz, z_id);
}

static void on_timeout_activity(struct zoned * znd)
{
	(void)znd;
}

struct zoned * zoned_alloc(int fd, char * name);
int read_superblock(struct zoned * znd);

#include "libzoned.c"

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static void activity_timeout(unsigned long data)
{
	(void)data;
}

static void bg_work_task(struct work_struct *work)
{
	(void) work;
}

/* -------------------------------------------------------------------------- */

void _zdm_free(struct zoned * znd, void *p, size_t sz, u32 code)
{
	zdm_free(znd, p, sz, code);
}

void * _zdm_alloc(struct zoned * znd, size_t sz, int code)
{
	return zdm_alloc(znd, sz, code);
}

void * _zdm_calloc(struct zoned * znd, size_t n, size_t sz, int code)
{
	return zdm_calloc(znd, n, sz, code);
}

int zdm_is_reverse_table_zone(struct megazone * megaz, struct map_addr * maddr)
{
	return is_reverse_table_zone(megaz, maddr);
}

/* -------------------------------------------------------------------------- */

static u64 mcache_greatest_gen(struct megazone *, int, u64 *, u64 *);
static u64 mcache_find_gen(struct megazone *, u64 base, int, u64 * out);
static void activity_timeout(unsigned long data);

u64 zdm_mcache_greatest_gen(struct megazone * mz, int at, u64 *_a, u64 *_b)
{
	return mcache_greatest_gen(mz, at, _a, _b);
}

u64 zdm_mcache_find_gen(struct megazone *mz, u64 base, int opt, u64 * out)
{
	return zdm_mcache_find_gen(mz, base, opt, out);
}

int zdm_zone_ctrl(struct megazone * megaz, u64 z_id, int command_id)
{
	int wp_err = 0;
	int fd = megaz->znd->ti->fd;

	if (megaz->znd->zinqtype == Z_TYPE_SMR_HA) {
		u64 mapped_zoned = z_id + megaz->znd->first_zone;
		u64 lba = Z_BLKSZ * ((megaz->mega_nr * 1024) + mapped_zoned);
		u64 s_addr = lba * Z_BLOCKS_PER_DM_SECTOR;
		int do_ata = megaz->znd->ata_passthrough;

		wp_err = zdm_zone_command(fd, command_id, s_addr, do_ata);
		if (wp_err) {
			Z_ERR(megaz->znd, "Reset WP: %" PRIx64 " -> %d failed.",
			       s_addr, wp_err);
			Z_ERR(megaz->znd, "Disabling Reset WP capability");
			megaz->znd->zinqtype = 0;
		}
	}
	return wp_err;
}


int zdm_reset_wp(struct megazone * megaz, u64 z_id)
{
	return zdm_zone_ctrl(megaz, z_id, SCSI_IOCTL_RESET_WP);
}

int zdm_close(struct megazone * megaz, u64 z_id)
{
	return zdm_zone_ctrl(megaz, z_id, SCSI_IOCTL_CLOSE_ZONE);
}

int zdm_open(struct megazone * megaz, u64 z_id)
{
	return zdm_zone_ctrl(megaz, z_id, SCSI_IOCTL_OPEN_ZONE);
}

int zdm_zoned_inq(struct zoned *znd)
{
	int is_host_aware = 0;
	int fd = znd->ti->fd;
	int do_ata = znd->ata_passthrough;
	zoned_inquiry_t * inq = zdm_device_inquiry(fd, do_ata);
	if (inq) {
		is_host_aware = zdm_is_ha_device(inq, 0);
	}
	znd->zinqtype = is_host_aware;
	return 0;
}

struct zoned * zoned_alloc(int fd, char * name);

struct zoned * zdm_acquire(int fd, char * name)
{
	return zoned_alloc(fd, name);
}

void zdm_release(struct zoned *znd)
{
	if (znd->z_superblock) {
		struct mz_superkey *key_blk = znd->z_superblock;
		struct zdm_superblock *sblock = &key_blk->sblock;

		sblock->flags = cpu_to_le32(0);
		sblock->csum = sb_crc32(sblock);
	}

	megazone_destroy(znd);
	zoned_destroy(znd);
}

int zdm_read(struct zoned *znd, void * data, u64 lba, int count)
{
	return read_block(znd->ti, DM_IO_KMEM, data, lba, count, 0);
}

int zdm_write(struct zoned *znd, void * data, u64 lba, int count)
{
	return write_block(znd->ti, DM_IO_KMEM, data, lba, count, 0);
}

/* -------------------------------------------------------------------------- */

struct zoned * zoned_alloc(int fd, char * name)
{
        struct zoned * znd = calloc(1, sizeof(*znd));
        if (znd) {
		u64 mzcount;
		u64 remainder;
		u64 nbytes = 0ul;
		int rcode = ioctl(fd, BLKGETSIZE64, &nbytes);
		if (rcode < 0) {
			perror("BLKGETSIZE64");
		}

		znd->ti = calloc(1, sizeof(*znd->ti));;
		znd->ti->fd = fd;
		znd->ti->private = znd;
		znd->nr_blocks = nbytes / 4096;
		znd->device_zone_count = znd->nr_blocks / Z_BLKSZ;

		mzcount   = dm_div_up(znd->device_zone_count, MAX_ZONES_PER_MZ);
		remainder = znd->device_zone_count % MAX_ZONES_PER_MZ;
		if ( 0 < remainder && remainder < 5 ) {
			DMERR("Final MZ contains too few zones!\n");
			mzcount--;
		}
		znd->mega_zones_count = mzcount;

		znd->gc_io_buf = vmalloc(GC_MAX_STRIPE * Z_C4K);
		znd->io_wq = create_singlethread_workqueue("kzoned");
		znd->z_superblock = vzalloc(Z_C4K);

		is_zoned_inquiry(znd);

		if (0 == strncmp("/dev/", name, 5)) {
			name += 5;
		}

		if (0 == strncmp("mapper/", name, 7)) {
			name += 7;
		}

		strncpy(znd->bdev_name, name, BDEVNAME_SIZE-1);

		rcode = megazone_init(znd);
                if (rcode) {
			megazone_destroy(znd);
			free(znd->ti);
			free(znd->gc_io_buf);
			destroy_workqueue(znd->io_wq);
			free(znd->z_superblock);
			znd = NULL;
		}
        }
        return znd;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

int zdm_superblock(struct zoned * znd)
{
	struct mz_superkey * key_blk = znd->z_superblock;
	struct megazone * megaz = &znd->z_mega[0];

	int rcode = -1;
        int n4kblks = 1;
        int use_worker = 1;
        int rc = 0;
	u64 sb_lba = 0;

	if (find_superblock(megaz, use_worker, 1)) {
		u64 generation;

		generation = mcache_greatest_gen(megaz, use_worker, &sb_lba, NULL);
		pr_debug("Generation: %" PRIu64 " @ %" PRIx64 "\n", generation, sb_lba);

		rc = read_block(znd->ti, DM_IO_VMA, key_blk,
				sb_lba, n4kblks, use_worker);
		if (rc) {
			znd->ti->error = "Superblock read error.";
			return rc;
		}

		znd->super_block = &key_blk->sblock;
		rcode = 0;
	} else {
		fprintf(stderr, "Failed to find superblock\n");
	}

        return rcode;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int read_block(struct dm_target *ti, enum dm_io_mem_type dtype,
                      void *data, u64 lba, unsigned int count, int queue)
{
        off_t block = lba * Z_BLOCKS_PER_DM_SECTOR * 512ul;
        unsigned int c4k = count * Z_BLOCKS_PER_DM_SECTOR * 512ul;
        int rc = pread64(ti->fd, data, c4k, block);
        if (rc != c4k) {
                fprintf(stderr, "read error: %d reading %"
			PRIx64 "\n", rc, lba);
        } else {
		rc = 0;
        }
	(void)dtype;
	(void)queue;
        return rc;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

static int write_block(struct dm_target *ti, enum dm_io_mem_type dtype,
                       void *data, u64 lba, unsigned int count, int queue)
{
        off_t block = lba * Z_BLOCKS_PER_DM_SECTOR * 512ul;
        unsigned int c4k = count * Z_BLOCKS_PER_DM_SECTOR  * 512ul;

        int rc = pwrite64(ti->fd, data, c4k, block);
        if (rc != c4k) {
                fprintf(stderr, "write error: %d writing %"
			PRIx64 "\n", rc, lba);
        } else {
		rc = 0;
        }
	(void)dtype;
	(void)queue;

        return rc;
}

int zdm_superblock_check(struct zdm_superblock * sblock)
{
	return sb_check(sblock);
}

int zdm_map_onto_zdm(struct zoned *znd, u64 sector_nr, struct map_addr * out)
{
	return map_addr_to_zdm(znd, sector_nr, out);
}

int zdm_map_addr(u64 dm_s, struct map_addr * out)
{
	return map_addr_calc(dm_s, out);
}

int zdm_sync_tables(struct megazone * megaz, int need_table_push)
{
	return do_sync_tables(megaz, need_table_push);
}

int zdm_sync_crc_pages(struct megazone * megaz)
{
	return sync_crc_pages(megaz);
}

int zdm_unused_phy(struct megazone * megaz, u64 block_nr, u64 orig)
{
	return unused_phy(megaz, block_nr, orig);
}

int zdm_unused_addr(struct megazone * megaz, u64 dm_s)
{
	return unused_addr(megaz, dm_s);
}

u64 zdm_lookup(struct megazone * megaz, struct map_addr * maddr)
{
	return z_lookup(megaz, maddr);
}

int zdm_mapped_addmany(struct megazone * megaz, u64 dm_s, u64 lba, u64 count)
{
	return z_mapped_addmany(megaz, dm_s, lba, count);
}

int zdm_mapped_discard(struct megazone * megaz, u64 dm_s, u64 lba)
{
	return z_mapped_discard(megaz, dm_s, lba);
}

int zdm_mapped_to_list(struct megazone * megaz, u64 dm_s, u64 lba, int purge)
{
	return z_mapped_to_list(megaz, dm_s, lba, purge);
}

int zdm_mapped_sync(struct megazone * megaz)
{
	return z_mapped_sync(megaz);
}

int zdm_mapped_init(struct megazone * megaz)
{
	return z_mapped_init(megaz);
}

int zdm_write_if_dirty(struct megazone * megaz, struct map_pg * oldest, int use_wq)
{
	return write_if_dirty(megaz, oldest, use_wq);
}

int zdm_release_table_pages(struct megazone * megaz)
{
	return release_table_pages(megaz);
}

int zdm_sync(struct megazone * megaz, int do_tables)
{
	return do_SYNC(megaz, do_tables);
}

u32 zdm_sb_crc32(struct zdm_superblock *sblock)
{
	return sb_crc32(sblock);
}

u64 zdm_reserve_blocks(struct megazone * megaz, u32 flags, u32 count, u32 *avail)
{
	return z_acquire(megaz, flags, count, avail);
}

int zdm_move_to_map_tables(struct megazone * megaz, struct map_cache * jrnl)
{
	return move_to_map_tables(megaz, jrnl);
}

struct map_pg *zdm_get_map_entry(struct megazone * megaz, struct map_addr * maddr, int dir)
{
	return get_map_entry(megaz, maddr, dir);
}

struct map_pg *zdm_smap_entry(struct megazone * megaz, struct map_addr * maddr)
{
	return sector_map_entry(megaz, maddr);
}

struct map_pg *zdm_rmap_entry(struct megazone * megaz, struct map_addr * maddr)
{
	return reverse_map_entry(megaz, maddr);
}

struct map_pg *zdm_map_table_entry(struct megazone * megaz, u64 lba, int is_map_to)
{
	return get_map_table_entry(megaz, lba, is_map_to);

}

int zdm_update_map_entry(struct megazone * megaz, struct map_pg * map, struct map_addr *maddr, u64 lba, int is_fwd)
{
	return update_map_entry(megaz, map, maddr, lba, is_fwd);
}

struct crc_pg *zdm_get_meta_pg_crc(struct megazone * megaz, struct map_addr * maddr, int is_map_to)
{
	return get_meta_pg_crc(megaz, maddr, is_map_to, 0);
}

int zdm_free_unused(struct megazone * megaz, int allowed_pages)
{
	return fpages(megaz, allowed_pages);
}

int zdm_mz_integrity_check(struct megazone * megaz)
{
	return meta_integrity_test(megaz);
}


u16 zdm_crc16_le16(void const *data, size_t len)
{
	return crc_md_le16(data, len);
}

u64 zdm_map_value(struct megazone * megaz, u32 delta)
{
	return map_value(megaz, delta);
}

u64 zdm_map_encode(struct megazone * megaz, u64 to_addr, u32 * value)
{
	return map_encode(megaz, to_addr, value);
}

u64 zdm_lookup_cache(struct megazone * megaz, struct map_addr * maddr)
{
	return z_lookup_cache(megaz, maddr);
}

u64 zdm_locate_sector(struct megazone * megaz, struct map_addr * maddr)
{
	return locate_sector(megaz, maddr);
}

int zdm_load_page(struct megazone * megaz, struct map_pg * mapped, u64 lba, int is_to)
{
	return load_page(megaz, mapped, lba, is_to);
}


// static int load_page(struct megazone *, struct map_pg *, u64 lba, int);

// static u64 locate_sector(struct megazone * megaz, struct map_addr * maddr);
// static int z_zone_gc_chunk(struct gc_state * gc_entry);
// static int z_zone_gc_grab_empty_zone(struct gc_state * gc_entry);

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
// static int zoned_init(struct dm_target *ti, struct zoned *znd);
// static int fpages(struct megazone * megaz, int allowed_pages);
// static int zoned_create_disk(struct dm_target *ti, struct zoned * znd);

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
// static int zoned_init_disk(struct dm_target *ti, struct zoned * znd,
// 			   int create, int check, int force);
// static sector_t jentry_value(struct map_sect_to_lba * e, bool is_block);
// static u64 z_lookup_cache(struct megazone * megaz, struct map_addr * sm);


int zdm_meta_test(struct zoned * znd)
{
	u64 dm_s;
	u64 lba;
	u64 mz = 0;
	int verbose = 1;
	struct megazone * megaz = &znd->z_mega[mz];

	for (mz = 0; mz < znd->mega_zones_count; mz++) {
		int err = zdm_mapped_init(&znd->z_mega[mz]);
		if (err) {
			printf("MZ #%"PRIu64" Init failed -> %d\n", mz, err);
			return err;
		}
		err = zdm_mz_integrity_check(&znd->z_mega[mz]);
		if (err) {
			printf("MZ #%"PRIu64" Check failed -> %d\n", mz, err);
			return err;
		}
	}

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

int zdm_sb_test_flag(struct zdm_superblock * sb, int bit_no)
{
	return sb_test_flag(sb, bit_no);
}

void zdm_sb_set_flag(struct zdm_superblock * sb, int bit_no)
{
	sb_set_flag(sb, bit_no);
}

int zdm_do_something(struct zoned * znd)
{
	int rcode;
	struct zdm_superblock * sblock = znd->super_block;
	char uuid_str[40];

	uuid_unparse(sblock->uuid, uuid_str);

	rcode = zdm_superblock_check(sblock);
	printf("sb check -> %d %s\n", rcode, rcode ? "error" : "okay");

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

	zdm_meta_test(znd);

	return 0;

}


#if 0
int main(int argc, char *argv[])
{
	int opt;
	int index;
	int loglevel;
	int exCode = 0;

	/* Parse command line */
	errno = EINVAL; // Assume invalid Argument if we die
	while ((opt = getopt(argc, argv, "l:")) != -1) {
		switch (opt) {
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
		fd = open(argv[index], O_RDONLY);
		if (fd) {
			struct zoned * znd = zdm_acquire(fd, argv[index]);
			int rcode = zdm_superblock(znd);

			printf("read sb? fd: %d -> %d\n", fd, rcode);
			if (0 == rcode) {
				zdm_do_something(znd);
			} else {
				printf("Unable to find/load superblock\n");
			}
		} else {
			perror("Failed to open file");
			fprintf(stderr, "file: %s", argv[index]);
		}
	}

	(void) loglevel;

	return exCode;
}

#endif
