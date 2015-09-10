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

#ifndef _ZONED_H_
#define _ZONED_H_

#define __packed                        __attribute__((packed))
#include <stdint.h>
#include <inttypes.h>

#include <time.h>
#include <uuid/uuid.h>

#include "utypes.h"
#include "list.h"
#include "libcrc.h"
#include "libsort.h"
#include "malloc.h"


typedef unsigned long long __le64;


#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define BDEVNAME_SIZE 40


enum dm_io_mem_type {
	DM_IO_PAGE_LIST,/* Page list */
	DM_IO_BIO,      /* Bio vector */
	DM_IO_VMA,      /* Virtual memory area */
	DM_IO_KMEM,     /* Kernel memory */
};

struct dm_target {
	int             fd;
	const char * fname; /* usually a device: /dev/sdb[1-n] */
	void *     private;
	char *       error;
};

struct atomic_type {
	int counter;
};

struct work_struct {
	int  tag;
};

struct mutex {
	int  inuse;
};

struct dm_target_callbacks {
	void * pfn;
};

struct inode {
	void * node;
};

struct timer_list {
	u64 ticks;
};

typedef int spinlock_t;
typedef struct atomic_type atomic_t;
typedef u64 sector_t;
struct dm_kcopyd_client {
	int dummy;
};

struct dm_kcopyd_throttle {
	unsigned throttle;
	unsigned num_io_jobs;
	unsigned io_period;
	unsigned total_period;
	unsigned last_jiffies;
};

struct workqueue_struct {
	int      q_id;
	char * q_name;
};

static inline void del_timer_sync(struct timer_list * t) { (void) t; }
static inline void might_sleep(void) {}
static inline void msleep_interruptible(unsigned t) { (void) t; }
static void activity_timeout(unsigned long data);
static void bg_work_task(struct work_struct *work);

typedef void pfnTimeout(unsigned long data);
static void activity_timeout(unsigned long data);

static inline void setup_timer(struct timer_list * t, pfnTimeout * to_fn, unsigned long arg)
{
	(void)t;
	(void)to_fn;
	(void)arg;
}


#include "libzoned.h"

static inline char * _zdisk(struct zoned *znd)
{
	return znd->bdev_name;
}

int _debug(void);
void set_debug(int state);

#define Z_ERR(znd, fmt, arg...) \
	do { if (_debug() > 0) { \
		pr_err("dm-zoned(%s): " fmt "\n", _zdisk(znd), ## arg); \
	} } while (0)

#define Z_INFO(znd, fmt, arg...) \
	do { if (_debug() > 1) { \
		pr_err("dm-zoned(%s): " fmt "\n", _zdisk(znd), ## arg); \
	} } while (0)

#define Z_DBG(znd, fmt, arg...) \
	do { if (_debug() > 2) { \
		fprintf(stdout, "dm-zoned(%s): " fmt "\n", _zdisk(znd), ## arg); \
	} } while (0)


#define GFP_KERNEL 0
#define jiffies              ((u64)clock())
#define jiffies_64           ((u64)clock())
#define msecs_to_jiffies(v)  ( (v) * 1000)
#define time_before64(a, b)  ( (a) < (b) ? 1 : 0 )


#define Dspin_lock( p )
#define Dspin_unlock( p )
#define spin_lock(p)                 (void)p
#define spin_unlock(p)               (void)p
#define spin_lock_irqsave(p, f)      (void)p, (void)f
#define	spin_unlock_irqrestore(p, f) (void)p, (void)f

#define mzio_lock( p )   (void)p
#define mzio_unlock( p ) (void)p


static inline void * vzalloc(size_t sz) { return calloc(sz, 1); }
static inline void * kzalloc(size_t sz, int f) {
	(void)f;
	return vzalloc(sz);
}
static inline void * kcalloc(size_t sz, size_t ct, int f)
{
        (void)f;
	return calloc(sz, ct);
}
static inline void * kmalloc(size_t sz, int f)
{
	return kzalloc(sz, f);
}

static inline void * vmalloc(size_t sz) { return calloc(sz, 1); }


static inline void vfree(void *p) { free(p); }
static inline void kfree(void *p) { free(p); }

static inline void free_pages(unsigned long p, int order)
{
	free( (void *)p );
	(void) order;
}

static inline void free_page(unsigned long p)
{
	free_pages(p, 0);
}

static inline void * __get_free_pages(int kind, int order)
{
	int count = 1 << order;
        void * pmem = calloc(Z_C4K, count);
        (void) kind;

        return pmem;
}

static inline void * get_zeroed_page(int kind)
{
	return __get_free_pages(kind, 0);
}


static inline le16 cpu_to_le16(u16 val) { return htole16(val); }
static inline u16 le16_to_cpu(le16 val) { return le16toh(val); }

static inline le32 cpu_to_le32(u32 val) { return htole32(val); }
static inline u32 le32_to_cpu(le32 val) { return le32toh(val); }

static inline le64 cpu_to_le64(u64 val) { return htole64(val); }
static inline u64 le64_to_cpu(le64 val) { return le64toh(val); }


#define pr_err(fmt, ...)    fprintf(stdout, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)  fprintf(stdout, fmt, ##__VA_ARGS__)
#define DMERR(fmt, ...)     fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define DMINFO(fmt, ...)    fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define DMWARN(fmt, ...)    fprintf(stdout, fmt "\n", ##__VA_ARGS__)

#define IS_ERR( v )         ((v) != 0 )
#define PTR_ERR( v )         ((v) != 0 )

#define BUG_ON( x )         do { if ( (x) ) { fprintf(stderr, "FAIL: %" PRIx64 " at %s.%d\n", (u64)(x), __FILE__, __LINE__ ); } } while (0)

#define CONFIG_BLK_ZONED 1
#define SINGLE_DEPTH_NESTING 1


static inline void dm_io_client_destroy(void * p) { (void)p; }
static inline void dm_kcopyd_client_destroy(void * p) { (void)p; }
static inline void destroy_workqueue(void * p) { (void)p; }
static inline void dm_put_device(void * p, void * d) { (void)p; (void) d; }
static inline u64 i_size_read(void * p) { (void)p;  return 0; }


#define dm_div_up(n, sz) (((n) + (sz) - 1) / (sz))

static inline void spin_lock_init(spinlock_t * plck)  { *plck = 0; }

static inline void mutex_init(struct mutex * plck)  { plck->inuse = 0; }
static inline void mutex_lock(struct mutex * plck)    { plck->inuse++; }
static inline void mutex_lock_nested(struct mutex * plck, int class_id)
{
	(void) class_id;
	mutex_lock(plck);
}

static inline void mutex_unlock(struct mutex * plck)  { plck->inuse--; }

static inline void atomic_inc(atomic_t * value) { value->counter++; }
static inline void atomic_dec(atomic_t * value) { value->counter--; }


#define INIT_WORK(work, pfn_task)  (void)work, (void) pfn_task

static inline void * dm_io_client_create(void) { return calloc(1, 1); }
static inline void * dm_kcopyd_client_create(struct dm_kcopyd_throttle * throttle)
{
	return calloc(1, sizeof(struct dm_kcopyd_client));
}

static inline struct workqueue_struct * create_singlethread_workqueue(const char * name )
{
	struct workqueue_struct * wq = calloc(1, sizeof(*wq));
	wq->q_id++;
	wq->q_name = (char *)name;
	return wq;
};

static inline void generate_random_uuid(uuid_t out)
{
	uuid_generate(out);
}

static inline void set_bit(int bit_no, unsigned long * bits)
{
	*bits |= (1 << bit_no);
}

static inline void clear_bit(int bit_no, unsigned long * bits)
{
	*bits &= ~(1 << bit_no);
}

static inline int test_bit(int bit_no, unsigned long * bits)
{
	return (*bits & (1 << bit_no) ) ? -1 : 0;
}

static inline int test_and_set_bit(int bit_no, unsigned long * bits)
{
	int value = test_bit(bit_no, bits);
	set_bit(bit_no, bits);
	return value;
}

static inline int test_and_clear_bit(int bit_no, unsigned long * bits)
{
	int value = test_bit(bit_no, bits);
	clear_bit(bit_no, bits);
	return value;
}

static inline void queue_work(struct workqueue_struct * wq, struct work_struct * work)
{
	printf("do something: %d\n", __LINE__);
}


static inline void flush_workqueue(struct workqueue_struct * wq)
{
	printf("do nothing: %d\n", __LINE__);
}

static inline int work_pending(struct work_struct * work)
{
	return 0;
}


static inline void ssleep(int s)
{
	sleep(s);
}

static inline void msleep(int ms)

{
	usleep(1000 * ms);
}

u64 zdm_mcache_find_gen(struct megazone *mz, u64 base, int opt, u64 * out);
u64 zdm_mcache_greatest_gen(struct megazone * mz, int at, u64 *_a, u64 *_b);
int zdm_reset_wp(struct megazone * megaz, u64 z_id);
int zdm_close(struct megazone * megaz, u64 z_id);
int zdm_open(struct megazone * megaz, u64 z_id);
int zdm_zoned_inq(struct zoned *znd);
int zdm_zone_command(int fd, int command, uint64_t lba, int do_ata);

struct zoned * zdm_acquire(int fd, char * name);
struct zoned * zoned_alloc(int fd, char * name);

void zdm_release(struct zoned *znd);
int zdm_read(struct zoned *znd, void * data, u64 lba, int count);
int zdm_write(struct zoned *znd, void * data, u64 lba, int count);
int zdm_superblock(struct zoned * znd);
int zdm_superblock_check(struct zdm_superblock * sblock);
int zdm_meta_test(struct zoned * znd);
int zdm_do_something(struct zoned * znd);
int zdm_sb_test_flag(struct zdm_superblock * sb, int bit_no);
void zdm_sb_set_flag(struct zdm_superblock * sb, int bit_no);

int zdm_map_onto_zdm(struct zoned *znd, u64 sector_nr, struct map_addr * out);
int zdm_map_addr(u64 dm_s, struct map_addr * out);
int zdm_sync_tables(struct megazone * megaz, int need_table_push);
int zdm_sync_crc_pages(struct megazone * megaz);
int zdm_unused_phy(struct megazone * megaz, u64 block_nr, u64 orig);
int zdm_unused_addr(struct megazone * megaz, u64 dm_s);
u64 zdm_lookup(struct megazone * megaz, struct map_addr * maddr);
int zdm_mapped_addmany(struct megazone * megaz, u64 dm_s, u64 lba, u64 count);
int zdm_mapped_discard(struct megazone * megaz, u64 dm_s, u64 lba);
int zdm_mapped_to_list(struct megazone * megaz, u64 dm_s, u64 lba, int purge);
int zdm_mapped_sync(struct megazone * megaz);
int zdm_mapped_init(struct megazone * megaz);
int zdm_write_if_dirty(struct megazone * megaz, struct map_pg * oldest, int use_wq);
int zdm_release_table_pages(struct megazone * megaz);
int zdm_sync(struct megazone * megaz, int do_tables);
u32 zdm_sb_crc32(struct zdm_superblock *sblock);
u64 zdm_reserve_blocks(struct megazone * megaz, u32 flags, u32 count, u32 *avail);
int zdm_move_to_map_tables(struct megazone * megaz, struct map_cache * jrnl);
struct map_pg *zdm_get_map_entry(struct megazone * megaz, struct map_addr * maddr, int dir);
struct map_pg *zdm_smap_entry(struct megazone * megaz, struct map_addr * maddr);
struct map_pg *zdm_rmap_entry(struct megazone * megaz, struct map_addr * maddr);
struct map_pg *zdm_map_table_entry(struct megazone * megaz, u64 lba, int is_map_to);
int zdm_update_map_entry(struct megazone * megaz, struct map_pg * map, struct map_addr *maddr, u64 lba, int is_fwd);
struct crc_pg *zdm_get_meta_pg_crc(struct megazone * megaz, struct map_addr * maddr, int is_map_to);
int zdm_free_unused(struct megazone * megaz, int allowed_pages);
int zdm_mz_integrity_check(struct megazone * megaz);
u16 zdm_crc16_le16(void const *data, size_t len);
u64 zdm_map_value(struct megazone * megaz, u32 delta);
u64 zdm_map_encode(struct megazone * megaz, u64 to_addr, u32 * value);
int zdm_is_reverse_table_zone(struct megazone * megaz, struct map_addr * maddr);
u64 zdm_lookup_cache(struct megazone * megaz, struct map_addr * maddr);
u64 zdm_locate_sector(struct megazone * megaz, struct map_addr * maddr);
int zdm_load_page(struct megazone * megaz, struct map_pg * mapped, u64 lba, int is_to);

#endif // _ZONED_H_

