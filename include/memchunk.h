/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_MEMCHUNK_HEADER_INCLUDED_
#define _FIRESTORM_MEMCHUNK_HEADER_INCLUDED_

#define MEMCHUNK_SHIFT	12
#define MEMCHUNK_SIZE	(1 << MEMCHUNK_SHIFT)
#define MEMCHUNK_MASK	(MEMCHUNK_SIZE - 1)

#define MEMCHUNK_DEBUG_FREE 0
#define MEMCHUNK_POISON 1
#define MEMCHUNK_POISON_PATTERN 0x5a
#define OBJCACHE_DEBUG_FREE 0
#define OBJCACHE_POISON 1
#define OBJCACHE_POISON_PATTERN 0xa5

struct _objcache {
	/** Pointer to next object to allocate */
	uint8_t *o_ptr;
	/** Pointer to byte after last object in current chunk */
	uint8_t *o_ptr_end;
	/** Freshest chunk (we never allocated to o_ptr_end yet) */
	struct chunk_hdr *o_cur;
	/** List of chunks which have a free list */
	struct list_head o_partials;
	/** List of full chunks */
	struct list_head o_full;
	/** Mempool to allocate from */
	struct _mempool *o_pool;
	/** Every objcache is in the main memchunk list */
	struct list_head o_list;
	/** Text label for this objcache */
	const char *o_label;
	/** Number of objects which can be packed in to one chunk */
	uint16_t o_num;
	/** Size of objects to allocate */
	uint16_t o_sz;
};

/* Full chunks: nowhere, c_next = NULL */
/* Partial chunks: c_next is non-NULL and c_free_list is the free obj list */
/* Free chunks: in p_free list, c_free_list is chunk pointer, c_next is valid */
struct chunk_hdr {
	union {
		struct {
			struct chunk_hdr *next;
			uint8_t *ptr;
		}c_m;
		struct {
			struct _objcache *cache;
			uint8_t *free_list;
			struct list_head list;
			uint16_t inuse;
		}c_o;
	};
};

struct _mempool {
	struct chunk_hdr *p_free;
	struct list_head p_caches;
	struct list_head p_list;
	const char *p_label;
	unsigned int p_numfree;
	unsigned int p_reserve;
};

struct _memchunk {
	struct _mempool m_gpool;
	struct chunk_hdr *m_hdr;
	uint8_t *m_chunks;
	struct _objcache m_self_cache;
	struct _objcache m_pool_cache;
	struct list_head m_pools;
	size_t m_size;
};

#endif /* _FIRESTORM_MEMCHUNK_HEADER_INCLUDED_ */
