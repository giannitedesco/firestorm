/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
 *
 * Efficient memory allocator for flow tracking. All object types are allocated
 * from a pre-allocated block of memory of a fixed size. Expected uses are:
 *  - flowstates (eg: top level hash tables)
 *  - flows (eg: ipq / tcp_session)
 *  - buffer headers (eg: ip_fragment / tcp_rbuf)
 *  - buffer data: blocks of raw data, some fixed power of 2 size
 *
 * TODO:
 *  o objcache_fini() is unimplemented
 *  o Analysis printout with fragmentation stats
 *  o May need a obj->oom() callback to free-up timed out objects!
*/

#include <firestorm.h>
#include <memchunk.h>

#define USE_MMAP 1

#if USE_MMAP
#include <sys/mman.h>
#endif

#if OBJCACHE_POISON
#define O_POISON(ptr, len) memset(ptr, OBJCACHE_POISON_PATTERN, len)
#else
#define O_POISON(ptr, len) do { } while(0);
#endif

#if MEMCHUNK_POISON
#define M_POISON(ptr, len) memset(ptr, MEMCHUNK_POISON_PATTERN, len)
#else
#define M_POISON(ptr, len) do { } while(0);
#endif

struct _obj_cache {
	/** Size of objects to allocate */
	size_t o_sz;
	/** Number of objects which can be packed in to one chunk */
	unsigned int o_num;
	/** Pointer to next object to allocate */
	uint8_t *o_ptr;
	/** Pointer to byte after last object in current chunk */
	uint8_t *o_ptr_end;
	/** Freshest chunk (we never allocated to o_ptr_end yet) */
	struct chunk_hdr *o_cur;
	/** List of chunks which have a free list */
	struct list_head o_partials;
	/** Every objcache is in the main memchunk list */
	struct list_head o_list;
	/** Text label for this objcache */
	const char *o_label;
};

/* Full chunks: nowhere, c_next = NULL */
/* Partial chunks: c_next is non-NULL and c_free_list is the free obj list */
/* Free chunks: in m_free list, c_free_list is chunk pointer, c_next is valid */
struct chunk_hdr {
	union {
		struct {
			struct chunk_hdr *next;
			uint8_t *ptr;
		}c_m;
		struct {
			struct _obj_cache *cache;
			uint8_t *free_list;
			unsigned int inuse;
			struct list_head list;
		}c_o;
	};
};

struct _memchunk {
	struct chunk_hdr *m_hdr;
	struct chunk_hdr *m_free;
	size_t m_inuse;
	size_t m_size;
	uint8_t *m_chunks;
	struct list_head m_caches;
	struct _obj_cache m_self_cache;
};

static struct _memchunk mc;

#if USE_MMAP
static void *chunk_alloc(size_t sz)
{
	void *ret;

	ret = mmap(NULL, sz, PROT_READ|PROT_WRITE,
				MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if ( ret == MAP_FAILED )
		return NULL;

	return ret;
}
static void chunk_free(void *ptr, size_t sz)
{
	munmap(ptr, sz);
}
#else
static void *chunk_alloc(size_t sz)
{
	return malloc(sz);
}
static void chunk_free(void *ptr, size_t sz)
{
	free(ptr);
}
#endif

static size_t round_up(size_t sz)
{
	return (sz + MEMCHUNK_MASK) & ~MEMCHUNK_MASK;
}

static void *idx2ptr(struct _memchunk *m, unsigned int i)
{
	return m->m_chunks + (i << MEMCHUNK_SHIFT);
}

static unsigned int ptr2idx(struct _memchunk *m, void *ptr)
{
	unsigned long idx;

	assert((uint8_t *)ptr >= m->m_chunks);
	assert((uint8_t *)ptr < (uint8_t *)m->m_hdr + m->m_size);

	idx = (unsigned long)ptr;
	idx -= (unsigned long)m->m_chunks;
	idx >>= MEMCHUNK_SHIFT;

	return idx;
}

static void *hdr2ptr(struct _memchunk *m, struct chunk_hdr *hdr)
{
	assert(hdr >= m->m_hdr);
	assert((uint8_t *)hdr < m->m_chunks);
	return idx2ptr(m, hdr - m->m_hdr);
}

static struct chunk_hdr *ptr2hdr(struct _memchunk *m, void *ptr)
{
	return &m->m_hdr[ptr2idx(m, ptr)];
}

static void do_cache_init(struct _memchunk *m, struct _obj_cache *o,
				const char *label, size_t obj_sz)
{
	o->o_sz = obj_sz;
	o->o_num = MEMCHUNK_SIZE / obj_sz;
	o->o_ptr = o->o_ptr_end = NULL;
	o->o_cur = NULL;
	INIT_LIST_HEAD(&o->o_partials);
	list_add_tail(&o->o_list, &m->m_caches);
	o->o_label = label;

	mesg(M_INFO, "objcache: new: %s (%u byte)", o->o_label, o->o_sz);
}

int memchunk_init(size_t numchunks)
{
	struct _memchunk *m;
	unsigned int i;
	size_t msz;

	if ( numchunks == 0 )
		goto out_err;

	m = &mc;

	/* Calculate metadata and total size */
	msz = round_up(sizeof(*m->m_hdr) * numchunks);
	m->m_size = msz + numchunks * MEMCHUNK_SIZE;

	mesg(M_INFO, "memchunk: %uK requested (%u chunks), %uK total",
		(numchunks * MEMCHUNK_SIZE) >> 10,
		numchunks, m->m_size >> 10);
	mesg(M_INFO, "memchunk: %uK metadata %u chunks: %u.%.2u%% of total",
		msz >> 10, msz >> MEMCHUNK_SHIFT,
		((msz >> 10) * 100) / (m->m_size >> 10),
		(((msz >> 10) * 10000) / (m->m_size >> 10)) % 100);
	
	m->m_chunks = chunk_alloc(m->m_size);
	if ( m->m_chunks == NULL )
		goto out_free;

	/* Metadata first, chunks later */
	m->m_hdr = (void *)m->m_chunks;
	M_POISON(m->m_hdr, msz);
	m->m_chunks += msz;

	INIT_LIST_HEAD(&m->m_caches);

	/* Put all chunks in the free list, lowest address first */
	for(i = 0; i < numchunks; i++) {
		m->m_hdr[i].c_m.ptr = idx2ptr(m, i);
		if ( i + 1 == numchunks )
			m->m_hdr[i].c_m.next = NULL;
		else
			m->m_hdr[i].c_m.next = &m->m_hdr[i + 1];
	}
	m->m_free = m->m_hdr;

	do_cache_init(m, &m->m_self_cache, "_objcache",
			sizeof(struct _obj_cache));
	return 1;

out_free:
	chunk_free(m->m_chunks, m->m_size);
out_err:
	return 0;
}

void memchunk_fini(void)
{
	struct _memchunk *m = &mc;
	chunk_free(m->m_hdr, m->m_size);
	mesg(M_INFO, "memchunk: %uK released: "
		"%u.%.2u%% was still in use in %u chunks",
		m->m_size >> 10,
		(m->m_inuse * 100) / (m->m_size >> MEMCHUNK_SHIFT),
		((m->m_inuse * 10000) / (m->m_size >> MEMCHUNK_SHIFT)) % 100,
		m->m_inuse);
}

void *memchunk_alloc(memchunk_t m)
{
	struct chunk_hdr *hdr;

	if ( m->m_free == NULL )
		return NULL;

	hdr = m->m_free;
	m->m_free = hdr->c_m.next;
	m->m_inuse++;

	M_POISON(hdr->c_m.ptr, MEMCHUNK_SIZE);
	return hdr->c_m.ptr;
}

void memchunk_free(memchunk_t m, void *chunk)
{
	struct chunk_hdr *hdr;

	if ( chunk == NULL )
		return;

	hdr = ptr2hdr(m, chunk);
	assert(chunk == hdr->c_m.ptr);
	M_POISON(hdr, sizeof(*hdr));
	hdr->c_m.ptr = chunk;
	hdr->c_m.next = m->m_free;
	m->m_free = hdr;
	m->m_inuse--;
}

static struct chunk_hdr *memchunk_get(memchunk_t m)
{
	struct chunk_hdr *hdr;

	if ( m->m_free == NULL )
		return NULL;

	hdr = m->m_free;
	m->m_free = hdr->c_m.next;
	m->m_inuse++;

	return hdr;
}

static void memchunk_put(memchunk_t m, struct chunk_hdr *hdr)
{
#if MEMCHUNK_DEBUG_FREE
	struct chunk_hdr *tmp;

	for(tmp = m->m_free; tmp; tmp = tmp->c_m.next)
		assert(tmp != hdr);
#endif
	M_POISON(hdr, sizeof(*hdr));
	hdr->c_m.ptr = hdr2ptr(m, hdr);
	hdr->c_m.next = m->m_free;
	m->m_free = hdr;
	m->m_inuse--;
}

obj_cache_t objcache_init(const char *label, size_t obj_sz)
{
	struct _obj_cache *o;

	assert(obj_sz < MEMCHUNK_SIZE);

	if ( obj_sz < sizeof(void *) )
		obj_sz = sizeof(void *);

	o = objcache_alloc(&mc.m_self_cache);
	if ( o == NULL )
		return NULL;

	do_cache_init(&mc, o, label, obj_sz);
	return o;
}

void objcache_fini(obj_cache_t o)
{
	assert(o == NULL);
}

static void *alloc_from_partial(struct _obj_cache *o, struct chunk_hdr *c)
{
	void *ret;
	ret = c->c_o.free_list;
	c->c_o.free_list = *(uint8_t **)ret;
	if ( NULL == c->c_o.free_list )
		list_del(&c->c_o.list);
	c->c_o.inuse++;
	O_POISON(ret, o->o_sz);
	return ret;
}

static void *alloc_fast(struct _obj_cache *o)
{
	void *ret;
	ret = o->o_ptr;
	o->o_ptr += o->o_sz;
	o->o_cur->c_o.inuse++;
	O_POISON(ret, o->o_sz);
	return ret;
}

static void *alloc_slow(struct _obj_cache *o)
{
	struct chunk_hdr *c;

	c = memchunk_get(&mc);
	if ( NULL == c )
		return NULL;

	o->o_cur = c;
	o->o_ptr = c->c_m.ptr;
	o->o_ptr_end = o->o_ptr + o->o_sz * o->o_num;

	c->c_o.cache = o;
	c->c_o.inuse = 0;
	c->c_o.free_list = NULL;
	INIT_LIST_HEAD(&c->c_o.list);

	return alloc_fast(o);
}

static struct chunk_hdr *first_partial(struct _obj_cache *o)
{
	if ( list_empty(&o->o_partials) )
		return NULL;
	return list_entry(o->o_partials.next, struct chunk_hdr, c_o.list);
}

static void *do_alloc(struct _obj_cache *o)
{
	struct chunk_hdr *c;

	/* First check free list */
	if ( (c = first_partial(o)) && c->c_o.free_list )
		return alloc_from_partial(o, c);

	/* Then check ptr/ptr_end */
	if ( likely(o->o_ptr + o->o_sz <= o->o_ptr_end) )
		return alloc_fast(o);

	/* Finall resort to slow path */
	return alloc_slow(o);
}

void *objcache_alloc(obj_cache_t o)
{
	return do_alloc(o);
}

void *objcache_alloc0(obj_cache_t o)
{
	void *ret;
	
	ret = do_alloc(o);
	if ( likely(ret != NULL) )
		memset(ret, 0, o->o_sz);

	return ret;
}

static void do_cache_free(struct _obj_cache *o, struct chunk_hdr *c, void *obj)
{
#if OBJCACHE_DEBUG_FREE
	uint8_t **tmp;
	assert((uint8_t *)obj < o->o_ptr || (uint8_t *)obj > o->o_ptr_end);
	for(tmp = (uint8_t **)c->c_o.free_list; tmp; tmp = (uint8_t **)*tmp)
		assert(tmp != obj);
#endif

	assert(c->c_o.inuse);
	assert(c->c_o.inuse <= o->o_num);

	/* First add to partials if this is first free from chunk */
	if ( NULL == c->c_o.free_list ) {
		assert(list_empty(&c->c_o.list));
		assert(c == o->o_cur || c->c_o.inuse == o->o_num);
		list_add(&c->c_o.list, &o->o_partials);
	}

	O_POISON(obj, o->o_sz);

	/* add object to free list */
	*(uint8_t **)obj = c->c_o.free_list;
	c->c_o.free_list = obj;

	/* decrement inuse and free the chunk if it's the last object */
	if ( 0 == --c->c_o.inuse ) {
		list_del(&c->c_o.list);
		if ( o->o_cur == c ) {
			o->o_ptr = o->o_ptr_end = NULL;
			o->o_cur = NULL;
		}
		memchunk_put(&mc, c);
	}
}

void objcache_free(void *obj)
{
	struct chunk_hdr *c;
	c = ptr2hdr(&mc, obj);
	do_cache_free(c->c_o.cache, c, obj);
}

void objcache_free2(obj_cache_t o, void *obj)
{
	struct chunk_hdr *c;
	c = ptr2hdr(&mc, obj);
	assert(c->c_o.cache == o);
	do_cache_free(c->c_o.cache, c, obj);
}
