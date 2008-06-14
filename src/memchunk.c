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

/* Full chunks: nowhere */
/* Partial chunks: in o_partials list, next_obj/use/u.list are valid */
/* Free chunks: in m_free list, next_obj is chunk pointer, next is valid */
struct chunk_hdr {
	uint8_t *next_obj;
	unsigned int use;
	union {
		struct list_head list;
		struct chunk_hdr *next;
	}u;
};

struct _obj_cache {
	size_t o_sz;
	unsigned int o_obj_per_chunk;
	struct _memchunk *o_chunk;
	struct list_head o_partials;
	struct list_head o_list;
	const char *o_label;
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

static void *hdr2ptr(struct _memchunk *m, struct chunk_hdr *hdr)
{
	return idx2ptr(m, hdr - m->m_hdr);
}

static struct chunk_hdr *ptr2hdr(struct _memchunk *m, void *ptr)
{
	unsigned long pint;

	assert((uint8_t *)ptr >= m->m_chunks);
	assert((uint8_t *)ptr < (uint8_t *)m->m_hdr + m->m_size);

	pint = (unsigned long)ptr;
	pint -= (unsigned long)m->m_chunks;
	pint >>= MEMCHUNK_SHIFT;

	return &m->m_hdr[pint];
}

static void do_cache_init(struct _memchunk *m, struct _obj_cache *o,
				const char *label, size_t obj_sz)
{
	o->o_sz = obj_sz;
	o->o_obj_per_chunk = MEMCHUNK_SIZE / obj_sz;
	o->o_chunk = m;
	INIT_LIST_HEAD(&o->o_partials);
	list_add_tail(&o->o_list, &m->m_caches);
	o->o_label = label;

	mesg(M_INFO, "objcache: new: %s (%u byte)", o->o_label, o->o_sz);
}

memchunk_t memchunk_init(size_t numchunks)
{
	struct _memchunk *m;
	unsigned int i;
	size_t msz;

	if ( numchunks == 0 )
		goto out_err;

	/* The memchunk itself comes from the system heap, this helps our
	 * chunks align better (gah, the age old problems) :S
	*/
	m = calloc(1, sizeof(*m));
	if ( m == NULL )
		goto out_err;

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
	m->m_chunks += msz;

	INIT_LIST_HEAD(&m->m_caches);

	/* Put all chunks in the free list, lowest address first */
	for(i = 0; i < numchunks; i++) {
		m->m_hdr[i].next_obj = idx2ptr(m, i);
		m->m_hdr[i].use = 0;
		if ( i + 1 == numchunks )
			m->m_hdr[i].u.next = NULL;
		else
			m->m_hdr[i].u.next = &m->m_hdr[i + 1];
	}
	m->m_free = m->m_hdr;

	do_cache_init(m, &m->m_self_cache, "_objcache",
			sizeof(struct _obj_cache));
	goto out;

out_free:
	free(m);
out_err:
	m = NULL;
out:
	return m;
}

void memchunk_fini(memchunk_t m)
{
	if ( m != NULL )
		chunk_free(m->m_hdr, m->m_size);
	mesg(M_INFO, "memchunk: %uK released: "
		"%u.%.2u%% was still in use in %u chunks",
		m->m_size >> 10,
		(m->m_inuse * 100) / (m->m_size >> MEMCHUNK_SHIFT),
		((m->m_inuse * 10000) / (m->m_size >> MEMCHUNK_SHIFT)) % 100,
		m->m_inuse);
	free(m);
}

void *memchunk_alloc(memchunk_t m)
{
	struct chunk_hdr *hdr;

	if ( m->m_free == NULL )
		return NULL;

	hdr = m->m_free;
	m->m_free = hdr->u.next;
	m->m_inuse++;

	return hdr->next_obj;
}

void memchunk_free(memchunk_t m, void *chunk)
{
	struct chunk_hdr *hdr;

	if ( chunk == NULL )
		return;

	hdr = ptr2hdr(m, chunk);
	hdr->next_obj = chunk;
	hdr->u.next = m->m_free;
	m->m_free = hdr;
	m->m_inuse--;
}

static struct chunk_hdr *memchunk_get(memchunk_t m)
{
	struct chunk_hdr *hdr;

	if ( m->m_free == NULL )
		return NULL;

	hdr = m->m_free;
	m->m_free = hdr->u.next;
	m->m_inuse++;

	return hdr;
}

static void memchunk_put(memchunk_t m, struct chunk_hdr *hdr)
{
	hdr->next_obj = hdr2ptr(m, hdr);
	hdr->u.next = m->m_free;
	m->m_free = hdr;
	m->m_inuse--;
}

static struct _obj_cache *cache_find(struct _memchunk *m, const char *l)
{
	struct _obj_cache *o;

	list_for_each_entry(o, &m->m_caches, o_list) {
		if ( !strcmp(o->o_label, l) )
			return o;
	}

	return NULL;
}

obj_cache_t objcache_init(memchunk_t m, const char *label, size_t obj_sz)
{
	struct _obj_cache *o;

	assert(obj_sz < MEMCHUNK_SIZE);

	if ( obj_sz < sizeof(void *) )
		obj_sz = sizeof(void *);

	o = cache_find(m, label);
	if ( o ) {
		size_t max;

		max = (obj_sz > o->o_sz) ? obj_sz : o->o_sz;
		mesg(M_INFO, "objcache: %s: %u bytes -> %u bytes",
			o->o_label, o->o_sz, max);
		o->o_sz = max;
		o->o_obj_per_chunk = MEMCHUNK_SIZE / max;
		return o;
	}

	o = objcache_alloc(&m->m_self_cache);
	if ( o == NULL )
		return NULL;

	do_cache_init(m, o, label, obj_sz);
	return o;
}

void objcache_fini(obj_cache_t o)
{
	assert(o == NULL);
}

static void *cache_alloc_slow(struct _obj_cache *o)
{
	struct chunk_hdr *hdr;
	uint8_t *ret, *ptr, *end;

	hdr = memchunk_get(o->o_chunk);
	if ( hdr == NULL )
		return NULL;

	ret = hdr->next_obj;
	hdr->next_obj += o->o_sz;
	hdr->use = 1;
	list_add(&hdr->u.list, &o->o_partials);

	for(ptr = ret, end = ret + o->o_sz * (o->o_obj_per_chunk - 1);
		ptr < end; ptr += o->o_sz) {
		*(uint8_t **)ptr = ptr + o->o_sz;
	}
	*(uint8_t **)ptr = NULL;

	return ret;
}

void *objcache_alloc(obj_cache_t o)
{
	struct chunk_hdr *hdr;
	void *ret;

	if ( unlikely(list_empty(&o->o_partials)) )
		return cache_alloc_slow(o);

	hdr = list_entry(o->o_partials.next, struct chunk_hdr, u.list);
	ret = hdr->next_obj;
	hdr->next_obj = *(uint8_t **)ret;
	if ( unlikely(hdr->next_obj == NULL) )
		list_del(&hdr->u.list);
	assert(hdr->use < o->o_obj_per_chunk);
	hdr->use++;

	return ret;
}

static void move_to_partials(struct _obj_cache *o, struct chunk_hdr *hdr)
{
	list_add(&hdr->u.list, &o->o_partials);
}

static void cache_free_slow(struct _memchunk *m, struct chunk_hdr *hdr)
{
	list_del(&hdr->u.list);
	memchunk_put(m, hdr);
}

void objcache_free(obj_cache_t o, void *obj)
{
	struct chunk_hdr *hdr;

	/* 1. Add object back on to the free list */
	hdr = ptr2hdr(o->o_chunk, obj);
	assert(hdr->use >= 1);
	*(uint8_t **)obj = hdr->next_obj;

	/* 2. If chunk was full, move to partials */
	if ( unlikely(hdr->next_obj == NULL) )
		move_to_partials(o, hdr);

	/* 3. Free it */
	hdr->next_obj = obj;
	hdr->use--;

	/* 4. If chunk becomes empty return with memchunk_put */
	if ( unlikely(hdr->use == 0) )
		cache_free_slow(o->o_chunk, hdr);
}

void *objcache_alloc0(obj_cache_t o)
{
	void *ret;
	
	ret = objcache_alloc(o);
	if ( likely(ret != NULL) )
		memset(ret, 0, o->o_sz);

	return ret;
}
