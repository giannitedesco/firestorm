/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
 *
 * Efficient memory allocator for flow tracking. All object types are allocated
 * from a pre-allocated block of memory of a fixed size.
 *
 * TODO:
 *  o Implement objcaches
 *  o Allow similar sized objects to share chunks
 *  o Debug printout with fragmentation stats
 *  o May need a obj->oom() callback to free-up timed out objects!
 *  o Objects to be placed under management:
 *     - flowstates (eg: top level hash tables)
 *     - flows (eg: ipq / tcp_session)
 *     - buffer headers (eg: ip_fragment / tcp_rbuf)
 *     - buffer data: blocks of raw data, some fixed power of 2 size
*/

#include <firestorm.h>
#include <memchunk.h>

#define USE_MMAP 1

#if USE_MMAP
#include <sys/mman.h>
#endif

struct chunk_hdr {
	struct _obj_cache *cache;
	void *next_obj;
	union {
		struct list_head list;
		struct chunk_hdr *next;
	}u;
};

struct _obj_cache {
	size_t o_sz;
	struct _memchunk *o_chunk;
	struct list_head o_partials;
	unsigned int o_num_partials;
	struct list_head o_list;
	const char * const o_label;
};

struct _memchunk {
	struct chunk_hdr *m_hdr;
	struct chunk_hdr *m_free;
	size_t m_inuse;
	size_t m_size;
	uint8_t *m_chunks;
	struct list_head m_caches;
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
	return ((sz + MEMCHUNK_MASK) >> MEMCHUNK_SHIFT) << MEMCHUNK_SHIFT;
}

static void *idx2ptr(struct _memchunk *m, unsigned int i)
{
	return m->m_chunks + (i << MEMCHUNK_SHIFT);
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

	/* Put all chunks in the free list */
	for(i = 0; i < numchunks; i++) {
		m->m_hdr[i].cache = NULL;
		m->m_hdr[i].next_obj = idx2ptr(m, i);
		if ( i + 1 == numchunks )
			m->m_hdr[i].u.next = NULL;
		else
			m->m_hdr[i].u.next = &m->m_hdr[i + 1];
	}

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
	mesg(M_INFO, "memchunk: %uK released: %u.%.2u%% was still inuse",
		m->m_size >> 10,
		((m->m_inuse >> 10) * 100) / (m->m_size >> 10),
		(((m->m_inuse  >> 10) * 10000) / (m->m_size >> 10)) % 100);
	free(m);
}

void *memchunk_alloc(memchunk_t m)
{
	struct chunk_hdr *hdr;

	if ( m->m_free == NULL )
		return NULL;

	hdr = m->m_free;
	m->m_free = hdr->u.next;
	m->m_inuse += MEMCHUNK_SIZE + sizeof(*hdr);

	return hdr->next_obj;
}

void memchunk_free(memchunk_t m, void *chunk)
{
	struct chunk_hdr *hdr;

	if ( chunk == NULL )
		return;

	hdr = ptr2hdr(m, chunk);
	hdr->u.next = m->m_free;
	m->m_free = hdr;
	m->m_inuse -= MEMCHUNK_SIZE + sizeof(*hdr);
}
