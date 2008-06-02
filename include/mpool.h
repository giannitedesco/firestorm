/*
 * This file is part of dotscara
 * Copyright (c) 2003 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2
 */
#ifndef _MPOOL_HEADER_INCLUDED_
#define _MPOOL_HEADER_INCLUDED_

/* for memset */
#include <string.h>

/** mpool descriptor.
 * \ingroup g_mpool
*/
struct mpool {
	/** Object size. */
	size_t obj_size;
	/** Size of each block including mpool_hdr overhead. */
	size_t slab_size;
	/** List of blocks. */
	struct mpool_hdr *slabs;
	/** List of free'd objects. */
	void *free;
};

/** mpool memory area descriptor.
 * \ingroup g_mpool
*/
struct mpool_hdr {
	/** Pointer to next item in the list */
	struct mpool_hdr *next;
	/** Pointer to next available object */
	void *next_obj;
	/** Data up to the slab_size */
	uint8_t data[0];
};

int _public mpool_init(struct mpool *m, size_t obj_size, unsigned slab_size)
	_nonull(1);
void _public mpool_fini(struct mpool *m) _nonull(1);
void _public mpool_destroy(struct mpool *m, void(*dtor)(void *)) _nonull(1,2);
void * _public mpool_alloc(struct mpool *m) _malloc _nonull(1);
static inline void *mpool_alloc0(struct mpool *m) _malloc _nonull(1);
static inline void mpool_free(struct mpool *m, void *obj) _nonull(1);

/** Free an individual object.
 * \ingroup g_mpool
 * @param m mpool object that obj was allocated from.
 * @param obj pointer to object to free.
 *
 * When an mpool object is free'd it's added to a linked list of
 * free objects which mpool_alloc() scans before trying to commit
 * further memory resources.
*/
static inline void mpool_free(struct mpool *m, void *obj)
{
	if ( unlikely(obj == NULL) )
		return;
	if ( unlikely(m->obj_size < sizeof(void *)) )
		return;
	*(void **)obj = m->free;
	m->free = obj;
}

/** Allocate an object initialized to zero.
 * \ingroup g_mpool
 *
 * @param m mpool object to allocate from.
 *
 * This is the same as mpool_alloc() but initializes the returned
 * memory to all zeros.
 *
 * @return pointer to new object or NULL for error
*/
static inline void *mpool_alloc0(struct mpool *m)
{
	void *ret;

	ret = mpool_alloc(m);
	if ( likely(ret) )
		memset(ret, 0, m->obj_size);

	return ret;
}

#endif /* _MPOOL_HEADER_INCLUDED_ */
