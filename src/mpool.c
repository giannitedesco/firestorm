/*
* This file is part of Firestorm NIDS
* Copyright (c) 2003 Gianni Tedesco
* Released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <mpool.h>

/** Initialise an mpool.
 * \ingroup g_mpool
 *
 * @param m an mpool structure to use
 * @param obj_size size of objects to allocate
 * @param slab_size size of slabs in number of objects (set to zero for auto)
 *
 * Creates a new empty memory pool descriptor with the passed values
 * set. The resultant mpool has no alignment requirement set.
 *
 * @return zero on error, non-zero for success
 * (may only return 0 if the obj_size is 0).
 */
int _public mpool_init(struct mpool *m, size_t obj_size, unsigned slab_size)
{
	/* quick sanity checks */
	if ( obj_size == 0 )
		return 0;

	if ( obj_size < sizeof(void *) )
		obj_size = sizeof(void *);

	m->obj_size = obj_size;

	if ( slab_size ) {
		m->slab_size = sizeof(struct mpool_hdr) + 
				(slab_size * obj_size);
	}else{
		/* XXX: totally arbitrary... */
		if ( m->obj_size < 8192 ) {
			m->slab_size = sizeof(struct mpool_hdr) +
				(8192 - (8192 % m->obj_size));
		}else{
			m->slab_size = sizeof(struct mpool_hdr) +
				(4 * m->obj_size);
		}
	}

	m->slabs = NULL;
	m->free = NULL;

	return 1;
}

/** Slow path for mpool allocations.
 * \ingroup g_mpool
 * @param m a valid mpool structure returned from mpool_init()
 *
 * Allocate a new object, returns NULL if out of memory. Note that this
 * is the slow path, the fast path for common case (no new allocation
 * needed) is handled in the inline fucntion mpool_alloc() in mpool.h.
 *
 * @return a new object
 */
static void *mpool_alloc_slow(struct mpool *m)
{
	struct mpool_hdr *h;
	void *ptr, *ret;
	
	h = ptr = malloc(m->slab_size);
	if ( h == NULL )
		return NULL;

	/* Set first object */
	ret = ptr + sizeof(*h);
	h->next_obj = ret + m->obj_size;

	/* prepend to slab list */
	h->next = m->slabs;
	m->slabs = h;

	return ret;
}

/** Allocate an object from an mpool.
 * \ingroup g_mpool
 * @param m a valid mpool structure returned from mpool_init()
 *
 * Allocate a new object, returns NULL if out of memory. This is the
 * fast path. It never calls malloc directly.
 *
 * @return a new object
 */
void *mpool_alloc(struct mpool *m)
{
	/* Try a free'd object first */
	if ( unlikely(m->free) ) {
		void *ret = m->free;
		m->free = *(void **)m->free;
		return ret;
	}

	/* If there is space in the slab, allocate */
	if ( m->slabs != NULL ) {
		void *ret = m->slabs->next_obj;
		m->slabs->next_obj += m->obj_size;

		if ( m->slabs->next_obj <= ((void *)m->slabs) + m->slab_size )
			return ret;
	}

	/* Otherwise go to slow path (calls malloc) */
	return mpool_alloc_slow(m);
}

/** Destroy an mpool object.
 * \ingroup g_mpool
 * @param m a valid mpool structure returned from mpool_init()
 *
 * Frees up all allocated memory from the #mpool and resets all members
 * to invalid values.
 */
void _public mpool_fini(struct mpool *m)
{
	struct mpool_hdr *h, *f;

	for(h=m->slabs; (f=h) ; free(f))
		h=h->next;

	memset(m, 0, sizeof(*m));
}

/** Destroy an mpool calling a destructor function for each object.
 * \ingroup g_mpool
 * @param m a valid mpool structure returned from mpool_init()
 * @param dtor A destructor function to call taking a single parameter
 *    which is a pointer to an object.
 *
 * Same as mpool_fini() but calls a destructor on every allocated object.
 */
void _public mpool_destroy(struct mpool *m, void(*dtor)(void *))
{
	struct mpool_hdr *h, *f;
	void *p;

	for(h=m->slabs; (f=h); h=h->next, free(f)) {
		for(p = f->data; p < f->next_obj; p += m->obj_size)
			(*dtor)(p);
	}

	memset(m, 0, sizeof(*m));
}
