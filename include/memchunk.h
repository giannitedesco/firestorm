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

typedef struct _memchunk *memchunk_t;
typedef struct _obj_cache *obj_cache_t;

memchunk_t memchunk_init(size_t numchunks) _malloc;
void memchunk_fini(memchunk_t m);
void *memchunk_alloc(memchunk_t m) _malloc;
void memchunk_free(memchunk_t m, void *chunk);
void memchunk_free_obj(memchunk_t m, void *chunk);

obj_cache_t objcache_init(memchunk_t m, size_t obj_sz) _malloc;
void objcache_fini(obj_cache_t o);
void *objcache_alloc(obj_cache_t o) _malloc;
void objcache_free(obj_cache_t o, void *obj);

#endif /* _FIRESTORM_MEMCHUNK_HEADER_INCLUDED_ */
