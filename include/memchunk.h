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

void *memchunk_alloc(memchunk_t m) _malloc;
void memchunk_free(memchunk_t m, void *chunk);

#endif /* _FIRESTORM_MEMCHUNK_HEADER_INCLUDED_ */
