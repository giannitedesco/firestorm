/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_CAPTURE_HEADER_INCLUDED_
#define _FIRESTORM_CAPTURE_HEADER_INCLUDED_

struct _source {
	const struct _capdev *s_capdev;
	const char *s_name;
	netproto_t s_linktype;
	unsigned int s_swab;
	struct list_head s_list;
};

/** Are timestamps on packets the current system time? */
#define CAPDEV_REALTIME	(1<<0)
/** The only way a capture can be "asynchronous" is to use the nbio API. */
#define CAPDEV_ASYNC	(1<<1)

struct _capdev {
	bitmask_t c_flags;

	struct _pkt *(*c_dequeue)(struct _source *s);

	off_t (*cf_index)(struct _pkt *pkt);
	struct _pkt *(*c_query)(struct _source *s, off_t off);

	void (*c_rewind)(struct _source *s);

	void (*c_dtor)(struct _source *s);

	const char *c_name;
};

void _source_free(struct _source *s) _nonull(1);

static inline uint16_t source_swap16(struct _source *src, uint16_t i)
{
	return (src->s_swab) ? sys_bswap16(i) : i;
}
static inline uint32_t source_swap32(struct _source *src, uint32_t i)
{
	return (src->s_swab) ? sys_bswap32(i) : i;
}

#endif /* _FIRESTORM_CAPTURE_HEADER_INCLUDED_ */
