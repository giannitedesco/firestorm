#ifndef _INTERNAL_CAPTURE_HEADER_INCLUDED_
#define _INTERNAL_CAPTURE_HEADER_INCLUDED_

#include "packet.h"

struct _source {
	const struct _capdev *s_capdev;
	const char *s_name;
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

#endif /* _INTERNAL_CAPTURE_HEADER_INCLUDED_ */
