/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _P_STREAM_HEADER_INCLUDED_
#define _P_STREAM_HEADER_INCLUDED_

struct stream_ops {
	size_t sm_state_sz;
	void (*sm_ctor)(void *priv);
	size_t (*sm_append)(void *priv, const uint8_t *buf, size_t sz);
};

#endif /* _P_STREAM_HEADER_INCLUDED_ */
