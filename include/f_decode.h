/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_DECODE_HEADER_INCLUDED_
#define _FIRESTORM_DECODE_HEADER_INCLUDED_

struct _netproto {
	unsigned int np_id;
	const char *np_label;
	void (*np_decode)(struct _pkt *p);
	struct list_head np_list;
};

void netproto_register(struct _netproto *l);
void decode(struct _source *s, struct _pkt *p);

#endif /* _FIRESTORM_DECODE_HEADER_INCLUDED_ */
