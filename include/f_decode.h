/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_DECODE_HEADER_INCLUDED_
#define _FIRESTORM_DECODE_HEADER_INCLUDED_

struct _linktype {
	unsigned int lt_id;
	const char *lt_label;
	void (*lt_decode)(struct _pkt *p);
	struct list_head lt_list;
};

struct _netproto {
	unsigned int np_id;
	const char *np_label;
	void (*nt_decode)(struct _pkt *p);
	struct list_head np_list;
};

void linktype_register(struct _linktype *l);
void decode(struct _source *s, struct _pkt *p);

#endif /* _FIRESTORM_DECODE_HEADER_INCLUDED_ */
