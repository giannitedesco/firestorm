/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_EVENT_HEADER_INCLUDED_
#define _FIRESTORM_EVENT_HEADER_INCLUDED_

#include <stdarg.h>

typedef void (*event_cbfn_t)(struct _event *e, va_list args);

struct _event {
	struct list_head e_list;
	const char *e_label;
	event_cbfn_t e_cbfn;
};

void _event_register(event_t ev, const char *label, event_cbfn_t cbfn);

extern struct _event ev_pkt_new;

#endif /* _FIRESTORM_EVENT_HEADER_INCLUDED_ */
