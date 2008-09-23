/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_event.h>

static LIST_HEAD(events);

struct cbfn {
	event_cbfn_t cbfn;
	struct list_head list;
};

event_t event_by_name(const char *name)
{
	struct _event *ret;

	list_for_each_entry(ret, &events, e_list)
		if ( !strcmp(ret->e_label, name) )
			return ret;

	return NULL;
}

void event_fire(event_t ev, ...)
{
	va_list va;

	va_start(va, ev);
	ev->e_cbfn(ev, va);
	va_end(va);
}

void _event_register(event_t ev, const char *label, event_cbfn_t cbfn)
{
	ev->e_label = label;
	ev->e_cbfn = cbfn;
	list_add_tail(&ev->e_list, &events);
	mesg(M_DEBUG, "event: %s registered", label);
}
