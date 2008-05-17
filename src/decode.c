/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <stdio.h>

#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>

static LIST_HEAD(linktypes);

linktype_t linktype_by_id(unsigned int id)
{
	struct _linktype *l;

	list_for_each_entry(l, &linktypes, lt_list)
		if ( l->lt_id == id )
			return l;

	return NULL;
}

const char *linktype_label(linktype_t l)
{
	assert(l->lt_label != NULL);
	return l->lt_label;
}

void linktype_register(struct _linktype *l)
{
	assert(l != NULL && l->lt_label != NULL);
	mesg(M_INFO, "linktype: registered: %s (id 0x%x)",
		l->lt_label, l->lt_id);
	list_add_tail(&l->lt_list, &linktypes);
}

void decode(struct _source *s, struct _pkt *p)
{
	p->pkt_nxthdr = p->pkt_base;
	s->s_linktype->lt_decode(p);
}
